//! Limite de débit de `/api/v1` (`docs/api-console.md`) : seaux à jetons en
//! mémoire de `serve`, dans deux tables distinctes.
//!
//! - **Par appareil** authentifié : 120 appels par minute, rafale de 30.
//!   Bornée par le nombre d'appareils, jamais évincée. Appliquée après
//!   l'authentification, avant l'écriture de « vu le ».
//! - **Par IP cliente** (IPv4 entière, IPv6 sur son /64) : 10 par minute.
//!   `POST /api/v1/pair` y passe avant tout traitement ; ailleurs, seul un
//!   échec d'authentification y puise, pour changer un 401 en 429 : un seau
//!   d'IP vide ne bloque jamais une requête à jeton valide (NAT partagé avec
//!   un attaquant). Table bornée à [`MAX_IPS`] clés ; seul un seau plein,
//!   équivalent à une clé absente, est évincé. Table pleine de seaux entamés :
//!   refus (fermé).
//!
//! Le temps vient de `Clock::monotonic` : un réglage de l'heure système ne
//! remplit ni ne vide aucun seau.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use axum::http::HeaderMap;

/// Règle d'un seau : `burst` jetons au plus, `per_minute` rendus par minute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub burst: u32,
    pub per_minute: u32,
}

impl Rule {
    fn per_second(self) -> f64 {
        f64::from(self.per_minute) / 60.0
    }

    /// Secondes pour remplir un seau vide.
    fn full_after(self) -> u64 {
        (f64::from(self.burst) / self.per_second()).ceil() as u64
    }
}

/// Appareil authentifié.
pub const DEVICE_RULE: Rule = Rule {
    burst: 30,
    per_minute: 120,
};
/// IP cliente : appairages et échecs d'authentification.
pub const IP_RULE: Rule = Rule {
    burst: 10,
    per_minute: 10,
};
/// Clés au plus dans la table des IP.
pub const MAX_IPS: usize = 4096;

/// Clé de la table des IP : une IPv4, ou le /64 d'une IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpKey {
    V4(Ipv4Addr),
    /// Les 64 premiers bits de l'adresse.
    V6(u64),
    /// Adresse inconnue (routeur servi sans `ConnectInfo`, dans les tests) :
    /// toutes ces requêtes partagent un seau.
    Unknown,
}

impl IpKey {
    pub fn of(ip: Option<IpAddr>) -> Self {
        match ip.map(|ip| ip.to_canonical()) {
            Some(IpAddr::V4(ip)) => Self::V4(ip),
            Some(IpAddr::V6(ip)) => Self::V6((ip.to_bits() >> 64) as u64),
            None => Self::Unknown,
        }
    }
}

impl fmt::Display for IpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(ip) => write!(f, "{ip}"),
            Self::V6(prefix) => write!(f, "{}/64", Ipv6Addr::from_bits(u128::from(*prefix) << 64)),
            Self::Unknown => f.write_str("inconnue"),
        }
    }
}

/// IP cliente. Derrière Caddy, le pair est la boucle locale (`127.0.0.1` ou
/// `::1`) : la dernière valeur de `X-Forwarded-For` est alors celle que
/// Caddy a écrite (il remplace l'en-tête reçu, faute de `trusted_proxies`).
/// Venant d'un autre pair, l'en-tête est ignoré : il serait forgé.
pub fn client_ip(peer: Option<SocketAddr>, headers: &HeaderMap) -> Option<IpAddr> {
    let peer = peer?.ip().to_canonical();
    if !peer.is_loopback() {
        return Some(peer);
    }
    let forwarded = headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(|value| value.trim().parse::<IpAddr>().ok());
    Some(forwarded.map_or(peer, |ip| ip.to_canonical()))
}

/// Requête refusée : secondes à attendre avant qu'un jeton revienne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limited {
    pub retry_after: u64,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(rule: Rule, now: Instant) -> Self {
        Self {
            tokens: f64::from(rule.burst),
            at: now,
        }
    }

    fn refill(&mut self, rule: Rule, now: Instant) {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rule.per_second()).min(f64::from(rule.burst));
        self.at = self.at.max(now);
    }

    fn take(&mut self, rule: Rule, now: Instant) -> Result<(), Limited> {
        self.refill(rule, now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let wait = ((1.0 - self.tokens) / rule.per_second()).ceil() as u64;
            Err(Limited {
                retry_after: wait.max(1),
            })
        }
    }

    fn is_full(&self, rule: Rule, now: Instant) -> bool {
        let mut bucket = *self;
        bucket.refill(rule, now);
        bucket.tokens >= f64::from(rule.burst)
    }
}

/// Les deux tables, partagées par les requêtes de `serve`.
#[derive(Debug, Default)]
pub struct Limiter {
    devices: Mutex<HashMap<i64, Bucket>>,
    ips: Mutex<HashMap<IpKey, Bucket>>,
}

impl Limiter {
    /// Un appel de l'appareil `id`.
    pub fn device(&self, id: i64, now: Instant) -> Result<(), Limited> {
        let mut devices = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
        devices
            .entry(id)
            .or_insert_with(|| Bucket::full(DEVICE_RULE, now))
            .take(DEVICE_RULE, now)
    }

    /// Un appairage ou un échec d'authentification venu de `key`.
    pub fn ip(&self, key: IpKey, now: Instant) -> Result<(), Limited> {
        let mut ips = self.ips.lock().unwrap_or_else(PoisonError::into_inner);
        if !ips.contains_key(&key) && ips.len() >= MAX_IPS {
            ips.retain(|_, bucket| !bucket.is_full(IP_RULE, now));
            if ips.len() >= MAX_IPS {
                return Err(Limited {
                    retry_after: IP_RULE.full_after(),
                });
            }
        }
        ips.entry(key)
            .or_insert_with(|| Bucket::full(IP_RULE, now))
            .take(IP_RULE, now)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn ip(text: &str) -> IpKey {
        IpKey::of(Some(text.parse().expect("ip")))
    }

    #[test]
    fn a_device_has_a_burst_of_30_then_two_per_second() {
        let limiter = Limiter::default();
        let t0 = Instant::now();
        for _ in 0..30 {
            limiter.device(1, t0).expect("rafale");
        }
        assert_eq!(limiter.device(1, t0), Err(Limited { retry_after: 1 }));
        // Un autre appareil a son propre seau.
        limiter.device(2, t0).expect("autre appareil");
        let t1 = t0 + Duration::from_millis(500);
        limiter.device(1, t1).expect("un jeton rendu");
        assert!(limiter.device(1, t1).is_err());
    }

    #[test]
    fn an_ip_gets_ten_per_minute() {
        let limiter = Limiter::default();
        let t0 = Instant::now();
        let key = ip("192.0.2.1");
        for _ in 0..10 {
            limiter.ip(key, t0).expect("sous la limite");
        }
        assert_eq!(limiter.ip(key, t0), Err(Limited { retry_after: 6 }));
        limiter
            .ip(key, t0 + Duration::from_secs(6))
            .expect("un jeton toutes les 6 s");
    }

    #[test]
    fn ipv6_is_keyed_on_its_64_prefix() {
        assert_eq!(ip("2001:db8::1"), ip("2001:db8::ffff:2"));
        assert_ne!(ip("2001:db8::1"), ip("2001:db8:0:1::1"));
        assert_eq!(ip("::ffff:192.0.2.1"), ip("192.0.2.1"));
        assert_eq!(ip("2001:db8::1").to_string(), "2001:db8::/64");
        assert_eq!(ip("192.0.2.1").to_string(), "192.0.2.1");
    }

    #[test]
    fn a_full_table_of_started_buckets_refuses_new_keys() {
        let limiter = Limiter::default();
        let t0 = Instant::now();
        for n in 0..MAX_IPS as u32 {
            limiter
                .ip(IpKey::V4(Ipv4Addr::from_bits(n)), t0)
                .expect("place libre");
        }
        let newcomer = ip("198.51.100.7");
        assert!(limiter.ip(newcomer, t0).is_err(), "table pleine : fermé");
        // Une minute plus tard, les seaux sont pleins de nouveau : évincés.
        limiter
            .ip(newcomer, t0 + Duration::from_secs(60))
            .expect("place libérée");
    }

    #[test]
    fn forwarded_for_is_read_from_loopback_only() {
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "198.51.100.1".parse().unwrap());
        headers.append(
            "x-forwarded-for",
            "203.0.113.9, 203.0.113.5".parse().unwrap(),
        );
        let remote: SocketAddr = "192.0.2.10:443".parse().unwrap();
        assert_eq!(
            client_ip(Some(remote), &headers),
            Some("192.0.2.10".parse().unwrap())
        );
        for local in ["127.0.0.1:50000", "[::1]:50000"] {
            assert_eq!(
                client_ip(Some(local.parse().unwrap()), &headers),
                Some("203.0.113.5".parse().unwrap()),
                "{local}"
            );
        }
        let local: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        assert_eq!(
            client_ip(Some(local), &HeaderMap::new()),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(client_ip(None, &headers), None);
    }
}
