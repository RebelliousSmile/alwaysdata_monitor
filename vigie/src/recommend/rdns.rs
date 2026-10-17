//! Reverse DNS borné, résolu au moment de proposer (#13) : 10 IP au plus,
//! 5 s en tout. Une IP non résolue dans le temps est `None` : elle ne reçoit
//! pas de règle (seul un hébergeur vérifié en reçoit une).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// IP résolues au plus par proposition.
pub const MAX_IPS: usize = 10;
/// Budget total.
pub const BUDGET: Duration = Duration::from_secs(5);

/// Nom de chaque IP (les `MAX_IPS` premières), `None` si non résolue.
pub fn reverse(ips: &[IpAddr]) -> HashMap<IpAddr, Option<String>> {
    let deadline = Instant::now() + BUDGET;
    let (tx, rx) = mpsc::channel();
    let ips: Vec<IpAddr> = ips.iter().take(MAX_IPS).copied().collect();
    for &ip in &ips {
        let tx = tx.clone();
        // Fil détaché : un résolveur lent ne retient pas la commande au-delà
        // du budget.
        std::thread::spawn(move || {
            let _ = tx.send((ip, lookup(ip)));
        });
    }
    drop(tx);
    let mut names: HashMap<IpAddr, Option<String>> = ips.iter().map(|&ip| (ip, None)).collect();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok((ip, name)) => {
                names.insert(ip, name);
            }
            Err(_) => break,
        }
    }
    names
}

#[cfg(unix)]
fn lookup(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;
    use std::net::SocketAddr;

    let addr = SocketAddr::new(ip, 0);
    let mut host = [0 as libc::c_char; 1025];
    // SAFETY : sockaddr construit à la main pour la famille de l'adresse, de
    // la bonne taille ; `host` est un tampon de NI_MAXHOST octets que
    // getnameinfo termine par un octet nul en cas de succès.
    let rc = unsafe {
        match addr {
            SocketAddr::V4(v4) => {
                let mut sa: libc::sockaddr_in = std::mem::zeroed();
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                libc::getnameinfo(
                    (&raw const sa).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            SocketAddr::V6(v6) => {
                let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_addr.s6_addr = v6.ip().octets();
                libc::getnameinfo(
                    (&raw const sa).cast(),
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if rc != 0 {
        return None;
    }
    // SAFETY : terminé par un octet nul (succès de getnameinfo).
    let name = unsafe { CStr::from_ptr(host.as_ptr()) };
    let name = name
        .to_str()
        .ok()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!name.is_empty() && name.len() <= 253).then_some(name)
}

#[cfg(not(unix))]
fn lookup(_ip: IpAddr) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_most_ten_ips_within_the_budget() {
        let ips: Vec<IpAddr> = (1..=12)
            .map(|i| format!("192.0.2.{i}").parse().unwrap())
            .collect();
        let started = Instant::now();
        let names = reverse(&ips);
        assert_eq!(names.len(), MAX_IPS);
        assert!(started.elapsed() <= BUDGET + Duration::from_secs(1));
    }
}
