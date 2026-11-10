//! Appareils de la console : jetons, codes d'appairage et leurs empreintes
//! (`docs/api-console.md`).
//!
//! Le veilleur ne garde que l'empreinte SHA-256 d'un jeton ou d'un code : une
//! base volée ne contient rien qui ouvre l'API.

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Octets aléatoires d'un jeton d'appareil.
pub const TOKEN_BYTES: usize = 32;
/// Octets aléatoires d'un code d'appairage.
pub const CODE_BYTES: usize = 16;
/// Durée de vie d'un code d'appairage, en secondes.
pub const PAIRING_TTL: i64 = 600;
/// Longueur maximale du nom d'un appareil, en caractères.
pub const MAX_NAME_CHARS: usize = 64;
/// Au-delà, un jeton ou un code présenté est refusé sans être haché.
pub const MAX_SECRET_LEN: usize = 128;

/// Empreinte SHA-256 d'un jeton ou d'un code.
pub type Hash = [u8; 32];

fn random_secret(bytes: usize) -> Result<String> {
    let mut raw = vec![0u8; bytes];
    getrandom::fill(&mut raw)
        .map_err(|err| anyhow::anyhow!("tirage aléatoire impossible : {err}"))?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

/// Jeton d'appareil : 32 octets aléatoires en base64url sans remplissage.
pub fn new_token() -> Result<String> {
    random_secret(TOKEN_BYTES)
}

/// Code d'appairage : 16 octets aléatoires en base64url sans remplissage.
pub fn new_code() -> Result<String> {
    random_secret(CODE_BYTES)
}

/// Empreinte du secret tel qu'il est transmis.
pub fn hash(secret: &str) -> Hash {
    Sha256::digest(secret.as_bytes()).into()
}

/// Comparaison en temps constant.
pub fn ct_eq(a: &Hash, b: &Hash) -> bool {
    a.ct_eq(b).into()
}

/// `vigie://pair?u=<public_url>&c=<code>` : le même lien dans le QR code et
/// en texte. Collé tel quel, il porte l'adresse du veilleur et le code.
pub fn pair_link(public_url: &str, code: &str) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("u", public_url)
        .append_pair("c", code)
        .finish();
    format!("vigie://pair?{query}")
}

/// L'adresse publique doit être en https ; http n'est admis que sur la boucle
/// locale (127.0.0.1, ::1, localhost), pour les essais.
pub fn check_public_url(public_url: &str) -> Result<()> {
    let url = url::Url::parse(public_url)
        .with_context(|| format!("api.public_url illisible (reçu : {public_url})"))?;
    let loopback = match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        _ => bail!(
            "api.public_url doit être en https (http n'est admis que sur 127.0.0.1, ::1 ou localhost) : reçu {public_url}"
        ),
    }
}

/// Nom d'appareil : non vide, 64 caractères au plus, sans caractère de contrôle.
pub fn check_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if name.is_empty() {
        bail!("nom d'appareil vide");
    }
    if name.chars().count() > MAX_NAME_CHARS {
        bail!("nom d'appareil trop long : {MAX_NAME_CHARS} caractères au plus");
    }
    if name.chars().any(char::is_control) {
        bail!("nom d'appareil : caractère de contrôle refusé");
    }
    Ok(name)
}

/// QR code en caractères Unicode, deux modules par caractère, clair sur fond
/// sombre : les modules clairs sont pleins, pour un terminal à fond sombre.
pub fn render_qr(link: &str) -> Result<String> {
    let code = QrCode::new(link.as_bytes()).context("QR code impossible")?;
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_random_and_url_safe() {
        let a = new_token().expect("token");
        let b = new_token().expect("token");
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_eq!(new_code().expect("code").len(), 22);
    }

    #[test]
    fn a_hash_finds_its_secret_again() {
        let token = new_token().expect("token");
        assert!(ct_eq(&hash(&token), &hash(&token)));
        assert!(!ct_eq(&hash(&token), &hash(&new_token().expect("token"))));
    }

    #[test]
    fn the_link_carries_the_url_and_the_code() {
        let link = pair_link("https://veilleur.example.org", "abc-_1");
        assert_eq!(
            link,
            "vigie://pair?u=https%3A%2F%2Fveilleur.example.org&c=abc-_1"
        );
        let parsed = url::Url::parse(&link).expect("url");
        let pairs: Vec<_> = parsed.query_pairs().collect();
        assert_eq!(pairs[0].1, "https://veilleur.example.org");
        assert_eq!(pairs[1].1, "abc-_1");
    }

    #[test]
    fn plain_http_is_only_for_loopback() {
        for ok in [
            "https://veilleur.example.org",
            "http://127.0.0.1:8080",
            "http://[::1]:8080/",
            "http://localhost:8080",
        ] {
            assert!(check_public_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://veilleur.example.org",
            "http://192.0.2.10",
            "ftp://veilleur.example.org",
            "veilleur.example.org",
        ] {
            assert!(check_public_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn names_are_bounded() {
        assert_eq!(check_name("  téléphone ").expect("ok"), "téléphone");
        assert!(check_name("   ").is_err());
        assert!(check_name(&"é".repeat(65)).is_err());
        assert!(check_name(&"é".repeat(64)).is_ok());
        assert!(check_name("a\nb").is_err());
    }
}
