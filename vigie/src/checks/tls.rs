//! `tls` : poignée de main rustls sur le port du site. Un certificat refusé
//! (nom non couvert, expiré, autorité inconnue) est critique ; un certificat
//! valide est lu pour sa date d'expiration.

use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Instant;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use url::{Host, Url};

use super::{CheckError, CheckKind, Ctx};
use crate::config::Site;
use crate::finding::{Finding, Severity};

const WARNING_DAYS: i64 = 14;
const CRITICAL_DAYS: i64 = 3;

pub fn run(site: &Site, ctx: &Ctx) -> Result<Vec<Finding>, CheckError> {
    let url =
        Url::parse(&site.url).map_err(|err| CheckError::new(format!("URL illisible : {err}")))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let (addr, server_name) = resolve(&url, port)?;
    let finding = |severity, key: &str, detail: String| {
        Finding::new(&site.id, CheckKind::Tls.name(), severity, key, detail)
    };
    let leaf = match handshake(addr, server_name, ctx) {
        Ok(leaf) => leaf,
        Err(Handshake::Refused(err)) => {
            return Ok(vec![finding(
                Severity::Critical,
                "invalid",
                format!("certificat refusé : {err}"),
            )]);
        }
        Err(Handshake::Io(err)) => return Err(err),
    };
    let (_, cert) = x509_parser::parse_x509_certificate(&leaf)
        .map_err(|err| CheckError::new(format!("certificat illisible : {err}")))?;
    let not_after = cert.validity().not_after.timestamp();
    let days = (not_after - crate::now()).div_euclid(86_400);
    let detail = format!(
        "certificat valable jusqu'au {} ({days} j)",
        crate::iso_utc(not_after)
    );
    Ok(match days {
        ..CRITICAL_DAYS => vec![finding(Severity::Critical, "expiry", detail)],
        CRITICAL_DAYS..WARNING_DAYS => vec![finding(Severity::Warning, "expiry", detail)],
        _ => Vec::new(),
    })
}

fn resolve(url: &Url, port: u16) -> Result<(SocketAddr, ServerName<'static>), CheckError> {
    match url.host() {
        Some(Host::Domain(domain)) => {
            let addr = (domain, port)
                .to_socket_addrs()
                .map_err(|err| CheckError::new(format!("résolution de {domain} : {err}")))?
                .next()
                .ok_or_else(|| CheckError::new(format!("{domain} : aucune adresse")))?;
            let name = ServerName::try_from(domain.to_owned())
                .map_err(|err| CheckError::new(format!("{domain} : {err}")))?;
            Ok((addr, name))
        }
        Some(Host::Ipv4(ip)) => Ok((SocketAddr::from((ip, port)), ServerName::from(ip))),
        Some(Host::Ipv6(ip)) => Ok((SocketAddr::from((ip, port)), ServerName::from(ip))),
        None => Err(CheckError::new("URL sans hôte")),
    }
}

enum Handshake {
    /// rustls a refusé le certificat ou la négociation.
    Refused(rustls::Error),
    /// Réseau : non concluant.
    Io(CheckError),
}

fn handshake(
    addr: SocketAddr,
    server_name: ServerName<'static>,
    ctx: &Ctx,
) -> Result<Vec<u8>, Handshake> {
    let remaining = ctx.deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Handshake::Io(CheckError {
            message: "échéance du passage atteinte".into(),
            cut_short: true,
        }));
    }
    let timeout = remaining.min(ctx.request_timeout);
    let io_err = |err: io::Error| Handshake::Io(CheckError::new(format!("{addr} : {err}")));
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(io_err)?;
    stream.set_read_timeout(Some(timeout)).map_err(io_err)?;
    stream.set_write_timeout(Some(timeout)).map_err(io_err)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(Handshake::Refused)?
        .with_root_certificates(ctx.trust.root_store())
        .with_no_client_auth();
    let mut conn =
        ClientConnection::new(Arc::new(config), server_name).map_err(Handshake::Refused)?;
    while conn.is_handshaking() {
        if let Err(err) = conn.complete_io(&mut stream) {
            let refused = err
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                .cloned();
            return Err(match refused {
                Some(refused) => Handshake::Refused(refused),
                None => io_err(err),
            });
        }
    }
    conn.peer_certificates()
        .and_then(|certs| certs.first())
        .map(|leaf| leaf.as_ref().to_vec())
        .ok_or_else(|| Handshake::Io(CheckError::new("aucun certificat présenté")))
}
