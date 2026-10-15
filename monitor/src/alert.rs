//! Alertes par e-mail : un relais SMTP authentifié (port 587, STARTTLS
//! obligatoire), un seul destinataire, jamais un client.
//!
//! Le mot de passe est lu dans `password_file` à chaque envoi. Le fichier est
//! refusé, avant toute connexion, s'il est lisible par le groupe ou les autres
//! ou s'il appartient à un autre utilisateur. Aucune erreur ne cite son contenu.

use std::io::Read;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

use crate::config::Alerts;
use crate::store::Incident;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    pub subject: String,
    pub body: String,
}

pub trait Notifier {
    fn send(&self, email: &Email, timeout: Duration) -> Result<(), String>;
}

/// Notifier des tests : garde les e-mails, ou échoue sur demande.
#[derive(Debug, Default)]
pub struct MemoryNotifier {
    sent: Mutex<Vec<Email>>,
    failing: Mutex<bool>,
}

impl MemoryNotifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_failing(&self, failing: bool) {
        *self.failing.lock().unwrap_or_else(|e| e.into_inner()) = failing;
    }

    /// Rend les e-mails reçus depuis le dernier appel.
    pub fn take(&self) -> Vec<Email> {
        std::mem::take(&mut *self.sent.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl Notifier for MemoryNotifier {
    fn send(&self, email: &Email, _timeout: Duration) -> Result<(), String> {
        if *self.failing.lock().unwrap_or_else(|e| e.into_inner()) {
            return Err("échec simulé".into());
        }
        self.sent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(email.clone());
        Ok(())
    }
}

pub struct SmtpNotifier {
    alerts: Alerts,
}

impl SmtpNotifier {
    pub fn new(alerts: Alerts) -> Self {
        Self { alerts }
    }
}

impl Notifier for SmtpNotifier {
    fn send(&self, email: &Email, timeout: Duration) -> Result<(), String> {
        let password = read_password(&self.alerts.password_file)?;
        let mailbox = |value: &str| {
            value
                .parse::<Mailbox>()
                .map_err(|err| format!("adresse {value} : {err}"))
        };
        let message = Message::builder()
            .from(mailbox(&self.alerts.from)?)
            .to(mailbox(&self.alerts.to)?)
            .subject(email.subject.clone())
            .header(ContentType::TEXT_PLAIN)
            .message_id(None)
            .body(email.body.clone())
            .map_err(|err| format!("construction de l'e-mail : {err}"))?;
        let transport = SmtpTransport::starttls_relay(&self.alerts.smtp_host)
            .map_err(|err| format!("relais {} : {err}", self.alerts.smtp_host))?
            .port(self.alerts.smtp_port)
            .credentials(Credentials::new(
                self.alerts.smtp_user().to_owned(),
                password,
            ))
            .timeout(Some(timeout))
            .build();
        transport.send(&message).map(|_| ()).map_err(|err| {
            format!(
                "envoi par {}:{} : {err}",
                self.alerts.smtp_host, self.alerts.smtp_port
            )
        })
    }
}

/// Lit le mot de passe après avoir vérifié le fichier ouvert (et non son
/// chemin, qui pourrait changer entre la vérification et la lecture).
pub fn read_password(path: &Path) -> Result<String, String> {
    let shown = path.display();
    let mut file =
        std::fs::File::open(path).map_err(|err| format!("password_file {shown} : {err}"))?;
    let meta = file
        .metadata()
        .map_err(|err| format!("password_file {shown} : {err}"))?;
    check_permissions(path, &meta)?;
    let mut raw = String::new();
    file.read_to_string(&mut raw).map_err(|err| {
        format!(
            "password_file {shown} : lecture impossible ({})",
            err.kind()
        )
    })?;
    let password = raw.trim_end_matches(['\r', '\n']).to_owned();
    if password.is_empty() {
        return Err(format!("password_file {shown} est vide"));
    }
    Ok(password)
}

#[cfg(unix)]
fn check_permissions(path: &Path, meta: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "password_file {} en mode {mode:o} : 600 attendu (chmod 600)",
            path.display()
        ));
    }
    // SAFETY: geteuid n'a ni argument ni effet de bord, et ne peut échouer.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(format!(
            "password_file {} appartient à l'uid {}, pas à l'uid {euid} du veilleur",
            path.display(),
            meta.uid()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path, _meta: &std::fs::Metadata) -> Result<(), String> {
    Ok(())
}

/// Un objet d'e-mail tient sur une ligne.
fn one_line(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn header(site_url: &str, incident: &Incident) -> String {
    format!(
        "Site : {} ({site_url})\nContrôle : {} — {}\nConstat : {}\nPremier signal : {}\nIncident n° {}\n",
        incident.site,
        incident.check_name,
        incident.severity,
        incident.detail,
        crate::iso_utc(incident.opened_at),
        incident.id,
    )
}

fn ack_hint(incident: &Incident) -> String {
    format!(
        "\nPour arrêter les rappels, sur le veilleur :\n  ~/monitor/bin/monitor ack {}\n",
        incident.id
    )
}

pub fn open_email(incident: &Incident, site_url: &str) -> Email {
    Email {
        subject: one_line(&format!(
            "[monitor] {} : {}",
            incident.site, incident.detail
        )),
        body: format!("{}{}", header(site_url, incident), ack_hint(incident)),
    }
}

pub fn reminder_email(incident: &Incident, site_url: &str) -> Email {
    Email {
        subject: one_line(&format!(
            "[monitor] {} : toujours en cours — {}",
            incident.site, incident.detail
        )),
        body: format!("{}{}", header(site_url, incident), ack_hint(incident)),
    }
}

pub fn close_email(incident: &Incident, site_url: &str) -> Email {
    let closed = incident
        .closed_at
        .map(crate::iso_utc)
        .unwrap_or_else(|| "?".into());
    Email {
        subject: one_line(&format!(
            "[monitor] {} : rétabli — {}",
            incident.site, incident.detail
        )),
        body: format!("{}Rétabli : {closed}\n", header(site_url, incident)),
    }
}

pub fn test_email(now: i64) -> Email {
    Email {
        subject: "[monitor] e-mail de test".into(),
        body: format!(
            "E-mail de test envoyé par `monitor test-alert` le {}.\nLe relais SMTP fonctionne.\n",
            crate::iso_utc(now)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    fn incident() -> Incident {
        Incident {
            id: 7,
            key: "site-a/exposed/.env".into(),
            site: "site-a".into(),
            check_name: "exposed".into(),
            severity: Severity::Critical,
            detail: "fichier exposé\r\nBcc: x@y".into(),
            opened_at: 0,
            closed_at: Some(60),
            acked_at: None,
        }
    }

    #[test]
    fn subjects_stay_on_one_line() {
        let email = open_email(&incident(), "https://a.example.org/");
        assert!(!email.subject.contains(['\r', '\n']), "{:?}", email.subject);
        assert!(email.subject.starts_with("[monitor] site-a : "));
        assert!(email.body.contains("monitor ack 7"));
        assert!(email.body.contains("1970-01-01T00:00:00Z"));
        let close = close_email(&incident(), "https://a.example.org/");
        assert!(close.subject.contains("rétabli"));
        assert!(!close.body.contains("ack"));
    }

    #[test]
    fn reads_the_password_without_its_line_ending() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("smtp-password");
        std::fs::write(&path, "s3cret\r\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        assert_eq!(read_password(&path).expect("lu"), "s3cret");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_readable_password_file_without_quoting_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("smtp-password");
        std::fs::write(&path, "s3cret\n").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = read_password(&path).expect_err("refusé");
        assert!(err.contains("644"), "{err}");
        assert!(!err.contains("s3cret"), "{err}");
    }
}
