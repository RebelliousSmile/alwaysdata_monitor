//! Alertes par e-mail : un relais SMTP authentifié (port 587, STARTTLS
//! obligatoire), un seul destinataire, jamais un client.
//!
//! Incidents `vulns` (#21) : objet = première ligne du détail ; au-delà de
//! cinq e-mails en attente pour un site (ouvertures, rappels ou clôtures),
//! un seul e-mail groupé ([`vulns_grouped_open`], [`vulns_grouped_reminder`],
//! [`vulns_grouped_close`]).
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

use crate::capability::WATCHER_SITE;
use crate::config::Alerts;
use crate::finding::Severity;
use crate::store::{CloseReason, Incident};

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
        "\nPour arrêter les rappels, sur le veilleur :\n  ~/vigie/bin/vigie ack {}\n",
        incident.id
    )
}

/// Incident d'un contrôle du veilleur (pseudo-site [`WATCHER_SITE`]) :
/// gabarits propres, sans ligne « site » ni URL.
fn is_watcher(incident: &Incident) -> bool {
    incident.site == WATCHER_SITE
}

/// Source de failles d'un incident `vulns-sync` (clé du constat).
fn watcher_source(incident: &Incident) -> String {
    one_line(incident.finding_key().unwrap_or("?"))
}

fn watcher_header(incident: &Incident) -> String {
    let source = watcher_source(incident);
    format!(
        "Veilleur : base de failles {source}\nContrôle : {} — {}\nConstat : {}\nPremier signal : {}\nIncident n° {}\n",
        incident.check_name,
        incident.severity,
        incident.detail,
        crate::iso_utc(incident.opened_at),
        incident.id,
    )
}

fn watcher_hint(incident: &Incident) -> String {
    format!(
        "\nRelancer à la main et lire le journal, sur le veilleur :\n  ~/vigie/bin/vigie vulns sync --source {}\n  journalctl -u vigie-vulns-sync\n",
        watcher_source(incident)
    )
}

/// E-mail d'un incident du veilleur.
#[derive(Clone, Copy)]
enum Mail {
    Open,
    Reminder,
    Close,
}

fn watcher_email(incident: &Incident, kind: Mail) -> Email {
    let source = watcher_source(incident);
    let closed = incident
        .closed_at
        .map(crate::iso_utc)
        .unwrap_or_else(|| "?".into());
    let (subject, tail) = match kind {
        Mail::Open => (
            format!("[vigie] veilleur : base de failles {source} non synchronisée"),
            format!("{}{}", watcher_hint(incident), ack_hint(incident)),
        ),
        Mail::Reminder => (
            format!("[vigie] veilleur : base de failles {source} toujours non synchronisée"),
            format!("{}{}", watcher_hint(incident), ack_hint(incident)),
        ),
        Mail::Close => match incident.close_reason {
            Some(CloseReason::Unwatched) => (
                format!("[vigie] veilleur : base de failles {source} plus surveillée"),
                format!(
                    "Plus surveillée : {closed}\nLa source n'est plus déclarée dans [vulns] sources : l'incident est clos sans que l'état de la base soit connu.\n"
                ),
            ),
            Some(CloseReason::Resolved) | None => (
                format!("[vigie] veilleur : base de failles {source} de nouveau synchronisée"),
                format!("Synchronisée de nouveau : {closed}\n"),
            ),
        },
    };
    Email {
        subject: one_line(&subject),
        body: format!("{}{tail}", watcher_header(incident)),
    }
}

/// Incident du contrôle `vulns` (#21).
pub fn is_vulns(incident: &Incident) -> bool {
    incident.check_name == crate::vulns::matching::finding::CHECK
}

/// Première ligne du détail d'un incident `vulns`, sur une ligne, 200
/// caractères au plus : l'objet de ses e-mails.
fn vulns_first_line(incident: &Incident) -> String {
    one_line(incident.detail.lines().next().unwrap_or(""))
        .chars()
        .take(crate::vulns::matching::finding::MAX_SUBJECT_CHARS)
        .collect()
}

fn vulns_hint(site: &str) -> String {
    format!(
        "\nFailles, versions corrigées et dérogations, sur le veilleur :\n  ~/vigie/bin/vigie site vulns {site}\n"
    )
}

fn vulns_email(incident: &Incident, site_url: &str, kind: Mail) -> Email {
    let first = vulns_first_line(incident);
    let closed = incident
        .closed_at
        .map(crate::iso_utc)
        .unwrap_or_else(|| "?".into());
    let (subject, tail) = match kind {
        Mail::Open => (
            format!("[vigie] {} : {first}", incident.site),
            format!("{}{}", vulns_hint(&incident.site), ack_hint(incident)),
        ),
        Mail::Reminder => (
            format!("[vigie] {} : toujours en cours — {first}", incident.site),
            format!("{}{}", vulns_hint(&incident.site), ack_hint(incident)),
        ),
        Mail::Close => match incident.close_reason {
            Some(CloseReason::Unwatched) => (
                format!("[vigie] {} : plus surveillé — {first}", incident.site),
                format!(
                    "Plus surveillé : {closed}\nAucune source d'inventaire ne voit plus ce composant, ou la source qui le voyait est retirée : l'incident est clos sans que l'état du composant soit connu.\n"
                ),
            ),
            Some(CloseReason::Resolved) | None => (
                format!("[vigie] {} : rétabli — {first}", incident.site),
                format!("Rétabli : {closed}\n"),
            ),
        },
    };
    Email {
        subject: one_line(&subject),
        body: format!("{}{tail}", header(site_url, incident)),
    }
}

/// Compte par gravité et les dix plus graves d'un envoi groupé.
fn vulns_digest(incidents: &[Incident]) -> String {
    let count = |s: Severity| incidents.iter().filter(|i| i.severity == s).count();
    let mut sorted: Vec<&Incident> = incidents.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
    let mut text = format!(
        "Constats : {} ({} critique(s), {} avertissement(s), {} information(s))\n\nLes {} plus graves :\n",
        incidents.len(),
        count(Severity::Critical),
        count(Severity::Warning),
        count(Severity::Info),
        sorted.len().min(10),
    );
    for i in sorted.iter().take(10) {
        text.push_str(&format!(
            "  n° {} — {} — {}\n",
            i.id,
            i.severity,
            vulns_first_line(i)
        ));
    }
    if incidents.iter().any(|i| {
        i.detail
            .contains(crate::vulns::matching::finding::INTERNAL_NOTE)
    }) {
        text.push('\n');
        text.push_str(crate::vulns::matching::finding::INTERNAL_NOTE);
        text.push('\n');
    }
    text
}

fn grouped_header(site: &str, site_url: &str) -> String {
    format!("Site : {site} ({site_url})\nContrôle : vulns\n")
}

/// Un seul e-mail pour plus de cinq ouvertures `vulns` en attente sur un
/// site (premier rapprochement, faille entrée dans KEV…).
pub fn vulns_grouped_open(site: &str, site_url: &str, incidents: &[Incident]) -> Email {
    Email {
        subject: one_line(&format!(
            "[vigie] {site} : {} constats de failles à traiter",
            incidents.len()
        )),
        body: format!(
            "{}{}{}\nPour arrêter les rappels d'un incident, sur le veilleur :\n  ~/vigie/bin/vigie ack <n°>\n",
            grouped_header(site, site_url),
            vulns_digest(incidents),
            vulns_hint(site)
        ),
    }
}

/// Un seul rappel pour plus de cinq rappels `vulns` dus sur un site.
pub fn vulns_grouped_reminder(site: &str, site_url: &str, incidents: &[Incident]) -> Email {
    Email {
        subject: one_line(&format!(
            "[vigie] {site} : {} constats de failles toujours en cours",
            incidents.len()
        )),
        body: format!(
            "{}{}{}\nPour arrêter les rappels d'un incident, sur le veilleur :\n  ~/vigie/bin/vigie ack <n°>\n",
            grouped_header(site, site_url),
            vulns_digest(incidents),
            vulns_hint(site)
        ),
    }
}

/// Un seul e-mail pour plus de cinq clôtures `vulns` à annoncer sur un site,
/// rétablis et plus surveillés séparés.
pub fn vulns_grouped_close(site: &str, site_url: &str, incidents: &[Incident]) -> Email {
    let mut sorted: Vec<&Incident> = incidents.iter().collect();
    sorted.sort_by_key(|i| i.id);
    let (unwatched, resolved): (Vec<&Incident>, Vec<&Incident>) = sorted
        .into_iter()
        .partition(|i| i.close_reason == Some(CloseReason::Unwatched));
    let mut body = grouped_header(site, site_url);
    for (title, list) in [
        ("Rétablis", &resolved),
        ("Plus surveillés (état du composant inconnu)", &unwatched),
    ] {
        if list.is_empty() {
            continue;
        }
        body.push_str(&format!("\n{title} : {}\n", list.len()));
        for i in list.iter() {
            body.push_str(&format!("  n° {} — {}\n", i.id, vulns_first_line(i)));
        }
    }
    body.push_str(&vulns_hint(site));
    Email {
        subject: one_line(&format!(
            "[vigie] {site} : {} constats de failles clos ({} rétabli(s), {} plus surveillé(s))",
            incidents.len(),
            resolved.len(),
            unwatched.len()
        )),
        body,
    }
}

pub fn open_email(incident: &Incident, site_url: &str) -> Email {
    if is_watcher(incident) {
        return watcher_email(incident, Mail::Open);
    }
    if is_vulns(incident) {
        return vulns_email(incident, site_url, Mail::Open);
    }
    Email {
        subject: one_line(&format!("[vigie] {} : {}", incident.site, incident.detail)),
        body: format!("{}{}", header(site_url, incident), ack_hint(incident)),
    }
}

pub fn reminder_email(incident: &Incident, site_url: &str) -> Email {
    if is_watcher(incident) {
        return watcher_email(incident, Mail::Reminder);
    }
    if is_vulns(incident) {
        return vulns_email(incident, site_url, Mail::Reminder);
    }
    Email {
        subject: one_line(&format!(
            "[vigie] {} : toujours en cours — {}",
            incident.site, incident.detail
        )),
        body: format!("{}{}", header(site_url, incident), ack_hint(incident)),
    }
}

/// E-mail de clôture, selon sa raison : « rétabli » quand le contrôle ne
/// voit plus le constat, « plus surveillé » quand le contrôle a quitté la
/// typologie du site (`close_unwatched`), sans rien dire de l'état du site.
pub fn close_email(incident: &Incident, site_url: &str) -> Email {
    if is_watcher(incident) {
        return watcher_email(incident, Mail::Close);
    }
    if is_vulns(incident) {
        return vulns_email(incident, site_url, Mail::Close);
    }
    let closed = incident
        .closed_at
        .map(crate::iso_utc)
        .unwrap_or_else(|| "?".into());
    match incident.close_reason {
        Some(CloseReason::Unwatched) => Email {
            subject: one_line(&format!(
                "[vigie] {} : plus surveillé — {}",
                incident.site, incident.detail
            )),
            body: format!(
                "{}Plus surveillé : {closed}\nLe contrôle ne s'applique plus à ce site (site, typologie ou clé d'agent changés) : l'incident est clos sans que l'état du site soit connu.\n",
                header(site_url, incident)
            ),
        },
        Some(CloseReason::Resolved) | None => Email {
            subject: one_line(&format!(
                "[vigie] {} : rétabli — {}",
                incident.site, incident.detail
            )),
            body: format!("{}Rétabli : {closed}\n", header(site_url, incident)),
        },
    }
}

pub fn test_email(now: i64) -> Email {
    Email {
        subject: "[vigie] e-mail de test".into(),
        body: format!(
            "E-mail de test envoyé par `vigie test-alert` le {}.\nLe relais SMTP fonctionne.\n",
            crate::iso_utc(now)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            open_notified_at: None,
            close_notified_at: None,
            last_reminder_at: None,
            close_reason: Some(CloseReason::Resolved),
        }
    }

    #[test]
    fn subjects_stay_on_one_line() {
        let email = open_email(&incident(), "https://a.example.org/");
        assert!(!email.subject.contains(['\r', '\n']), "{:?}", email.subject);
        assert!(email.subject.starts_with("[vigie] site-a : "));
        assert!(email.body.contains("vigie ack 7"));
        assert!(email.body.contains("1970-01-01T00:00:00Z"));
        let close = close_email(&incident(), "https://a.example.org/");
        assert!(close.subject.contains("rétabli"));
        assert!(!close.body.contains("ack"));
    }

    #[test]
    fn an_unwatched_close_never_says_restored() {
        let incident = Incident {
            close_reason: Some(CloseReason::Unwatched),
            ..incident()
        };
        let close = close_email(&incident, "https://a.example.org/");
        assert!(close.subject.contains("plus surveillé"), "{close:?}");
        assert!(!close.subject.contains(['\r', '\n']));
        for text in [&close.subject, &close.body] {
            assert!(!text.to_lowercase().contains("rétabli"), "{close:?}");
        }
    }

    #[test]
    fn watcher_emails_have_their_own_wording() {
        let incident = Incident {
            key: "_veilleur/vulns-sync/osv-npm".into(),
            site: WATCHER_SITE.into(),
            check_name: "vulns-sync".into(),
            severity: Severity::Warning,
            detail: "base osv-npm non synchronisée depuis 4 jours".into(),
            close_reason: None,
            closed_at: None,
            ..incident()
        };
        let open = open_email(&incident, "site retiré de la configuration");
        assert_eq!(
            open.subject,
            "[vigie] veilleur : base de failles osv-npm non synchronisée"
        );
        let reminder = reminder_email(&incident, "site retiré de la configuration");
        for email in [&open, &reminder] {
            assert!(email.body.contains("vigie vulns sync --source osv-npm"));
            assert!(email.body.contains("journalctl -u vigie-vulns-sync"));
            assert!(email.body.contains("vigie ack 7"));
            assert!(!email.body.contains("Site :"), "{email:?}");
            assert!(!email.body.contains("site retiré"), "{email:?}");
        }
        let resolved = Incident {
            closed_at: Some(60),
            close_reason: Some(CloseReason::Resolved),
            ..incident.clone()
        };
        let close = close_email(&resolved, "site retiré de la configuration");
        assert!(close.subject.ends_with("de nouveau synchronisée"));
        let unwatched = Incident {
            close_reason: Some(CloseReason::Unwatched),
            ..resolved
        };
        let close = close_email(&unwatched, "site retiré de la configuration");
        assert!(close.subject.ends_with("plus surveillée"));
        assert!(!close.body.contains("site retiré"));
        assert!(!close.body.to_lowercase().contains("rétabli"));
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
