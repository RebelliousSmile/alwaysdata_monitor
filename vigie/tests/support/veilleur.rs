//! Configuration minimale d'un veilleur de test : la base donnée et le seul
//! site A, sans relais SMTP réel. Incluse par `#[path]` dans les tests qui
//! montent le routeur de `serve`.

use std::path::PathBuf;

use vigie::config::{Alerts, Config, Site, SiteKind};

pub fn site_a() -> Site {
    Site {
        id: "site-a".into(),
        url: "https://site-a.example.org/".into(),
        kind: SiteKind::Generic,
        runtime: None,
        keyword_url: None,
        keyword: None,
        interval: 300,
        agent_silence: 900,
    }
}

pub fn config(database: PathBuf) -> Config {
    Config {
        alerts: Alerts {
            to: "alertes@example.org".into(),
            from: "vigie@example.org".into(),
            smtp_host: "smtp.example.org".into(),
            smtp_port: 587,
            smtp_user: None,
            password_file: database.with_file_name("smtp-password"),
        },
        database,
        api: None,
        commands: None,
        sites: vec![site_a()],
    }
}
