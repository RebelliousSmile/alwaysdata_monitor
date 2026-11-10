//! `vigie-inventory` : inventaire des composants d'un projet, lu dans ses
//! lockfiles au déploiement, écrit en CycloneDX 1.7 ou signé par la clé
//! d'inventaire du site et poussé au veilleur (issue #20,
//! `vigie/docs/inventaire.md`).
//!
//! La graine vient de `VIGIE_INVENTORY_KEY` (lue après l'analyse des
//! arguments, jamais par `clap`) ou de `--key-file`. Codes de sortie : 0
//! écrit ou envoyé, 1 refus du veilleur ou réseau, 2 usage, clé, lockfile,
//! projet.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

use vigie::config::is_valid_id;
use vigie::inventory::TOOL_VERSION;
use vigie::inventory::build::{self, Cms, Document, Options, Stamp};
use vigie::inventory::tool::{self, KEY_ENV, ToolError};

#[derive(Debug, Parser)]
#[command(
    name = "vigie-inventory",
    version = TOOL_VERSION,
    about = "Inventaire CycloneDX des lockfiles d'un projet, poussé au veilleur Vigie"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Crée une graine d'inventaire (création exclusive, 0600) et affiche sa
    /// clé publique, jamais la graine
    Keygen {
        /// Fichier de la graine, dans un dossier en 0700
        #[arg(long)]
        out: PathBuf,
    },
    /// Affiche la clé publique de la graine fournie
    Pubkey {
        /// Fichier de la graine (sinon la variable VIGIE_INVENTORY_KEY)
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
    /// Écrit le BOM CycloneDX seul, sans clé ni réseau
    Sbom {
        /// Identifiant du site (`metadata.component.name`, sinon « projet »)
        #[arg(long)]
        site: Option<String>,
        /// Fichier de sortie (sinon la sortie standard)
        #[arg(long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        project: ProjectArgs,
    },
    /// Signe l'inventaire avec la clé d'inventaire du site et l'envoie
    Push {
        /// Identifiant du site dans la configuration du veilleur
        #[arg(long)]
        site: String,
        /// URL de base du veilleur (https://vigie.example.org)
        #[arg(long)]
        endpoint: String,
        /// Écrit aussi le BOM dans ce fichier
        #[arg(long)]
        output: Option<PathBuf>,
        /// Affiche l'enveloppe non signée et n'envoie rien
        #[arg(long)]
        dry_run: bool,
        /// Sans clé fournie : message et code 0, rien n'est envoyé
        #[arg(long)]
        skip_without_key: bool,
        /// Fichier de la graine (sinon la variable VIGIE_INVENTORY_KEY)
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// Tests seulement : admet http vers 127.0.0.1 ou [::1]
        #[arg(long, hide = true)]
        allow_http_loopback: bool,
        #[command(flatten)]
        project: ProjectArgs,
    },
}

#[derive(Debug, Args)]
struct ProjectArgs {
    /// Dossier du projet
    #[arg(long, default_value = ".")]
    project_dir: PathBuf,
    /// Lockfile à lire, relatif au projet (répétable, 10 au plus) ; sinon
    /// les lockfiles connus à la racine
    #[arg(long)]
    lockfile: Vec<PathBuf>,
    /// CMS du projet : wpackagist-* en pkg:wordpress
    #[arg(long, value_enum)]
    cms: Option<CmsArg>,
    /// Retire les dépendances de développement (inventaire incomplet)
    #[arg(long)]
    omit_dev: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CmsArg {
    Wordpress,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("vigie-inventory : {err}");
            ExitCode::from(err.code)
        }
    }
}

fn site_id(site: &str) -> Result<(), ToolError> {
    if is_valid_id(site) {
        Ok(())
    } else {
        Err(ToolError::usage(
            "--site : identifiant du veilleur attendu ([a-z0-9-], 64 caractères au plus)",
        ))
    }
}

/// Lockfiles lus et document construit, faits sur stderr.
fn build_document(name: &str, project: &ProjectArgs) -> Result<Document, ToolError> {
    let found = tool::find_lockfiles(&project.project_dir, &project.lockfile)?;
    eprintln!(
        "lockfiles lus : {}",
        found
            .iter()
            .map(|f| f.relative.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let lockfiles = tool::read_lockfiles(&found)?;
    let (seq, sent_at) = tool::now();
    let options = Options {
        cms: project.cms.map(|CmsArg::Wordpress| Cms::Wordpress),
        omit_dev: project.omit_dev,
    };
    let document = tool::document(
        name,
        &lockfiles,
        options,
        Stamp {
            seq,
            sent_at,
            serial: tool::serial()?,
        },
    )?;
    for line in tool::summary(&document) {
        eprintln!("{line}");
    }
    Ok(document)
}

fn run(cli: Cli) -> Result<(), ToolError> {
    match cli.command {
        Command::Keygen { out } => {
            let public = vigie::command::key::create(&out).map_err(|e| tool::key_error(&out, e))?;
            let public = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                public.to_bytes(),
            );
            println!("{public}");
            eprintln!(
                "graine écrite dans {} (0600) : la mettre en secret {KEY_ENV} de \
                 l'environnement de déploiement, puis supprimer le fichier",
                out.display()
            );
            eprintln!("sur le veilleur : vigie site inventory-key <site> add --pubkey {public}");
            Ok(())
        }
        Command::Pubkey { key_file } => {
            let key = tool::signing_key(key_file.as_deref())?
                .ok_or_else(|| ToolError::usage(format!("aucune clé : {KEY_ENV} ou --key-file")))?;
            println!("{}", tool::public_key(&key));
            Ok(())
        }
        Command::Sbom {
            site,
            output,
            project,
        } => {
            if let Some(site) = &site {
                site_id(site)?;
            }
            let name = site.as_deref().unwrap_or(build::DEFAULT_NAME);
            let document = build_document(name, &project)?;
            let json = tool::bom_json(&document);
            match output {
                Some(path) => {
                    tool::write_atomic(&path, &json)?;
                    eprintln!("BOM écrit dans {}", path.display());
                }
                None => {
                    use std::io::Write;
                    std::io::stdout()
                        .write_all(&json)
                        .map_err(|_| ToolError::usage("écriture sur la sortie standard"))?;
                }
            }
            Ok(())
        }
        Command::Push {
            site,
            endpoint,
            output,
            dry_run,
            skip_without_key,
            key_file,
            allow_http_loopback,
            project,
        } => {
            site_id(&site)?;
            let url = tool::endpoint(&endpoint, allow_http_loopback)?;
            let key = if dry_run {
                None
            } else {
                match tool::signing_key(key_file.as_deref())? {
                    Some(key) => Some(key),
                    None if skip_without_key => {
                        eprintln!(
                            "aucune clé ({KEY_ENV} ou --key-file) : inventaire non envoyé \
                             (--skip-without-key)"
                        );
                        return Ok(());
                    }
                    None => {
                        return Err(ToolError::usage(format!(
                            "aucune clé : {KEY_ENV} ou --key-file (--skip-without-key pour \
                             ne rien envoyer sans clé)"
                        )));
                    }
                }
            };
            let document = build_document(&site, &project)?;
            if let Some(path) = &output {
                tool::write_atomic(path, &tool::bom_json(&document))?;
                eprintln!("BOM écrit dans {}", path.display());
            }
            let Some(key) = key else {
                let mut json = serde_json::to_vec_pretty(&document.envelope)
                    .map_err(|_| ToolError::usage("erreur interne : sérialisation"))?;
                json.push(b'\n');
                use std::io::Write;
                std::io::stdout()
                    .write_all(&json)
                    .map_err(|_| ToolError::usage("écriture sur la sortie standard"))?;
                eprintln!("--dry-run : enveloppe non signée, rien n'est envoyé");
                return Ok(());
            };
            tool::push(
                &tool::agent(allow_http_loopback),
                &url,
                &site,
                &document,
                &key,
            )?;
            eprintln!(
                "inventaire envoyé : {} composant(s), {}",
                document.report.components,
                if document.envelope.complete {
                    "complet"
                } else {
                    "incomplet"
                }
            );
            Ok(())
        }
    }
}
