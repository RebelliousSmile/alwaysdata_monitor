//! Ce que le veilleur sait du `.htaccess` d'un site : il n'en a que des
//! empreintes (rapports) et les commandes `htaccess-*` passées.
//!
//! - **Bloc en place** : celui du dernier `htaccess-apply` `done` dont
//!   `current_sha256` égale l'empreinte `.htaccess` du dernier rapport.
//!   Sans cette correspondance (fichier modifié hors de Vigie, retour
//!   arrière, première application), les règles en place sont inconnues.
//! - **Calcul préparé** : un `htaccess-apply` en calcul seul (`new_sha256`
//!   nul) `done`, sur la même empreinte précédente, rend `new_sha256` ; le
//!   veilleur ne peut pas la calculer lui-même (SHA-256 n'est pas
//!   composable, et il ne connaît pas le reste du fichier).
//! - **Retour arrière** : la copie privée de l'agent est le contenu d'avant
//!   le dernier `htaccess-apply` dont l'empreinte est en place.

use anyhow::Result;

use crate::capability::CommandKind;
use crate::command::store::Command;
use crate::command::{CommandResult, HTACCESS, HtaccessApply, HtaccessRollback, State};
use crate::facts::Files;
use crate::store::Store;

/// Empreinte du `.htaccess` du dernier rapport : `None` sans rapport ou si
/// `.htaccess` n'est pas un fichier critique de l'agent ; `Some(None)` pour
/// un fichier absent ou illisible.
pub fn reported_htaccess(store: &Store, site: &str) -> Result<Option<Option<String>>> {
    let Some(files) = store.last_files(site)? else {
        return Ok(None);
    };
    let files: Files = serde_json::from_str(&files)?;
    Ok(files.get(HTACCESS).cloned())
}

fn result_of(command: &Command) -> Option<CommandResult> {
    command
        .result
        .as_deref()
        .and_then(|r| serde_json::from_str(r).ok())
}

fn apply_params(command: &Command) -> Option<HtaccessApply> {
    (command.kind == CommandKind::HtaccessApply)
        .then(|| serde_json::from_str(&command.params).ok())
        .flatten()
}

/// Un `htaccess-apply` passé, ses paramètres et son identifiant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub command_id: String,
    pub created_at: i64,
    pub params: HtaccessApply,
}

/// Bloc en place : dernier `htaccess-apply` écrit (`new_sha256` non nul),
/// `done`, dont `current_sha256` égale `reported`.
pub fn block_in_place(store: &Store, site: &str, reported: &str) -> Result<Option<Applied>> {
    let commands = store.commands(site)?;
    Ok(commands.iter().rev().find_map(|c| {
        let params = apply_params(c)?;
        let result = result_of(c)?;
        (c.state == State::Done
            && params.new_sha256.is_some()
            && result.data.current_sha256.as_deref() == Some(reported))
        .then(|| Applied {
            command_id: c.id.clone(),
            created_at: c.created_at,
            params,
        })
    }))
}

/// Calcul préparé : le dernier `htaccess-apply` du site est un calcul seul,
/// `done`, sur `previous` ; rend ses paramètres, `new_sha256` rempli par le
/// résultat de l'agent.
pub fn prepared(store: &Store, site: &str, previous: Option<&str>) -> Result<Option<Applied>> {
    let commands = store.commands(site)?;
    let Some(last) = commands
        .iter()
        .rev()
        .find(|c| c.kind == CommandKind::HtaccessApply)
    else {
        return Ok(None);
    };
    let (Some(mut params), Some(result)) = (apply_params(last), result_of(last)) else {
        return Ok(None);
    };
    if last.state != State::Done
        || params.new_sha256.is_some()
        || params.previous_sha256.as_deref() != previous
        || result.data.current_sha256.as_deref() != previous
    {
        return Ok(None);
    }
    let Some(computed) = result.data.new_sha256 else {
        return Ok(None);
    };
    params.new_sha256 = Some(computed);
    Ok(Some(Applied {
        command_id: last.id.clone(),
        created_at: last.created_at,
        params,
    }))
}

/// Paramètres d'un retour arrière : le `.htaccess` a l'empreinte du dernier
/// `htaccess-apply` en place, la copie privée celle d'avant.
pub fn rollback_params(
    store: &Store,
    site: &str,
    reported: &str,
) -> Result<Option<HtaccessRollback>> {
    Ok(
        block_in_place(store, site, reported)?.map(|applied| HtaccessRollback {
            expected_current_sha256: Some(reported.to_owned()),
            prev_sha256: applied.params.previous_sha256,
        }),
    )
}
