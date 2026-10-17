//! Liste blanche de l'inventaire (`docs/failles.md`, « Inventaire reçu »,
//! `docs/protocole-agent.md`) : enveloppe Vigie et sous-ensemble strict de
//! CycloneDX 1.6 et 1.7.
//!
//! ```text
//! {"v":1,"type":"inventory","site","source"?,"seq","sent_at","agent","complete","skipped",
//!  "bom":{"bomFormat":"CycloneDX","specVersion","serialNumber",
//!         "metadata":{"timestamp","component":{"type":"application","name":<site>}},
//!         "components":[{"type","name","version","purl","scope","properties"}]}}
//! ```
//!
//! `deny_unknown_fields` partout : un champ de plus (`authors`, `supplier`,
//! `licenses`, `hashes`, `bom-ref`…) ou une propriété hors de `vigie:path`,
//! `vigie:scope`, `vigie:parent` et `vigie:config-version` refuse le document
//! entier. Un défaut d'enveloppe ou de BOM refuse tout ; un défaut propre à un
//! composant (purl non canonique, écosystème non admis, incohérence, doublon
//! `(purl, path)`…) l'écarte et le compte. Chaque refus est une raison fixe :
//! ni le texte d'erreur de serde, ni une valeur reçue.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    Component, ComponentType, Inventory, MAX_COMPONENTS, MAX_NAME_CHARS, MAX_PATH_CHARS,
    MAX_SKIPPED, Scope, Source,
};
use crate::capability;
use crate::command::printable;
use crate::config::SiteKind;
use crate::vulns::purl::{Purl, PurlType};
use crate::vulns::version::in_grammar as version_in_grammar;

/// Versions de CycloneDX acceptées (l'agent émet la 1.7).
pub const SPEC_VERSIONS: [&str; 2] = ["1.6", "1.7"];
/// Écart admis entre `metadata.timestamp` et `sent_at`, en secondes.
pub const TIMESTAMP_WINDOW: i64 = 30 * 86_400;

/// Propriétés admises sur un composant.
pub const PROPERTY_PATH: &str = "vigie:path";
pub const PROPERTY_SCOPE: &str = "vigie:scope";
pub const PROPERTY_PARENT: &str = "vigie:parent";
pub const PROPERTY_CONFIG_VERSION: &str = "vigie:config-version";

/// Refus du document entier ; la raison est fixe et ne cite rien du corps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SchemaError(pub &'static str);

/// Enveloppe Vigie. Lue à la réception ; écrite par `vigie-inventory`
/// (`build.rs`) avec les mêmes noms de champs, puis relue par [`parse`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub site: String,
    /// `agent` ou `ci` (#20) ; absent = `agent` (agents 0.5.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    pub seq: i64,
    pub sent_at: i64,
    pub agent: String,
    pub complete: bool,
    pub skipped: i64,
    pub bom: Bom,
}

/// BOM CycloneDX de la liste blanche.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Bom {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub metadata: Metadata,
    pub components: Vec<RawComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub timestamp: String,
    pub component: MetaComponent,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetaComponent {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
}

/// Composant tel qu'écrit dans le document, avant validation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawComponent {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub version: String,
    pub purl: String,
    pub scope: String,
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Property {
    pub name: String,
    pub value: String,
}

/// Raison fixe d'une erreur de désérialisation : le texte de serde recopie
/// des octets reçus, il n'est jamais formaté.
fn json_reason(err: &serde_json::Error) -> SchemaError {
    use serde_json::error::Category;
    match err.classify() {
        Category::Io | Category::Syntax | Category::Eof => SchemaError("JSON illisible"),
        Category::Data => {
            // Seul le début du message est lu, pour choisir une raison fixe.
            let text = err.to_string();
            if text.starts_with("unknown field") {
                SchemaError("champ hors liste blanche")
            } else if text.starts_with("missing field") {
                SchemaError("champ obligatoire absent")
            } else {
                SchemaError("type ou valeur de champ invalide")
            }
        }
    }
}

/// Analyse et valide un inventaire reçu pour `site`, de CMS `kind` (lu dans la
/// configuration du veilleur). L'horloge est vérifiée par l'appelant.
pub fn parse(body: &[u8], site: &str, kind: SiteKind) -> Result<Inventory, SchemaError> {
    let envelope: Envelope = serde_json::from_slice(body).map_err(|e| json_reason(&e))?;
    let schema = |why| Err(SchemaError(why));
    if envelope.v != 1 {
        return schema("v doit valoir 1");
    }
    if envelope.kind != "inventory" {
        return schema("type doit valoir inventory");
    }
    if envelope.site != site {
        return schema("site différent de X-Vigie-Site");
    }
    if envelope.seq < 1 {
        return schema("seq doit être positif");
    }
    if !printable(&envelope.agent, 64) {
        return schema("agent : 1 à 64 caractères imprimables");
    }
    if !(0..=MAX_SKIPPED).contains(&envelope.skipped) {
        return schema("skipped : 0 à 100 000");
    }
    let bom = envelope.bom;
    if bom.bom_format != "CycloneDX" {
        return schema("bomFormat doit valoir CycloneDX");
    }
    if !SPEC_VERSIONS.contains(&bom.spec_version.as_str()) {
        return schema("specVersion : 1.6 ou 1.7");
    }
    if !is_urn_uuid(&bom.serial_number) {
        return schema("serialNumber : urn:uuid: et UUID en minuscules");
    }
    let Some(generated_at) = utc_timestamp(&bom.metadata.timestamp) else {
        return schema("metadata.timestamp : RFC 3339 en UTC");
    };
    if generated_at.abs_diff(envelope.sent_at) > TIMESTAMP_WINDOW.unsigned_abs() {
        return schema("metadata.timestamp à plus de 30 jours de sent_at");
    }
    if bom.metadata.component.kind != "application" || bom.metadata.component.name != site {
        return schema("metadata.component : application au nom du site");
    }
    if bom.components.len() > MAX_COMPONENTS {
        return schema("plus de 2 000 composants");
    }

    let admitted = capability::inventory_ecosystems(kind);
    let mut dropped: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut kept: Vec<(String, Component)> = Vec::with_capacity(bom.components.len());
    for raw in bom.components {
        let properties = properties(&raw.properties)?;
        match component(&raw, &properties, admitted) {
            Ok(component) => {
                let purl = component.purl.canonical();
                if seen.insert((purl.clone(), component.path.clone())) {
                    kept.push((purl, component));
                } else {
                    *dropped.entry("doublon (purl, vigie:path)").or_insert(0) += 1;
                }
            }
            Err(why) => *dropped.entry(why).or_insert(0) += 1,
        }
    }
    kept.sort_by(|a, b| (&a.0, &a.1.path).cmp(&(&b.0, &b.1.path)));
    let components: Vec<Component> = kept.into_iter().map(|(_, c)| c).collect();
    let digest = digest(&components);
    Ok(Inventory {
        site: envelope.site,
        source: envelope.source.unwrap_or(Source::Agent),
        seq: envelope.seq,
        sent_at: envelope.sent_at,
        agent: envelope.agent,
        complete: envelope.complete,
        skipped: envelope.skipped,
        spec_version: bom.spec_version,
        serial: bom.serial_number,
        generated_at,
        components,
        dropped,
        digest,
    })
}

/// Propriétés d'un composant, par nom. Un nom hors liste ou en double refuse
/// le document entier.
fn properties(raw: &[Property]) -> Result<BTreeMap<&'static str, &str>, SchemaError> {
    let mut out = BTreeMap::new();
    for property in raw {
        let name = match property.name.as_str() {
            PROPERTY_PATH => PROPERTY_PATH,
            PROPERTY_SCOPE => PROPERTY_SCOPE,
            PROPERTY_PARENT => PROPERTY_PARENT,
            PROPERTY_CONFIG_VERSION => PROPERTY_CONFIG_VERSION,
            _ => return Err(SchemaError("propriété hors liste blanche")),
        };
        if out.insert(name, property.value.as_str()).is_some() {
            return Err(SchemaError("propriété en double"));
        }
    }
    Ok(out)
}

/// Valide un composant ; `Err` : la raison fixe de son écart.
fn component(
    raw: &RawComponent,
    properties: &BTreeMap<&'static str, &str>,
    admitted: &[PurlType],
) -> Result<Component, &'static str> {
    let ty = ComponentType::from_name(&raw.kind).ok_or("type hors liste")?;
    if !printable(&raw.name, MAX_NAME_CHARS) {
        return Err("name : 1 à 214 caractères imprimables");
    }
    let purl = Purl::parse(&raw.purl).map_err(|_| "purl hors grammaire")?;
    if purl.canonical() != raw.purl {
        return Err("purl non canonique");
    }
    if !admitted.contains(&purl.ty()) {
        return Err("écosystème non admis pour le site");
    }
    let version_ok = match purl.version() {
        None => raw.version.is_empty(),
        Some(v) => v == raw.version,
    };
    if !version_ok {
        return Err("version différente de celle du purl");
    }
    let path = properties
        .get(PROPERTY_PATH)
        .copied()
        .ok_or("vigie:path absent")?;
    if !valid_path(path) {
        return Err("vigie:path invalide");
    }
    let scope = properties
        .get(PROPERTY_SCOPE)
        .copied()
        .and_then(Scope::from_name)
        .ok_or("vigie:scope absent ou hors liste")?;
    let excluded = match raw.scope.as_str() {
        "required" => false,
        "excluded" => true,
        _ => return Err("scope : required ou excluded"),
    };
    if excluded != (scope == Scope::Dev) {
        return Err("scope excluded si et seulement si vigie:scope dev");
    }
    let category = (purl.ty(), purl.namespace().unwrap_or(""));
    let core = matches!(
        category,
        (PurlType::Wordpress, "core") | (PurlType::Prestashop, "core")
    );
    if (ty == ComponentType::Application) != core {
        return Err("type application si et seulement si noyau");
    }
    if scope == Scope::Mu && category != (PurlType::Wordpress, "plugin") {
        return Err("vigie:scope mu hors extension WordPress");
    }
    let parent = match properties.get(PROPERTY_PARENT) {
        None => None,
        Some(_) if category != (PurlType::Wordpress, "theme") => {
            return Err("vigie:parent hors thème WordPress");
        }
        Some(slug) => {
            Purl::new(PurlType::Wordpress, Some("theme"), slug, None)
                .map_err(|_| "vigie:parent hors grammaire")?;
            Some((*slug).to_owned())
        }
    };
    let config_version = match properties.get(PROPERTY_CONFIG_VERSION) {
        None => None,
        Some(_) if category != (PurlType::Prestashop, "module") => {
            return Err("vigie:config-version hors module PrestaShop");
        }
        Some(v) if !version_in_grammar(v) => return Err("vigie:config-version hors grammaire"),
        Some(v) => Some((*v).to_owned()),
    };
    Ok(Component {
        purl,
        name: raw.name.clone(),
        ty,
        scope,
        path: path.to_owned(),
        parent,
        config_version,
    })
}

/// `vigie:path` : relatif, 200 caractères au plus, segments non vides de
/// `[A-Za-z0-9._@+-]`, ni `.` ni `..`.
pub fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_CHARS
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'+' | b'-')
                })
        })
}

/// `urn:uuid:` suivi d'un UUID en minuscules (8-4-4-4-12).
fn is_urn_uuid(value: &str) -> bool {
    let Some(uuid) = value.strip_prefix("urn:uuid:") else {
        return false;
    };
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// RFC 3339 en UTC (`Z`), en secondes Unix.
fn utc_timestamp(value: &str) -> Option<i64> {
    if !value.ends_with('Z') || value.len() > 40 {
        return None;
    }
    value.parse::<jiff::Timestamp>().ok().map(|t| t.as_second())
}

/// Forme sérialisée d'un composant dans la liste canonique : écrite par le
/// veilleur depuis ses propres structures, jamais depuis les octets reçus.
#[derive(Serialize)]
struct CanonicalComponent<'a> {
    purl: String,
    path: &'a str,
    #[serde(rename = "type")]
    ty: &'static str,
    name: &'a str,
    scope: &'static str,
    parent: Option<&'a str>,
    config_version: Option<&'a str>,
}

/// SHA-256 de la liste canonique : composants triés par `(purl, path)` en
/// JSON compact. Ni `serialNumber`, ni `timestamp`, ni `seq` n'y entrent :
/// deux relevés identiques ont le même digest.
pub fn digest(components: &[Component]) -> [u8; 32] {
    let mut list: Vec<CanonicalComponent<'_>> = components
        .iter()
        .map(|c| CanonicalComponent {
            purl: c.purl.canonical(),
            path: &c.path,
            ty: c.ty.as_str(),
            name: &c.name,
            scope: c.scope.as_str(),
            parent: c.parent.as_deref(),
            config_version: c.config_version.as_deref(),
        })
        .collect();
    list.sort_by(|a, b| (&a.purl, a.path).cmp(&(&b.purl, b.path)));
    let json = serde_json::to_vec(&list).unwrap_or_default();
    Sha256::digest(&json).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_relative_and_bounded() {
        for ok in [
            "wp-content/plugins/exemple-formulaire",
            "composer.lock",
            "app/node_modules/@exemple/paquet",
            "a+b/c_d",
        ] {
            assert!(valid_path(ok), "{ok}");
        }
        for bad in [
            "",
            "/etc/passwd",
            "a//b",
            "a/../b",
            "./a",
            "a/",
            "a b",
            "a\\b",
            &"a".repeat(201),
        ] {
            assert!(!valid_path(bad), "{bad}");
        }
    }

    #[test]
    fn serial_numbers_are_lowercase_uuids() {
        assert!(is_urn_uuid("urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"));
        assert!(!is_urn_uuid(
            "urn:uuid:3E671687-395B-41F5-A30F-A58921A69B79"
        ));
        assert!(!is_urn_uuid("3e671687-395b-41f5-a30f-a58921a69b79"));
        assert!(!is_urn_uuid("urn:uuid:3e671687395b41f5a30fa58921a69b79"));
    }

    #[test]
    fn timestamps_must_be_utc() {
        assert_eq!(utc_timestamp("2026-10-17T12:00:00Z"), Some(1_792_238_400));
        assert_eq!(utc_timestamp("2026-10-17T14:00:00+02:00"), None);
        assert_eq!(utc_timestamp("17/10/2026"), None);
    }
}
