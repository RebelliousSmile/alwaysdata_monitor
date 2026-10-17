//! Texte issu des logs, servi par `/api/v1` (`docs/api-console.md`).
//!
//! Le JSON échappe déjà les guillemets et les contrôles ; il reste ce que la
//! console ou un terminal ferait du texte une fois décodé : séquences
//! d'échappement, sauts de ligne qui forgent des lignes de journal, texte
//! bidirectionnel trompeur. [`LogText`] ne se construit qu'en assainissant :
//! un champ de DTO de ce type ne peut pas porter le texte brut.

use serde::Serialize;

/// Longueur maximale d'un user-agent servi, en caractères.
pub const MAX_USER_AGENT_CHARS: usize = 512;
/// Longueur maximale d'un chemin servi, en caractères.
pub const MAX_PATH_CHARS: usize = 512;
/// Longueur maximale d'un détail d'incident ou de passage servi, en
/// caractères. Borne défensive : #8 écrit des détails bien plus courts.
pub const MAX_DETAIL_CHARS: usize = 2048;
/// Longueur maximale du résumé d'une faille connue, en caractères (mesure
/// des exports OSV du 2026-10-17 : 241 au plus).
pub const MAX_SUMMARY_CHARS: usize = 500;
/// Longueur maximale de l'attribution d'une faille connue (mention
/// `copyrights` de Wordfence, licence de la source), en caractères.
pub const MAX_ATTRIBUTION_CHARS: usize = 2000;

/// Texte d'origine log, assaini.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct LogText(String);

/// Caractère remplacé par U+FFFD : contrôles C0, DEL et C1, séparateurs de
/// ligne et de paragraphe Unicode, contrôles bidirectionnels.
fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}'
                | '\u{2029}'
                | '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

impl LogText {
    /// Seul constructeur : chaque caractère dangereux devient U+FFFD, puis
    /// le texte est coupé à `max_chars` caractères.
    pub fn new(raw: &str, max_chars: usize) -> Self {
        Self(
            raw.chars()
                .take(max_chars)
                .map(|c| if is_unsafe(c) { '\u{fffd}' } else { c })
                .collect(),
        )
    }

    /// User-agent, 512 caractères au plus.
    pub fn user_agent(raw: &str) -> Self {
        Self::new(raw, MAX_USER_AGENT_CHARS)
    }

    /// Chemin sans query string ni fragment, 512 caractères au plus : un
    /// jeton passé dans l'URL ne ressort pas.
    pub fn path(raw: &str) -> Self {
        let end = raw.find(['?', '#']).unwrap_or(raw.len());
        Self::new(&raw[..end], MAX_PATH_CHARS)
    }

    /// Referer réduit à son origine (`https://exemple.org:8443`) ; `None` si
    /// ce n'est pas une URL http ou https lisible.
    pub fn referer(raw: &str) -> Option<Self> {
        let url = url::Url::parse(raw).ok()?;
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }
        let origin = url.origin();
        origin
            .is_tuple()
            .then(|| Self::new(&origin.ascii_serialization(), MAX_PATH_CHARS))
    }

    /// Détail d'un incident ou d'un passage du contrôle `logs`.
    pub fn detail(raw: &str) -> Self {
        Self::new(raw, MAX_DETAIL_CHARS)
    }

    /// Résumé d'une faille connue (`summary` OSV, ou première ligne de
    /// `details`).
    pub fn summary(raw: &str) -> Self {
        Self::new(raw, MAX_SUMMARY_CHARS)
    }

    /// Attribution d'une faille connue, reproduite partout où elle est
    /// affichée.
    pub fn attribution(raw: &str) -> Self {
        Self::new(raw, MAX_ATTRIBUTION_CHARS)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<LogText> for String {
    fn from(text: LogText) -> Self {
        text.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_and_bidi_become_the_replacement_character() {
        let raw = "a\u{1b}[31mb\nc\u{7f}d\u{85}e\u{2028}f\u{202e}g\u{2066}h\u{200f}i";
        assert_eq!(
            LogText::detail(raw).as_str(),
            "a\u{fffd}[31mb\u{fffd}c\u{fffd}d\u{fffd}e\u{fffd}f\u{fffd}g\u{fffd}h\u{fffd}i"
        );
        // Le texte ordinaire, accents compris, passe tel quel.
        assert_eq!(LogText::detail("élevé : 42").as_str(), "élevé : 42");
    }

    #[test]
    fn user_agents_and_paths_are_cut_in_characters() {
        let ua = "é".repeat(MAX_USER_AGENT_CHARS + 10);
        assert_eq!(
            LogText::user_agent(&ua).as_str().chars().count(),
            MAX_USER_AGENT_CHARS
        );
        let path = format!("/{}", "é".repeat(MAX_PATH_CHARS + 10));
        assert_eq!(
            LogText::path(&path).as_str().chars().count(),
            MAX_PATH_CHARS
        );
    }

    #[test]
    fn a_path_loses_its_query_and_fragment() {
        assert_eq!(
            LogText::path("/wp-login.php?token=secret").as_str(),
            "/wp-login.php"
        );
        assert_eq!(LogText::path("/a#b?c").as_str(), "/a");
        assert_eq!(LogText::path("/a\u{1b}b").as_str(), "/a\u{fffd}b");
    }

    #[test]
    fn a_referer_is_reduced_to_its_origin() {
        assert_eq!(
            LogText::referer("https://exemple.org/page?token=secret")
                .expect("origine")
                .as_str(),
            "https://exemple.org"
        );
        assert_eq!(
            LogText::referer("http://exemple.org:8080/x")
                .expect("origine")
                .as_str(),
            "http://exemple.org:8080"
        );
        assert_eq!(LogText::referer("android-app://com.exemple/"), None);
        assert_eq!(LogText::referer("pas une url"), None);
    }
}
