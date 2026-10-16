//! Glob de chemin des règles déclaratives : seule « expression » admise par
//! la configuration, sans regex.
//!
//! - `*` : n'importe quelle suite d'octets sans `/` ;
//! - `**` : n'importe quelle suite d'octets, `/` compris ;
//! - `/**/` : un `/`, ou `/…/` (« zéro ou plusieurs dossiers ») ;
//! - `?` : un octet, sauf `/` ;
//! - le reste est littéral et sensible à la casse, comme un chemin Apache.
//!
//! Le chemin n'est ni décodé ni normalisé (`Entry::path`) : la comparaison se
//! fait octet par octet. Un glouton à deux pointeurs est faux avec deux
//! sortes d'étoiles ; la correspondance est donc une programmation dynamique
//! sur deux lignes, O(motif × chemin) bornée par 256 × 2048, précédée d'un
//! préfiltre sur les littéraux fixes de tête et de queue qui écarte presque
//! tous les chemins sans calcul.

use std::fmt;

use crate::logs::MAX_PATH;

/// Longueur maximale d'un motif, en caractères.
pub const MAX_PATTERN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GlobError {
    #[error("motif vide")]
    Empty,
    #[error("motif « {0} » : il doit commencer par /")]
    NotAbsolute(String),
    #[error("motif de {0} caractères : {MAX_PATTERN} au plus")]
    TooLong(usize),
    #[error("motif « {0} » : espace ou caractère de contrôle")]
    Control(String),
    #[error("motif « {0} » : trois étoiles ou plus à la suite")]
    Stars(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Byte(u8),
    /// `?`
    One,
    /// `*`
    Star,
    /// `**`
    Any,
    /// `/**/` : `/` puis, facultativement, `…/`.
    Dirs,
}

/// Motif compilé une fois, à la lecture de la configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct Glob {
    source: String,
    tokens: Vec<Token>,
    /// Littéraux fixes de tête et de queue (préfiltre).
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    /// Le motif n'a aucun joker : égalité stricte.
    literal: bool,
}

impl fmt::Debug for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Glob({:?})", self.source)
    }
}

impl fmt::Display for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl Glob {
    pub fn new(pattern: &str) -> Result<Self, GlobError> {
        if pattern.is_empty() {
            return Err(GlobError::Empty);
        }
        let chars = pattern.chars().count();
        if chars > MAX_PATTERN {
            return Err(GlobError::TooLong(chars));
        }
        if !pattern.starts_with('/') {
            return Err(GlobError::NotAbsolute(pattern.to_string()));
        }
        if pattern.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(GlobError::Control(pattern.to_string()));
        }
        if pattern.contains("***") {
            return Err(GlobError::Stars(pattern.to_string()));
        }
        let bytes = pattern.as_bytes();
        let mut tokens = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i..].starts_with(b"/**/") {
                tokens.push(Token::Dirs);
                i += 4;
            } else if bytes[i..].starts_with(b"**") {
                tokens.push(Token::Any);
                i += 2;
            } else {
                tokens.push(match bytes[i] {
                    b'*' => Token::Star,
                    b'?' => Token::One,
                    b => Token::Byte(b),
                });
                i += 1;
            }
        }
        let fixed = |t: &Token| match t {
            Token::Byte(b) => Some(*b),
            _ => None,
        };
        let prefix: Vec<u8> = tokens.iter().map_while(fixed).collect();
        let literal = prefix.len() == tokens.len();
        let mut suffix: Vec<u8> = if literal {
            Vec::new()
        } else {
            tokens.iter().rev().map_while(fixed).collect()
        };
        suffix.reverse();
        Ok(Self {
            source: pattern.to_string(),
            tokens,
            prefix,
            suffix,
            literal,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Le chemin entier correspond au motif. Au-delà de 2048 octets
    /// (`logs::MAX_PATH`), seul le début est lu : le coût reste borné.
    pub fn matches(&self, path: &str) -> bool {
        let path = &path.as_bytes()[..path.len().min(MAX_PATH)];
        if self.literal {
            return path == self.prefix.as_slice();
        }
        if path.len() < self.prefix.len() + self.suffix.len()
            || !path.starts_with(&self.prefix)
            || !path.ends_with(&self.suffix)
        {
            return false;
        }
        let tokens = &self.tokens[self.prefix.len()..self.tokens.len() - self.suffix.len()];
        let text = &path[self.prefix.len()..path.len() - self.suffix.len()];
        dp(tokens, text)
    }
}

/// `prev[j]` : les jetons déjà lus couvrent exactement `text[..j]`.
fn dp(tokens: &[Token], text: &[u8]) -> bool {
    let n = text.len();
    let mut prev = vec![false; n + 1];
    let mut next = vec![false; n + 1];
    prev[0] = true;
    for token in tokens {
        match *token {
            Token::Byte(b) => {
                next[0] = false;
                for j in 1..=n {
                    next[j] = prev[j - 1] && text[j - 1] == b;
                }
            }
            Token::One => {
                next[0] = false;
                for j in 1..=n {
                    next[j] = prev[j - 1] && text[j - 1] != b'/';
                }
            }
            Token::Star => {
                // Atteint depuis un `prev[i]` vrai sans `/` dans text[i..j].
                let mut reach = false;
                for j in 0..=n {
                    if j > 0 && text[j - 1] == b'/' {
                        reach = false;
                    }
                    reach |= prev[j];
                    next[j] = reach;
                }
            }
            Token::Any => {
                let mut reach = false;
                for j in 0..=n {
                    reach |= prev[j];
                    next[j] = reach;
                }
            }
            Token::Dirs => {
                // text[i..j] commence et finit par `/` (un seul `/` suffit) :
                // `reach` dit qu'un `prev[i]` vrai précède un `/` en text[i].
                let mut reach = false;
                next[0] = false;
                for j in 1..=n {
                    if prev[j - 1] && text[j - 1] == b'/' {
                        reach = true;
                    }
                    next[j] = reach && text[j - 1] == b'/';
                }
            }
        }
        if !next.iter().any(|&r| r) {
            return false;
        }
        std::mem::swap(&mut prev, &mut next);
    }
    prev[n]
}
