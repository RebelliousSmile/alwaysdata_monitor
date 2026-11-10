//! Lecteur ligne à ligne borné, commun à `pnpm-lock.yaml` et au `yarn.lock`
//! berry (ses fonctions de citation servent aussi au `yarn.lock` v1). Ce n'est
//! pas un lecteur YAML : il ne lit que des clés et des scalaires, et saute le
//! reste sans l'analyser.
//!
//! 1. Indentation par espaces seulement : une tabulation d'indentation est
//!    refusée.
//! 2. Un bloc de clé non lue est sauté par indentation ([`block_end`]),
//!    quel que soit son contenu.
//! 3. Une collection en ligne (`{…}`, `[…]`), valeur d'une clé non lue, est
//!    sautée par un parcours équilibré qui tient compte des chaînes citées
//!    ([`skip_flow`]) ; non fermée sur sa ligne : refus.
//! 4. Scalaires cités décodés comme YAML : `''` → `'` entre apostrophes ;
//!    entre guillemets `\\`, `\"`, `\/`, `\n`, `\t`, `\uXXXX`, tout autre
//!    échappement refusé.
//! 5. `&`, `*`, `!`, `|`, `>` refusés seulement comme premier caractère d'une
//!    clé ou d'un scalaire non cité qui est lu : une ancre, un alias ou un
//!    bloc changerait son sens. Ailleurs, ce sont des caractères.
//! 6. `---` admis une fois, avant tout contenu ; un second document est
//!    refusé. Les commentaires `#` en début de ligne sont ignorés.

use super::LockError;

/// Ligne significative : ni vide, ni commentaire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Line<'a> {
    /// Numéro dans le fichier, 1 pour la première.
    pub no: usize,
    /// Espaces d'indentation.
    pub indent: usize,
    /// Texte sans l'indentation ni les espaces de fin.
    pub text: &'a str,
}

impl Line<'_> {
    pub fn error(&self) -> LockError {
        LockError::Structure { line: self.no }
    }
}

/// Découpe le texte en lignes significatives (règles 1 et 6).
pub fn split(text: &str) -> Result<Vec<Line<'_>>, LockError> {
    let mut out = Vec::new();
    let mut document_marker = false;
    for (i, raw) in text.split('\n').enumerate() {
        let no = i + 1;
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let body = raw.trim_start_matches(' ');
        let indent = raw.len() - body.len();
        if body.starts_with('\t') {
            if body.trim().is_empty() {
                continue;
            }
            return Err(LockError::Structure { line: no });
        }
        let body = body.trim_end();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        if indent == 0 && (body == "---" || body.starts_with("--- ")) {
            if document_marker || !out.is_empty() {
                return Err(LockError::Structure { line: no });
            }
            document_marker = true;
            continue;
        }
        if indent == 0 && body == "..." {
            return Err(LockError::Structure { line: no });
        }
        out.push(Line {
            no,
            indent,
            text: body,
        });
    }
    Ok(out)
}

/// Fin du bloc de la ligne `i` : première ligne suivante dont l'indentation
/// ne dépasse pas la sienne (règle 2).
pub fn block_end(lines: &[Line<'_>], i: usize) -> usize {
    let indent = lines[i].indent;
    lines[i + 1..]
        .iter()
        .position(|line| line.indent <= indent)
        .map_or(lines.len(), |p| i + 1 + p)
}

/// Indicateurs refusés en tête d'une clé ou d'un scalaire lus (règle 5).
fn indicator(text: &str) -> bool {
    text.starts_with(['&', '*', '!', '|', '>'])
}

/// Sépare `clé: valeur` ; la valeur est vide quand un bloc suit. `read` : la
/// clé est lue (structure ou entrée), les indicateurs y sont refusés.
pub fn key_value<'a>(line: &Line<'a>, read: bool) -> Result<(String, &'a str), LockError> {
    let text = line.text;
    let (key, rest) = if text.starts_with(['\'', '"']) {
        let (key, rest) = quoted(text).ok_or_else(|| line.error())?;
        (key, rest)
    } else {
        // Le premier `:` suivi d'une espace ou de la fin : un `:` dans une URL
        // (`git+https://…`, `127.0.0.1:8765`) n'en est pas un.
        let bytes = text.as_bytes();
        let colon = (0..bytes.len())
            .find(|&i| bytes[i] == b':' && bytes.get(i + 1).is_none_or(|b| *b == b' '))
            .ok_or_else(|| line.error())?;
        let key = text[..colon].trim_end();
        if key.is_empty() || (read && indicator(key)) {
            return Err(line.error());
        }
        (key.to_owned(), &text[colon..])
    };
    let rest = rest.strip_prefix(':').ok_or_else(|| line.error())?;
    if !(rest.is_empty() || rest.starts_with(' ')) {
        return Err(line.error());
    }
    Ok((key, rest.trim()))
}

/// Valeur d'une clé non lue : une collection en ligne doit être fermée sur sa
/// ligne (règle 3) ; le reste n'est pas analysé.
pub fn skip_flow(line: &Line<'_>, value: &str) -> Result<(), LockError> {
    if value.starts_with(['{', '[']) {
        flow_end(value).ok_or_else(|| line.error())?;
    }
    Ok(())
}

/// Position qui suit la fermeture de la collection en ligne qui ouvre
/// `value`, en sautant les chaînes citées ; `None` si elle n'est pas fermée.
fn flow_end(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut depth = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            b'\'' | b'"' => {
                let (_, rest) = quoted(&value[i..])?;
                i = value.len() - rest.len();
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Scalaire lu : cité (décodé) ou non cité (sans indicateur en tête, sans
/// collection), commentaire de fin retiré.
pub fn scalar(line: &Line<'_>, value: &str) -> Result<String, LockError> {
    if value.starts_with(['\'', '"']) {
        let (text, rest) = quoted(value).ok_or_else(|| line.error())?;
        let rest = rest.trim_start();
        if !(rest.is_empty() || rest.starts_with('#')) {
            return Err(line.error());
        }
        return Ok(text);
    }
    let plain = value.split(" #").next().unwrap_or("").trim_end();
    if plain.is_empty() || indicator(plain) || plain.starts_with(['{', '[']) {
        return Err(line.error());
    }
    Ok(plain.to_owned())
}

/// Collection en ligne `{clé: valeur, …}` d'une valeur lue (résolution
/// pnpm) : clés et valeurs scalaires seulement.
pub fn flow_map(line: &Line<'_>, value: &str) -> Result<Vec<(String, String)>, LockError> {
    let end = flow_end(value).ok_or_else(|| line.error())?;
    let after = value[end..].trim_start();
    if !value.starts_with('{') || !(after.is_empty() || after.starts_with('#')) {
        return Err(line.error());
    }
    let inner = value[1..end - 1].trim();
    let mut out = Vec::new();
    if inner.is_empty() {
        return Ok(out);
    }
    // Découpe aux virgules de premier niveau, hors chaînes citées.
    let mut items = Vec::new();
    let (mut start, mut i) = (0, 0);
    let bytes = inner.as_bytes();
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' => {
                let (_, rest) = quoted(&inner[i..]).ok_or_else(|| line.error())?;
                i = inner.len() - rest.len();
                continue;
            }
            b'{' | b'[' => return Err(line.error()),
            b',' => {
                items.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    items.push(&inner[start..]);
    for item in items {
        let item = Line {
            text: item.trim(),
            ..*line
        };
        let (key, value) = key_value(&item, true)?;
        out.push((key, scalar(&item, value)?));
    }
    Ok(out)
}

/// Décode le scalaire cité qui ouvre `text` (règle 4) : `(texte, reste)`, ou
/// `None` s'il n'est pas fermé ou porte un échappement inconnu.
pub fn quoted(text: &str) -> Option<(String, &str)> {
    let mut chars = text.char_indices();
    let (_, quote) = chars.next()?;
    let mut out = String::new();
    match quote {
        '\'' => {
            while let Some((i, c)) = chars.next() {
                if c == '\'' {
                    if text[i + 1..].starts_with('\'') {
                        chars.next();
                        out.push('\'');
                    } else {
                        return Some((out, &text[i + 1..]));
                    }
                } else {
                    out.push(c);
                }
            }
            None
        }
        '"' => {
            while let Some((i, c)) = chars.next() {
                match c {
                    '"' => return Some((out, &text[i + 1..])),
                    '\\' => {
                        let (_, escape) = chars.next()?;
                        match escape {
                            '\\' => out.push('\\'),
                            '"' => out.push('"'),
                            '/' => out.push('/'),
                            'n' => out.push('\n'),
                            't' => out.push('\t'),
                            'u' => {
                                let hex = |chars: &mut std::str::CharIndices<'_>| {
                                    let mut code = 0u32;
                                    for _ in 0..4 {
                                        code = code * 16 + chars.next()?.1.to_digit(16)?;
                                    }
                                    Some(code)
                                };
                                let high = hex(&mut chars)?;
                                let code = if (0xD800..0xDC00).contains(&high) {
                                    // Paire de substitution : `\uD83D\uDE00`.
                                    if chars.next()?.1 != '\\' || chars.next()?.1 != 'u' {
                                        return None;
                                    }
                                    let low = hex(&mut chars)?;
                                    if !(0xDC00..0xE000).contains(&low) {
                                        return None;
                                    }
                                    0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                                } else {
                                    high
                                };
                                out.push(char::from_u32(code)?);
                            }
                            _ => return None,
                        }
                    }
                    c => out.push(c),
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str) -> Line<'_> {
        Line {
            no: 7,
            indent: 0,
            text,
        }
    }

    #[test]
    fn tabs_in_indentation_and_second_documents_are_refused() {
        assert_eq!(split("a:\n\tb: 1\n"), Err(LockError::Structure { line: 2 }));
        assert!(split("---\na: 1\n# commentaire\n\nb: 2\n").is_ok());
        assert_eq!(
            split("a: 1\n---\nb: 2\n"),
            Err(LockError::Structure { line: 2 })
        );
        // Une tabulation hors de l'indentation est du texte.
        assert_eq!(split("a: x\ty\n").expect("lu")[0].text, "a: x\ty");
    }

    #[test]
    fn unread_blocks_are_skipped_by_indentation() {
        let lines =
            split("a:\n  &ancre: *alias\n  b: !tag [1, {2\n    c: |\n      >\nd: 1\n").expect("lu");
        assert_eq!(block_end(&lines, 0), 5);
        assert_eq!(lines[5].text, "d: 1");
    }

    #[test]
    fn inline_collections_are_balanced_across_quoted_strings() {
        let l = line("engines: {node: '>=8 }', npm: \"a]\"}");
        let (_, value) = key_value(&l, true).expect("clé");
        assert!(skip_flow(&l, value).is_ok());
        assert!(skip_flow(&l, "{node: '>=8'").is_err());
        assert!(skip_flow(&l, "[darwin, linux").is_err());
        assert!(skip_flow(&l, "os=darwin & cpu=arm64").is_ok());
    }

    #[test]
    fn quoted_scalars_are_decoded() {
        assert_eq!(scalar(&line(""), "'it''s'"), Ok("it's".to_owned()));
        assert_eq!(scalar(&line(""), r#""a\"b""#), Ok("a\"b".to_owned()));
        assert_eq!(scalar(&line(""), r#""\u00e9""#), Ok("é".to_owned()));
        assert_eq!(scalar(&line(""), r#""\ud83d\ude00""#), Ok("😀".to_owned()));
        assert_eq!(scalar(&line(""), r#""a\/b\\c""#), Ok("a/b\\c".to_owned()));
        assert_eq!(scalar(&line(""), r#""é""#), Ok("é".to_owned()));
        for bad in [
            r#""a\x41""#,
            r#""\ud83d""#,
            "'ouvert",
            r#""ouvert"#,
            "'a' b",
        ] {
            assert!(scalar(&line(""), bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn indicators_are_refused_only_on_what_is_read() {
        for bad in ["&ancre 1", "*alias", "!tag 1", "|", ">-"] {
            assert!(scalar(&line(""), bad).is_err(), "{bad}");
        }
        assert!(key_value(&line("&clé: 1"), true).is_err());
        assert!(key_value(&line("&clé: 1"), false).is_ok());
        // Au milieu d'un scalaire, ce sont des caractères.
        assert_eq!(
            scalar(&line(""), "os=darwin & cpu=arm64"),
            Ok("os=darwin & cpu=arm64".to_owned())
        );
        assert_eq!(
            scalar(&line(""), "1.2.3 # commentaire"),
            Ok("1.2.3".to_owned())
        );
    }

    #[test]
    fn keys_split_on_the_first_colon_followed_by_a_space() {
        let l = line("lib@git+https://git.example.org:8443/lib.git#abc: {}");
        assert_eq!(
            key_value(&l, true),
            Ok((
                "lib@git+https://git.example.org:8443/lib.git#abc".to_owned(),
                "{}"
            ))
        );
        assert_eq!(
            key_value(&line("'@types/ms@0.7.34':"), true),
            Ok(("@types/ms@0.7.34".to_owned(), ""))
        );
        assert!(key_value(&line("sans deux-points"), true).is_err());
    }

    #[test]
    fn flow_maps_of_read_values_hold_scalars() {
        let l = line("");
        assert_eq!(
            flow_map(
                &l,
                "{commit: abc, repo: 'https://git.example.org/a.git', type: git}"
            ),
            Ok(vec![
                ("commit".to_owned(), "abc".to_owned()),
                (
                    "repo".to_owned(),
                    "https://git.example.org/a.git".to_owned()
                ),
                ("type".to_owned(), "git".to_owned()),
            ])
        );
        assert!(flow_map(&l, "{a: {b: 1}}").is_err());
        assert!(flow_map(&l, "{a: 1").is_err());
        assert!(flow_map(&l, "{a: *x}").is_err());
    }
}
