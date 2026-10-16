//! Identifiant de requête : 16 octets aléatoires en hex, posés sur chaque
//! réponse en `X-Request-Id` et cités par le journal. Un `X-Request-Id`
//! envoyé par le client est ignoré : il pourrait forger des lignes de journal.
//!
//! La couche [`layer`] rend aussi le corps des [`ApiError`], qu'un extracteur
//! ou un handler a pu produire sans connaître l'identifiant.
//!
//! [`current`] lit l'identifiant de la requête en cours depuis la tâche
//! tokio qui la sert. Une fermeture passée à `spawn_blocking` ne le voit pas :
//! elle le reçoit capturé.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::CONTENT_LENGTH;
use axum::middleware::Next;
use axum::response::Response;

use crate::error::ApiError;

pub const HEADER: &str = "x-request-id";

tokio::task_local! {
    static CURRENT: String;
}

/// 32 caractères hex minuscules. Sans aléa disponible, un identifiant nul
/// plutôt qu'une requête refusée : il ne protège rien.
pub fn generate() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        return "0".repeat(32);
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Identifiant de la requête servie par la tâche courante, `-` hors requête.
pub fn current() -> String {
    CURRENT
        .try_with(Clone::clone)
        .unwrap_or_else(|_| "-".to_owned())
}

pub async fn layer(request: Request, next: Next) -> Response {
    let id = generate();
    let mut response = CURRENT.scope(id.clone(), next.run(request)).await;
    if let Some(error) = response.extensions_mut().remove::<ApiError>() {
        // Le corps rendu remplace le vide ; les en-têtes posés avant lui
        // (`Retry-After` d'un 429) et les extensions restent.
        let (mut parts, _) = response.into_parts();
        let (rendered, body) = error.render(&id).into_parts();
        parts.status = rendered.status;
        parts.headers.remove(CONTENT_LENGTH);
        for (name, value) in &rendered.headers {
            parts.headers.insert(name, value.clone());
        }
        response = Response::from_parts(parts, body);
    }
    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(HEADER, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_32_hex_chars_and_differ() {
        let a = generate();
        let b = generate();
        assert_eq!(a.len(), 32);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn current_is_a_dash_outside_a_request() {
        assert_eq!(current(), "-");
        let seen = CURRENT.scope("abc".into(), async { current() }).await;
        assert_eq!(seen, "abc");
    }
}
