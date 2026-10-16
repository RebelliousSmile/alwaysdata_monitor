//! Erreurs de `/api/v1` : une seule forme, `{"error":{"code","message",
//! "request_id"}}`, jamais mise en cache (`docs/api-console.md`).
//!
//! Un handler ou un extracteur rend un [`ApiError`] ; la réponse produite ne
//! porte encore aucun corps, seulement l'erreur en extension. La couche de
//! [`crate::request_id`] l'écrit avec l'identifiant de la requête : ainsi un
//! extracteur, qui ne voit pas cet identifiant, rend la même forme qu'un
//! handler.
//!
//! Le point d'entrée des agents (`/r/v1/report`) et les routes inconnues hors
//! de l'API n'utilisent pas ce module : ils gardent leur 404 sans corps.

use axum::Json;
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Code stable lu par la console ; le message n'est qu'indicatif.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthorized,
    NotFound,
    Conflict,
    TooManyRequests,
    Internal,
}

impl ErrorCode {
    pub fn status(self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Message public : il ne dit jamais la cause d'une erreur interne, ni
    /// pourquoi un jeton ou un code est refusé.
    pub fn message(self) -> &'static str {
        match self {
            Self::Unauthorized => "authentification requise",
            Self::NotFound => "introuvable",
            Self::Conflict => "conflit avec l'état actuel",
            Self::TooManyRequests => "trop de requêtes",
            Self::Internal => "erreur interne",
        }
    }
}

/// Erreur de l'API de la console. La cause d'une erreur interne va au journal
/// de l'appelant, avec le request_id, jamais dans la réponse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiError(pub ErrorCode);

impl ApiError {
    pub const UNAUTHORIZED: Self = Self(ErrorCode::Unauthorized);
    pub const NOT_FOUND: Self = Self(ErrorCode::NotFound);
    pub const CONFLICT: Self = Self(ErrorCode::Conflict);
    pub const TOO_MANY_REQUESTS: Self = Self(ErrorCode::TooManyRequests);
    pub const INTERNAL: Self = Self(ErrorCode::Internal);

    /// Réponse complète, corps compris : appelé par la couche de
    /// `request_id` une fois l'identifiant connu.
    pub fn render(self, request_id: &str) -> Response {
        #[derive(Serialize)]
        struct Body<'a> {
            error: Inner<'a>,
        }
        #[derive(Serialize)]
        struct Inner<'a> {
            code: ErrorCode,
            message: &'static str,
            request_id: &'a str,
        }
        let mut response = (
            self.0.status(),
            Json(Body {
                error: Inner {
                    code: self.0,
                    message: self.0.message(),
                    request_id,
                },
            }),
        )
            .into_response();
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

impl IntoResponse for ApiError {
    /// Statut seul, l'erreur en extension : la couche de `request_id` écrit
    /// le corps (voir l'en-tête du module).
    fn into_response(self) -> Response {
        let mut response = self.0.status().into_response();
        response.extensions_mut().insert(self);
        response
    }
}

/// Fallback des routes de `/api/v1` : méthode refusée sur une route connue.
pub async fn not_found() -> ApiError {
    ApiError::NOT_FOUND
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn the_body_names_the_code_and_the_request_id_only() {
        let response = ApiError::INTERNAL.render("abc");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"error": {
                "code": "internal", "message": "erreur interne", "request_id": "abc"
            }})
        );
    }

    #[test]
    fn without_the_layer_the_response_has_no_body_but_keeps_the_error() {
        let response = ApiError::CONFLICT.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.extensions().get::<ApiError>(),
            Some(&ApiError::CONFLICT)
        );
    }
}
