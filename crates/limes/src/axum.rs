use crate::error::Error;
use crate::Authenticator;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};

/// Middleware to authenticate requests using the provided authenticator.
///
/// # Errors
/// - If the authorization header is missing.
/// - If the authentication fails.
/// - If no authenticator can handle the token.
pub async fn authentication_middleware<T: Authenticator>(
    State(verifiers): State<T>,
    authorization: Option<TypedHeader<Authorization<Bearer>>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(authorization) = authorization else {
        tracing::debug!("Missing authorization header");
        return (StatusCode::UNAUTHORIZED, "Missing authorization header").into_response();
    };

    let token = authorization.token();
    let auth_result = verifiers.authenticate(token).await;

    match auth_result {
        Ok(auth) => {
            request.extensions_mut().insert(auth);
            next.run(request).await
        }
        Err(e) => {
            tracing::debug!("Unauthenticated: {:?}", e);
            match e {
                Error::NoAuthenticatorCanHandleToken => (
                    StatusCode::UNAUTHORIZED,
                    "No authenticator can handle the token",
                )
                    .into_response(),
                Error::InternalError { .. } => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Authentication failed with internal error",
                )
                    .into_response(),
                _ => (StatusCode::UNAUTHORIZED, "Unauthenticated").into_response(),
            }
        }
    }
}
