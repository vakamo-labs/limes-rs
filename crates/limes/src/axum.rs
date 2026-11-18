use crate::Authenticator;
use crate::tower::AuthenticationLayer;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use tower_layer::Layer;
use tower_service::Service;

/// Middleware to authenticate requests using the provided authenticator.
///
/// This is a thin wrapper around [`AuthenticationLayer`], which also works outside of
/// `axum::middleware::from_fn_with_state` and with other tower-based servers such as tonic.
///
/// # Errors
/// - If the authorization header is missing.
/// - If the authentication fails.
/// - If no authenticator can handle the token.
#[deprecated(note = "use `limes::tower::AuthenticationLayer` instead: \
                     `router.layer(AuthenticationLayer::new(authenticator))`")]
pub async fn authentication_middleware<T: Authenticator + 'static>(
    State(verifiers): State<T>,
    // Kept for compatibility: axum rejects a malformed header before this function runs.
    _authorization: Option<TypedHeader<Authorization<Bearer>>>,
    request: Request,
    next: Next,
) -> Response {
    let mut service = AuthenticationLayer::new(verifiers).layer(next);
    match service.call(request).await {
        Ok(response) => response.map(axum::body::Body::new),
        Err(never) => match never {},
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::{Authentication, Subject, error::Result, introspect::IntrospectionResult};
    use axum::{
        Extension, Router, body::Body, http::StatusCode, middleware::from_fn_with_state,
        routing::get,
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[derive(Debug, Clone)]
    struct AcceptValid;

    impl Authenticator for AcceptValid {
        async fn authenticate(
            &self,
            token: &str,
            _: &IntrospectionResult,
        ) -> Result<Authentication> {
            if token != "valid" {
                return Err(crate::error::Error::unauthenticated("bad token"));
            }
            Ok(Authentication::builder()
                .token_header(None)
                .claims(serde_json::json!({}))
                .name(None)
                .email(None)
                .subject(Subject::new(None, "alice".to_string()))
                .principal_type(None)
                .build())
        }

        fn can_handle_token(&self, _: &str, _: &IntrospectionResult) -> bool {
            true
        }

        fn idp_id(&self) -> Option<&String> {
            None
        }
    }

    #[tokio::test]
    async fn deprecated_middleware_still_works() {
        async fn handler(Extension(auth): Extension<Authentication>) -> String {
            auth.subject().subject_in_idp().to_string()
        }
        let app = Router::new()
            .route("/", get(handler))
            .layer(from_fn_with_state(
                AcceptValid,
                authentication_middleware::<AcceptValid>,
            ));

        let request = Request::get("/")
            .header("authorization", "Bearer valid")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"alice");

        let request = Request::get("/").body(Body::empty()).unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"Missing authorization header");

        let request = Request::get("/")
            .header("authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
