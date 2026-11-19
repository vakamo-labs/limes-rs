//! A [tower](https://docs.rs/tower) layer that authenticates requests.
//!
//! [`AuthenticationLayer`] works with servers built on tower and the `http` crate whose
//! response bodies carry [`Bytes`], including `axum` and `tonic`:
//!
//! - **axum:** `Router::new().route(..).layer(AuthenticationLayer::new(authenticator))`,
//!   then read `Extension<Authentication>` in a handler.
//! - **tonic:** `Server::builder().layer(AuthenticationLayer::new(authenticator))`,
//!   then read `request.extensions().get::<Authentication>()` in a service method.
//!
//! Requests without a valid `Authorization: Bearer <token>` header are rejected before
//! they reach the inner service. gRPC requests (`content-type: application/grpc` or
//! `application/grpc+<format>`) are rejected with a `grpc-status` header, all other requests
//! with an HTTP status code.

use crate::Authenticator;
use crate::error::Error;
use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode, header};
use http_body_util::{Either, Full};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

/// gRPC status code `UNAUTHENTICATED`.
const GRPC_UNAUTHENTICATED: &str = "16";
/// gRPC status code `INTERNAL`.
const GRPC_INTERNAL: &str = "13";

/// Layer that authenticates every request with an [`Authenticator`].
///
/// On success the [`Authentication`](crate::Authentication) is inserted into the request
/// extensions and the request is passed to the inner service.
///
/// The response body of the inner service must implement `http_body::Body<Data = Bytes>`,
/// because rejections are answered with a [`Full<Bytes>`] body. This holds for axum and tonic;
/// other servers may need to map their body first.
#[derive(Debug, Clone)]
pub struct AuthenticationLayer<A> {
    authenticator: Arc<A>,
}

impl<A> AuthenticationLayer<A> {
    /// Create a layer that authenticates requests with `authenticator`.
    pub fn new(authenticator: A) -> Self {
        Self {
            authenticator: Arc::new(authenticator),
        }
    }
}

impl<S, A> Layer<S> for AuthenticationLayer<A> {
    type Service = AuthenticationService<S, A>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthenticationService {
            inner,
            authenticator: Arc::clone(&self.authenticator),
        }
    }
}

/// Service created by [`AuthenticationLayer`].
#[derive(Debug, Clone)]
pub struct AuthenticationService<S, A> {
    inner: S,
    authenticator: Arc<A>,
}

impl<S, A, ReqBody, ResBody> Service<Request<ReqBody>> for AuthenticationService<S, A>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    A: Authenticator + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<Either<ResBody, Full<Bytes>>>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        // Take the service that was driven to readiness and leave a fresh clone behind.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let authenticator = Arc::clone(&self.authenticator);

        Box::pin(async move {
            match authenticate(&*authenticator, &mut request).await {
                Ok(()) => {
                    let response = inner.call(request).await?;
                    Ok(response.map(Either::Left))
                }
                Err(rejection) => {
                    let response = if is_grpc(&request) {
                        rejection.grpc_response()
                    } else {
                        rejection.http_response()
                    };
                    Ok(response.map(Either::Right))
                }
            }
        })
    }
}

/// Authenticate `request` and insert the [`Authentication`](crate::Authentication) into its
/// extensions.
pub(crate) async fn authenticate<A: Authenticator, B>(
    authenticator: &A,
    request: &mut Request<B>,
) -> Result<(), Rejection> {
    let token = bearer_token(request.headers().get(header::AUTHORIZATION))?;
    let introspection = crate::introspect::introspect(token);
    match authenticator.authenticate(token, &introspection).await {
        Ok(authentication) => {
            request.extensions_mut().insert(authentication);
            Ok(())
        }
        Err(e) => {
            tracing::debug!("Unauthenticated: {:?}", e);
            Err(Rejection::from(&e))
        }
    }
}

/// Why a request was rejected, and how to answer it over HTTP and gRPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rejection {
    status: StatusCode,
    grpc_status: &'static str,
    message: &'static str,
}

impl Rejection {
    const MISSING_HEADER: Self = Self {
        status: StatusCode::UNAUTHORIZED,
        grpc_status: GRPC_UNAUTHENTICATED,
        message: "Missing authorization header",
    };
    const INVALID_HEADER: Self = Self {
        status: StatusCode::BAD_REQUEST,
        grpc_status: GRPC_UNAUTHENTICATED,
        message: "Invalid authorization header",
    };
    const UNAUTHENTICATED: Self = Self {
        status: StatusCode::UNAUTHORIZED,
        grpc_status: GRPC_UNAUTHENTICATED,
        message: "Unauthenticated",
    };

    /// A gRPC "trailers-only" response: HTTP 200 with the status in the headers.
    fn grpc_response(self) -> Response<Full<Bytes>> {
        let mut response = Response::new(Full::default());
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc"),
        );
        headers.insert("grpc-status", HeaderValue::from_static(self.grpc_status));
        headers.insert("grpc-message", HeaderValue::from_static(self.message));
        response
    }

    /// A plain-text response with the HTTP status code.
    pub(crate) fn http_response(self) -> Response<Full<Bytes>> {
        let mut response = Response::new(Full::from(self.message));
        *response.status_mut() = self.status;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        response
    }
}

impl From<&Error> for Rejection {
    fn from(error: &Error) -> Self {
        match error {
            Error::NoAuthenticatorCanHandleToken => Self {
                status: StatusCode::UNAUTHORIZED,
                grpc_status: GRPC_UNAUTHENTICATED,
                message: "No authenticator can handle the token",
            },
            Error::InternalError { .. } => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                grpc_status: GRPC_INTERNAL,
                message: "Authentication failed with internal error",
            },
            _ => Self::UNAUTHENTICATED,
        }
    }
}

/// Whether the request is a gRPC call (`content-type: application/grpc`, `application/grpc+proto`, …).
///
/// gRPC-Web (`application/grpc-web…`) is not: put this layer inside tonic-web's `GrpcWebLayer`,
/// which translates those requests to gRPC.
fn is_grpc<B>(request: &Request<B>) -> bool {
    request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.as_bytes().strip_prefix(b"application/grpc"))
        .is_some_and(|rest| matches!(rest.first(), None | Some(b'+' | b';')))
}

/// Extract the token from an `Authorization: Bearer <token>` header.
///
/// Matches the parsing of `headers::Authorization<Bearer>`: the scheme is case-insensitive,
/// must be followed by a space, leading whitespace of the token is ignored, and the value must
/// be visible ASCII. An empty token is unauthenticated.
fn bearer_token(value: Option<&HeaderValue>) -> Result<&str, Rejection> {
    const SCHEME: &str = "Bearer ";

    let Some(value) = value else {
        tracing::debug!("Missing authorization header");
        return Err(Rejection::MISSING_HEADER);
    };
    let value = value.to_str().map_err(|_| Rejection::INVALID_HEADER)?;
    match value.get(..SCHEME.len()) {
        Some(scheme) if scheme.eq_ignore_ascii_case(SCHEME) => {
            match value[SCHEME.len()..].trim_start() {
                "" => {
                    tracing::debug!("Bearer token is empty");
                    Err(Rejection::UNAUTHENTICATED)
                }
                token => Ok(token),
            }
        }
        _ => {
            tracing::debug!("Authorization header is not a bearer token");
            Err(Rejection::INVALID_HEADER)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Authentication, Subject, error::Result, introspect::IntrospectionResult};
    use ::tower::{ServiceExt, service_fn};
    use http_body_util::BodyExt;
    use std::convert::Infallible;

    /// Accepts the token `valid`; any other token selects an error.
    #[derive(Debug, Clone)]
    struct MockAuthenticator;

    impl Authenticator for MockAuthenticator {
        async fn authenticate(
            &self,
            token: &str,
            _introspection: &IntrospectionResult,
        ) -> Result<Authentication> {
            match token {
                "valid" => Ok(Authentication::builder()
                    .token_header(None)
                    .claims(serde_json::json!({}))
                    .name(None)
                    .email(None)
                    .subject(Subject::new(Some("idp".to_string()), "alice".to_string()))
                    .principal_type(None)
                    .build()),
                "unhandled" => Err(Error::NoAuthenticatorCanHandleToken),
                "internal" => Err(Error::internal("boom", "boom")),
                "" => panic!("empty token reached the authenticator"),
                _ => Err(Error::unauthenticated("bad token")),
            }
        }

        fn can_handle_token(&self, _: &str, _: &IntrospectionResult) -> bool {
            true
        }

        fn idp_id(&self) -> Option<&String> {
            None
        }
    }

    /// Echoes the authenticated subject, or panics if called without one.
    async fn whoami(request: Request<()>) -> std::result::Result<Response<String>, Infallible> {
        let auth = request
            .extensions()
            .get::<Authentication>()
            .expect("inner service called without authentication");
        Ok(Response::new(auth.subject().subject_in_idp().to_string()))
    }

    async fn send(
        authorization: Option<&str>,
        content_type: Option<&str>,
    ) -> (StatusCode, http::HeaderMap, String) {
        let service = AuthenticationLayer::new(MockAuthenticator).layer(service_fn(whoami));
        let mut request = Request::builder();
        if let Some(authorization) = authorization {
            request = request.header(header::AUTHORIZATION, authorization);
        }
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        let response = service.oneshot(request.body(()).unwrap()).await.unwrap();
        let (parts, body) = response.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        (
            parts.status,
            parts.headers,
            String::from_utf8(body.to_vec()).unwrap(),
        )
    }

    #[tokio::test]
    async fn valid_token_reaches_inner_service() {
        let (status, _, body) = send(Some("Bearer valid"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "alice");
    }

    #[tokio::test]
    async fn bearer_scheme_is_case_insensitive() {
        let (status, _, body) = send(Some("bearer valid"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "alice");
    }

    #[tokio::test]
    async fn leading_spaces_of_token_are_ignored() {
        let (status, _, body) = send(Some("Bearer   valid"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "alice");
    }

    #[tokio::test]
    async fn http_rejections() {
        let cases = [
            (
                None,
                StatusCode::UNAUTHORIZED,
                "Missing authorization header",
            ),
            (
                Some("Basic dXNlcg=="),
                StatusCode::BAD_REQUEST,
                "Invalid authorization header",
            ),
            (Some("Bearer "), StatusCode::UNAUTHORIZED, "Unauthenticated"),
            (
                Some("Bearer   "),
                StatusCode::UNAUTHORIZED,
                "Unauthenticated",
            ),
            (
                Some("Bearer"),
                StatusCode::BAD_REQUEST,
                "Invalid authorization header",
            ),
            (
                Some("Bearervalid"),
                StatusCode::BAD_REQUEST,
                "Invalid authorization header",
            ),
            (
                Some("Bearer unhandled"),
                StatusCode::UNAUTHORIZED,
                "No authenticator can handle the token",
            ),
            (
                Some("Bearer internal"),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Authentication failed with internal error",
            ),
            (
                Some("Bearer wrong"),
                StatusCode::UNAUTHORIZED,
                "Unauthenticated",
            ),
        ];
        for (authorization, expected_status, expected_body) in cases {
            let (status, headers, body) = send(authorization, None).await;
            assert_eq!(status, expected_status, "{authorization:?}");
            assert_eq!(body, expected_body, "{authorization:?}");
            assert!(headers.get("grpc-status").is_none());
        }
    }

    #[tokio::test]
    async fn grpc_rejections() {
        let cases = [
            (None, GRPC_UNAUTHENTICATED),
            (Some("Basic dXNlcg=="), GRPC_UNAUTHENTICATED),
            (Some("Bearer unhandled"), GRPC_UNAUTHENTICATED),
            (Some("Bearer internal"), GRPC_INTERNAL),
            (Some("Bearer wrong"), GRPC_UNAUTHENTICATED),
        ];
        for (authorization, expected_grpc_status) in cases {
            let (status, headers, body) = send(authorization, Some("application/grpc")).await;
            assert_eq!(status, StatusCode::OK, "{authorization:?}");
            assert_eq!(
                headers["grpc-status"], expected_grpc_status,
                "{authorization:?}"
            );
            assert_eq!(headers[header::CONTENT_TYPE], "application/grpc");
            assert!(headers.contains_key("grpc-message"));
            assert!(body.is_empty());
        }
    }

    #[tokio::test]
    async fn grpc_content_types() {
        for (content_type, grpc) in [
            ("application/grpc", true),
            ("application/grpc+proto", true),
            ("application/grpc;charset=utf-8", true),
            ("application/grpc-web", false),
            ("application/grpc-web+proto", false),
            ("application/grpc-report", false),
            ("application/json", false),
        ] {
            let (status, headers, _) = send(None, Some(content_type)).await;
            assert_eq!(headers.contains_key("grpc-status"), grpc, "{content_type}");
            assert_eq!(status == StatusCode::OK, grpc, "{content_type}");
        }
    }

    #[tokio::test]
    async fn axum_router() {
        use axum::{Extension, Router, routing::get};

        async fn handler(Extension(auth): Extension<Authentication>) -> String {
            auth.subject().subject_in_idp().to_string()
        }
        let app = Router::new()
            .route("/", get(handler))
            .layer(AuthenticationLayer::new(MockAuthenticator));

        let request = Request::get("/")
            .header(header::AUTHORIZATION, "Bearer valid")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"alice");

        let request = Request::get("/").body(axum::body::Body::empty()).unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn tonic_server() {
        use tonic::transport::{Server, server::TcpIncoming};
        use tonic_health::pb::{
            HealthCheckRequest, health_check_response::ServingStatus, health_client::HealthClient,
        };

        let (_reporter, health) = tonic_health::server::health_reporter();
        // Fails the call unless the layer handed the authentication to the service.
        let health = tonic::service::interceptor::InterceptedService::new(
            health,
            |request: tonic::Request<()>| match request.extensions().get::<Authentication>() {
                Some(auth) if auth.subject().subject_in_idp() == "alice" => Ok(request),
                _ => Err(tonic::Status::failed_precondition("no authentication")),
            },
        );
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap();
        tokio::spawn(
            Server::builder()
                .layer(AuthenticationLayer::new(MockAuthenticator))
                .add_service(health)
                .serve_with_incoming(incoming),
        );

        let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = HealthClient::new(channel);

        let status = client
            .check(HealthCheckRequest::default())
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
        assert_eq!(status.message(), "Missing authorization header");

        let mut request = tonic::Request::new(HealthCheckRequest::default());
        request
            .metadata_mut()
            .insert("authorization", "Bearer internal".parse().unwrap());
        let status = client.check(request).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Internal);

        let mut request = tonic::Request::new(HealthCheckRequest::default());
        request
            .metadata_mut()
            .insert("authorization", "Bearer valid".parse().unwrap());
        let response = client.check(request).await.unwrap().into_inner();
        assert_eq!(response.status(), ServingStatus::Serving);
    }
}
