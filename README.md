# limes

[![crates.io](https://img.shields.io/crates/v/limes.svg)](https://crates.io/crates/limes)
[![docs.rs](https://img.shields.io/docsrs/limes)](https://docs.rs/limes)
[![Tests](https://github.com/vakamo-labs/limes-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/vakamo-labs/limes-rs/actions/workflows/ci.yaml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Bearer-token authentication for `axum`, `tonic` and other [tower](https://docs.rs/tower) services. limes verifies OpenID Connect JWTs against the keys of your identity provider, and Kubernetes service account tokens with the `TokenReview` API. One server can accept tokens from several identity providers.

limes authenticates the requests of [Lakekeeper](https://github.com/lakekeeper/lakekeeper), an Apache Iceberg REST catalog.

## Features

- **JWT verification with cached keys.** limes finds the keys through `/.well-known/openid-configuration`, caches them and refreshes them in the background. A request for a known key never waits for a fetch, and the keys stay in use while the identity provider cannot be reached. Once keys have loaded, tokens with unknown key ids start at most one fetch every 30 seconds.
- **Kubernetes service accounts** through the `TokenReview` API, with audience checks.
- **Several identity providers.** An `AuthenticatorChain` gives each token to the first authenticator that accepts its issuer and audience. Every user gets a `Subject`: the id of the identity provider and the id of the user there.
- **Claim rules.** Require a scope, or claims with `any_of`, `all_of`, `none_of` or `exists`, also on nested claims. A rejection names the rule that failed, never a claim value, so it is safe to log.
- **Errors clients can act on.** A token that is not accepted gets 401, an identity provider that cannot be reached gets 503, and a fault of the server gets 500. gRPC requests get the matching `grpc-status`.
- **Your own authenticators** for API keys, opaque tokens or tests: implement the `Authenticator` trait.

## Quick start

```toml
[dependencies]
limes = "0.8"
```

```rust,no_run
use axum::{response::IntoResponse, routing::get, Extension};
use limes::{jwks::JWKSWebAuthenticator, tower::AuthenticationLayer, Authentication};

#[tokio::main]
async fn main() {
    let authenticator = JWKSWebAuthenticator::new(
        "https://accounts.google.com", // Must provide /.well-known/openid-configuration
        Some(std::time::Duration::from_secs(10 * 60)), // Refresh JWKS keys every 10 minutes
    )
    .await
    .unwrap()
    .set_accepted_audiences(vec!["my-app".to_string()]); // Acceptable audiences (optional)

    let app = axum::Router::new()
        .route("/whoami", get(whoami))
        .layer(AuthenticationLayer::new(authenticator));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn whoami(Extension(auth): Extension<Authentication>) -> impl IntoResponse {
    format!("Hello, {}!", auth.subject().subject_in_idp())
}
```

## Several identity providers

Subject ids are unique only within one identity provider, so give every authenticator in a chain its own `idp_id`. The `kubernetes` feature provides the `KubernetesAuthenticator`; it needs a direct dependency on `k8s-openapi` with a Kubernetes version feature, such as `k8s-openapi = { version = "0.29", features = ["v1_33"] }`.

```rust,no_run
use axum::{response::IntoResponse, routing::get, Extension};
use limes::{
    jwks::JWKSWebAuthenticator, kubernetes::KubernetesAuthenticator, tower::AuthenticationLayer,
    Authentication, AuthenticatorChain, AuthenticatorEnum,
};

#[tokio::main]
async fn main() {
    let oidc_authenticator = JWKSWebAuthenticator::new(
        "https://accounts.google.com", // Must provide /.well-known/openid-configuration
        Some(std::time::Duration::from_secs(10 * 60)), // Refresh JWKS keys every 10 minutes
    )
    .await
    .unwrap()
    .set_idp_id("oidc") // Unique identifier for this IdP
    .set_accepted_audiences(vec!["my-app".to_string()]); // Acceptable audiences (optional)

    // Uses the default Kubernetes client. Other constructors are available that accept a custom client.
    let kubernetes_authenticator = KubernetesAuthenticator::try_new_with_default_client(
        Some("kubernetes"), // Unique identifier for this IdP
        vec![],             // Don't validate the audience
    )
    .await
    .unwrap();

    // Chain the authenticators together. Order matters.
    // The first authenticator that returns true for `can_handle_token` will be used.
    let chain = AuthenticatorChain::<AuthenticatorEnum>::builder()
        .add_authenticator(oidc_authenticator)
        .add_authenticator(kubernetes_authenticator)
        .build();

    let app = axum::Router::new()
        .route("/whoami", get(whoami))
        .layer(AuthenticationLayer::new(chain));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn whoami(Extension(auth): Extension<Authentication>) -> impl IntoResponse {
    let subject = auth.subject();
    // The subject id is unique within its IdP, so the pair identifies the user.
    format!(
        "Hello, {} from {}!",
        subject.subject_in_idp(),
        subject.idp_id().unwrap_or("an unnamed IdP")
    )
}
```

## Reading the identity

An `Authentication` holds the `Subject`, the audiences of the token and the `Identity` the identity provider states: the claims of a JWT, or the user of a Kubernetes `TokenReview`. limes returns these as given. A display name, roles or a user type are your application's choice.

```rust
use limes::{Authentication, ClaimRule, Identity};

fn display_name(authentication: &Authentication) -> Option<&str> {
    match authentication.identity() {
        Identity::Claims(claims) => claims.name(),
        Identity::Kubernetes(user) => user.username(),
        _ => None,
    }
}

fn is_admin(authentication: &Authentication) -> bool {
    let rule = ClaimRule::any_of("realm_access.roles", ["admin"]).unwrap();
    authentication.satisfies(&rule)
}
```

## Custom authenticators

An authenticator returns an `Authentication`. A custom authenticator reports the attributes it verified as `Identity::Claims`:

```rust
use std::collections::HashMap;

use limes::{
    error::{Error, Result},
    introspect::IntrospectionResult,
    Authentication, Authenticator, Subject, VerifiedClaims,
};

/// Accepts the API keys of known clients.
#[derive(Clone)]
struct ApiKeys {
    clients: HashMap<String, String>,
}

impl Authenticator for ApiKeys {
    async fn authenticate(&self, token: &str, _: &IntrospectionResult) -> Result<Authentication> {
        let client = self
            .clients
            .get(token)
            .ok_or_else(|| Error::unauthenticated("Unknown API key"))?;
        let mut claims = serde_json::Map::new();
        claims.insert("client".to_string(), client.clone().into());
        Ok(Authentication::builder()
            .subject(Subject::new(Some("api-keys".to_string()), client.clone()))
            .identity(VerifiedClaims::new(claims))
            .build())
    }

    fn can_handle_token(&self, _: &str, introspection: &IntrospectionResult) -> bool {
        matches!(introspection, IntrospectionResult::Unknown)
    }

    fn idp_id(&self) -> Option<&str> {
        Some("api-keys")
    }
}
```

## tonic

`AuthenticationLayer` also works with tonic: `Server::builder().layer(AuthenticationLayer::new(authenticator))`. gRPC requests are rejected with a `grpc-status`, and service methods read the result with `request.extensions().get::<Authentication>()`.

`Server::builder().layer(..)` authenticates every service, including health checks, so Kubernetes gRPC probes would fail. To authenticate a single service, use tonic's `LayerExt::named_layer`:

```rust,ignore
use tonic::service::LayerExt;

Server::builder()
    .add_service(health_service)
    .add_service(AuthenticationLayer::new(authenticator).named_layer(my_service))
```

With gRPC-Web or CORS, add `AuthenticationLayer` inside `tonic_web::GrpcWebLayer` and any CORS layer, so that preflight requests and gRPC-Web translation happen before authentication.

## Feature flags

- `default`: `rustls-tls`, `aws-lc-rs` and `jwks`.
- `jwks`: the `JWKSWebAuthenticator`.
- `kubernetes`: the `KubernetesAuthenticator`. Select a Kubernetes version in your own `k8s-openapi` dependency; limes leaves that choice to the binary.
- `rustls-tls`: `rustls` for all dependencies.
- `aws-lc-rs`, `ring`: the crypto provider of the Kubernetes client's TLS.
- `valuable`: `valuable::Valuable` for `Subject`, for structured logging.
- `axum`: the deprecated `axum::authentication_middleware`. `tower::AuthenticationLayer` needs no feature.
- `all`: `kubernetes`, `rustls-tls`, `jwks`, `axum` and `valuable`. Choose the crypto provider, `aws-lc-rs` or `ring`, yourself.

The minimum supported Rust version is 1.95.

## Upgrading from 0.7

| 0.7 | 0.8 |
|---|---|
| `full_name()`, `email()`, `principal_type()` on `Authentication`, `PrincipalType` | Derive them from `identity()`. Each `VerifiedClaims` accessor reads one claim. 0.7 fell back across claims: the name to `given_name` or `first_name` and `family_name` or `last_name`, then `app_displayname`, then `preferred_username`; the email to `upn`, then `preferred_username`, if they contain `@`; the type came from `idtyp`, else human if a name claim was present, else application if `app_displayname` or `client_id` was. A Kubernetes identity had its `username()` as the name, the type application and no email. |
| `roles()`, `with_role_claim(s)` | Read the roles claim with `VerifiedClaims::claim(path)`. 0.7 took the strings of an array, or a single string. |
| `with_display_name_template`, `jwks::DisplayNameTemplate`, `jwks::DisplayNameTemplateError` | Removed. |
| `format_subject`, `parse_subject`, `Error::InvalidSubject` | Removed. Choose a string form of `Subject` in your application. |
| `claims(key)`, `all_claims()` | For `Identity::Claims(claims)`: `claims.as_json().get(key)` and `claims.as_json()`; `claims.claim(path)` reads nested claims. For `Identity::Kubernetes(user)`: `user.extra()`. To test a claim rule, `satisfies(rule)`. |
| `issuer()`, `scopes()`, `expires_at()`, `issued_at()`, `not_before()` | The same methods on `VerifiedClaims`. |
| `token_header()` | `introspect::introspect(token)` returns the header of a JWT. |
| `Authentication::idp_id()` | `subject().idp_id()`. `Subject::idp_id()` and `Authenticator::idp_id()` return `Option<&str>`. |
| `Authentication::builder()` with `token_header`, `claims`, `name`, `email`, `principal_type`, `roles` | `.subject(..)` and `.identity(..)` with `VerifiedClaims::new(map)`, `VerifiedClaims::try_from(value)` or a `KubernetesUser`; `audiences` is optional. |
| `Error::RefreshOpenIDWellKnownConfigError` | `Error::FetchJwksError`. `Error::kind()` tells 401, 503 and 500 apart. |
| `none_of` with a `Separator::Literal` made of whitespace | Refused with `ClaimRuleError::WhitespaceLiteralOnDeny`. Use `Separator::Whitespace`. |
| Exhaustive `match` on `IntrospectionResult`, `AuthenticatorEnum`, `KubernetesSubjectSource` | Add a wildcard arm. Patterns of `IntrospectionResult::JWTBearer` need `..`. |
| serde_json's `preserve_order` feature, turned on by limes for your whole build | limes leaves it off, so JSON objects sort their keys. If your code needs objects in insertion order, turn the feature on in your own `Cargo.toml`. |

limes 0.8 also moves to jsonwebtoken 12, kube 5.1 and k8s-openapi 0.29.

## Why the name?

"Limes" is the ancient Roman wall that fortified the Roman Empire. Just like those mighty walls, limes stands guard, protecting your applications from unauthorized access. So, while you won't find any tangy flavors here, you will find robust authentication to keep your digital empire safe. When life gives you Limes, add auth to your crate! Wait a minute ...

## License

Apache-2.0
