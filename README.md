# limes

[![crates.io](https://img.shields.io/crates/v/limes.svg)](https://crates.io/crates/limes)
[![docs.rs](https://img.shields.io/docsrs/limes)](https://docs.rs/limes)
[![Tests](https://github.com/vakamo-labs/limes-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/vakamo-labs/limes-rs/actions/workflows/ci.yaml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

limes is an extensible framework for bearer-token authentication in `axum`, `tonic` and other [tower](https://docs.rs/tower) services. It has two built-in authenticators. One verifies OpenID Connect (OIDC) JWTs against the JWKS of your identity provider. The other checks Kubernetes service account tokens with the `TokenReview` API. For API keys or other bearer tokens, implement the `Authenticator` trait.

limes is built for multi-tenant servers. An `AuthenticatorChain` reads the issuer and audience of a token before it verifies anything, and gives the token to the first authenticator that accepts them. So one server can accept tokens from many identity providers or tenants, such as several Keycloak realms or Entra ID tenants. Each user's `Subject` holds the `idp_id` of the authenticator and the user's id in that identity provider. An optional cache answers repeated tokens from memory.

## Features

- **JWT verification with cached keys.** limes finds the keys through `/.well-known/openid-configuration`, caches them and refreshes them in the background. A request for a known key never waits for a fetch, and the keys stay in use while the identity provider cannot be reached. Once keys have loaded, tokens with unknown key ids start at most one fetch every 30 seconds.
- **Kubernetes service accounts** through the `TokenReview` API, with audience checks. By default, each authenticator runs at most 32 reviews at the same time, so a flood of tokens cannot pile up requests at the API server. A request that finds no free slot within 1 second gets 503.
- **A cache of verified tokens** (feature `cache`). Clients send the same token for minutes. limes can answer a repeated token from memory for a time you choose, so most requests skip the signature check or the `TokenReview` request. A cached answer never outlives the token's `exp`, and the memory stays within a limit you set.
- **Several identity providers or tenants.** An `AuthenticatorChain` gives each token to the first authenticator that accepts its issuer and audience, before any verification.
- **Claim rules.** Require a scope, or claims with `any_of`, `all_of`, `none_of` or `exists`, also on nested claims. A rejection names the rule that failed, never a claim value, so it is safe to log.
- **Errors clients can act on.** A token that is not accepted gets 401, an identity provider that cannot be reached gets 503, and a fault of the server gets 500. gRPC requests get the matching `grpc-status`.
- **Your own authenticators** for API keys, opaque tokens or tests: implement the `Authenticator` trait.

## Quick start

```toml
[dependencies]
limes = "0.8"
axum = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
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

## Caching verified tokens

Verifying a JWT costs tens of microseconds of signature checks, and a Kubernetes token costs a `TokenReview` request to the API server. Clients send the same token for minutes. `CachedAuthenticator` wraps any authenticator, also a chain or one of your own, and answers a token it verified a short time ago from memory. It needs the `cache` feature:

```toml
[dependencies]
limes = { version = "0.8", features = ["cache"] }
```

```rust,no_run
use std::time::Duration;

use limes::{
    cache::{CacheConfig, CachedAuthenticator},
    jwks::JWKSWebAuthenticator,
    tower::AuthenticationLayer,
};

#[tokio::main]
async fn main() {
    let authenticator = JWKSWebAuthenticator::new("https://accounts.google.com", None)
        .await
        .unwrap()
        .set_accepted_audiences(vec!["my-app".to_string()]);

    let authenticator = CachedAuthenticator::new(
        authenticator,
        CacheConfig::builder()
            .time_to_live(Duration::from_secs(30)) // Reuse a verification for up to 30 seconds
            .max_bytes(64 * 1024 * 1024) // Hold up to 64 MiB of authentications (the default)
            .build(),
    );

    // Free the claims of expired tokens, for example when you export `stats()` as metrics.
    let cache = authenticator.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            cache.remove_expired();
        }
    });

    let app = axum::Router::new().layer(AuthenticationLayer::new(authenticator));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

What a cached answer means:

- A token is answered from the cache only while a fresh verification would still accept it. An entry ends after `time_to_live` or at the token's `exp`, whichever is earlier.
- The exception is a change the authenticator learns from outside the token: a key removed from the JWKS, a deleted Kubernetes service account or pod, or a revoked key of your own authenticator. Each process has its own cache, so in each process a token verified before the change keeps working for up to `time_to_live`. A removed JWKS key already works until the next JWKS refresh, one hour by default, so `time_to_live` matters most for Kubernetes tokens and authenticators of your own.
- While a client keeps using a token, each process verifies it about once per `time_to_live`. A longer time saves more verifications; a shorter time ends access sooner after such a change. 30 seconds is a good start.
- Only successful authentications are stored. The cache keeps an HMAC of each token, never the token itself.
- A flood of tokens used only once does not push out the tokens that clients keep sending.
- `max_bytes` bounds an estimate of the memory; plan for about 20 % more. An entry takes about 2 KB for a Kubernetes token, 5 to 6 KB for a typical OpenID Connect token, and up to 30 KB for an Entra ID token with many groups.
- An authenticator of your own should set `Authentication::valid_until` for credentials that expire; without it an entry lasts the whole `time_to_live`. Do not wrap an authenticator of single-use tokens, or one that counts uses: a cached answer does not call it.
- `stats()` reports hits, misses, evictions and size, for your metrics.

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
    Authentication, Authenticator, Subject, Token, VerifiedClaims,
};

/// Accepts the API keys of known clients.
#[derive(Clone)]
struct ApiKeys {
    clients: HashMap<String, String>,
}

impl Authenticator for ApiKeys {
    async fn authenticate(&self, token: &Token<'_>) -> Result<Authentication> {
        let client = self
            .clients
            .get(token.as_str())
            .ok_or_else(|| Error::unauthenticated("Unknown API key"))?;
        let mut claims = serde_json::Map::new();
        claims.insert("client".to_string(), client.clone().into());
        Ok(Authentication::builder()
            .subject(Subject::new(Some("api-keys".to_string()), client.clone()))
            .identity(VerifiedClaims::new(claims))
            .build())
    }

    fn can_handle_token(&self, token: &Token<'_>) -> bool {
        matches!(token.introspection(), IntrospectionResult::Unknown)
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
- `cache`: the `cache::CachedAuthenticator`, which reuses successful authentications for a short time.
- `all`: `kubernetes`, `rustls-tls`, `jwks`, `axum`, `valuable` and `cache`. Choose the crypto provider, `aws-lc-rs` or `ring`, yourself.

The minimum supported Rust version is 1.95.

## Upgrading

[UPGRADING.md](https://github.com/vakamo-labs/limes-rs/blob/main/UPGRADING.md) lists the changes that need updates in your code, from 0.7 to 0.8.

## Why the name?

"Limes" is the ancient Roman wall that fortified the Roman Empire. Just like those mighty walls, limes stands guard, protecting your applications from unauthorized access. So, while you won't find any tangy flavors here, you will find robust authentication to keep your digital empire safe. When life gives you Limes, add auth to your crate! Wait a minute ...

## License

Apache-2.0
