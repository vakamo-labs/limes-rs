[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://github.com/vakamo-labs/limes-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/vakamo-labs/limes-rs/actions/workflows/unittests.yaml)

# Limes

Limes is a multi-tenant capable Authentication middleware for OAuth2.0 and Open ID Connect with optional support for `axum`.
It supports the following [`Authenticator`]s natively:

* [`JWKSWebAuthenticator`](`jwks::JWKSWebAuthenticator`) that fetches JWKs keys from a `.well-known/openid-configuration`, refreshes keys regularly, and validates tokens locally.
* [`KubernetesAuthenticator`](`kubernetes::KubernetesAuthenticator`) which validates tokens using Kubernetes `TokenReview`.
* [`AuthenticatorChain`] holds a collection of [`Authenticator`]s and authenticates the token with the first suitable Authenticator. This is especially useful for multi-tenant setups where tokens from multiple IdPs should be accepted. Each IdP is assigned a unique `idp_id` to provide a globally unique [`Subject`] that identifies a user.

Custom Authenticators can easily be added by implementing the [`Authenticator`] trait.

# Single-Tenant Example

```no_run
use axum::{middleware::from_fn_with_state, response::IntoResponse, routing::get, Extension};
use limes::{
    axum::authentication_middleware, format_subject, jwks::JWKSWebAuthenticator, Authentication,
};

// Use none for single tenant setups
const IDP_SEPARATOR: Option<char> = None;

#[tokio::main]
async fn main() {
    let authenticator = JWKSWebAuthenticator::new(
        "https://accounts.google.com", // Must provide ./well-known/openid-configuration
        Some(std::time::Duration::from_secs(10 * 60)), // Refresh JWKS keys every 10 minutes
    )
    .await
    .unwrap()
    .set_accepted_audiences(vec!["my-app".to_string()]); // Acceptable audiences (optional)

    let app = axum::Router::new()
        .route("/whoami", get(whoami))
        .layer(from_fn_with_state(
            authenticator,
            authentication_middleware::<JWKSWebAuthenticator>,
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn whoami(Extension(auth): Extension<Authentication>) -> impl IntoResponse {
    format!("Hello, {}!", format_subject(auth.subject(), IDP_SEPARATOR))
}
```

# Multi-Tenant Setup
Limes supports the chained Authenticators. As each Authenticator can point to a different IdP, and subject IDs are not  guaranteed to be unique across IdPs, it is important to specify the `idp_id` for each [`Authenticator`] that is used in a [`AuthenticatorChain`].

```no_run
use axum::{middleware::from_fn_with_state, response::IntoResponse, routing::get, Extension};
use limes::{
    axum::authentication_middleware, format_subject, jwks::JWKSWebAuthenticator,
    kubernetes::KubernetesAuthenticator, Authentication, AuthenticatorChain, AuthenticatorEnum,
};

// We recommend using a character that is never used in subject ids
const IDP_SEPARATOR: Option<char> = Some('~');

#[tokio::main]
async fn main() {
    let oidc_authenticator = JWKSWebAuthenticator::new(
        "https://accounts.google.com", // Must provide ./well-known/openid-configuration
        Some(std::time::Duration::from_secs(10 * 60)), // Refresh JWKS keys every 10 minutes
    )
    .await
    .unwrap()
    .set_idp_id("oidc") // Unique identifier for this IdP. Must never contain the `IDP_SEPARATOR`
    .set_accepted_audiences(vec!["my-app".to_string()]); // Acceptable audiences (optional)

    // Uses the default Kubernetes client. Other constructors are available that accept a custom client.
    let kubernetes_authenticator = KubernetesAuthenticator::try_new_with_default_client(
        Some("kubernetes"), // Unique identifier for this IdP. Must never contain the `IDP_SEPARATOR`
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
        .layer(from_fn_with_state(
            chain,
            authentication_middleware::<AuthenticatorChain<AuthenticatorEnum>>,
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn whoami(Extension(auth): Extension<Authentication>) -> impl IntoResponse {
    format!("Hello, {}!", format_subject(auth.subject(), IDP_SEPARATOR))
    // Would print "oidc~<subject_id>" for google tokens, where oidc is the `idp_id` we set above.
}
```

# Feature flags
Limes uses a set of feature flags to reduce the amount of compiled code.
The following feature flags are available:

* `all`: Activate all features
* `default`: Includes `rustls-tls` and `jwks`.
* `kubernetes`: Provides the `KubernetesAuthenticator` implementation which validates tokens using Kubernetes `TokenReview`.
* `rustls-tls`: Enable `rustls` for all dependant crates.
* `jwks`: Provides the `JWKSWebAuthenticator`
* `multi-tenant`: Enable support for multiple IdPs. Setting this feature flag extends core structs such as [`Subject`] by an `idp_id` field.
* `axum`: Provides axum middleware that performs the Authentication and provides the tokens Payload as extension.
