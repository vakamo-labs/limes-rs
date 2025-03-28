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
}
