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
