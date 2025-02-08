pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Could not parse subject from string: {subject}")]
    InvalidSubject { subject: String },
    #[cfg(feature = "kubernetes")]
    #[error("Failed get kubernetes configuration: {0}")]
    KubernetesConfigError(#[source] kube::Error),
    #[cfg(feature = "kubernetes")]
    #[error("Failed to validate token using kubernetes TokenReview: {0}")]
    KubernetesTokenReviewError(#[source] kube::Error),
    #[error("Authentication failed: {reason}")]
    Unauthenticated { reason: String },
    #[error("Audience mismatch: expected {expected:?}, got {actual:?}")]
    AudienceMismatch {
        expected: Vec<String>,
        actual: Vec<String>,
    },
    #[error("Failed to parse URL: {0}")]
    UrlParseError(#[from] url::ParseError),
    #[cfg(feature = "jwks")]
    #[error("Failed to fetch openid configuration from {url}: {source}")]
    FetchOpenIDWellKnownConfigError {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[cfg(feature = "jwks")]
    #[error("Failed to refresh openid configuration from {url}: {reason}")]
    RefreshOpenIDWellKnownConfigError { url: String, reason: String },
    #[cfg(feature = "jwks")]
    #[error("Failed to parse openid configuration. Expected fields: {expected_fields:?}")]
    InvalidWellKnownConfig {
        expected_fields: &'static [&'static str],
        #[source]
        source: reqwest::Error,
    },
    #[cfg(feature = "jwks")]
    #[error("Failed to decode JWT Token. {reason}")]
    JWTDecodeError { reason: String },
    #[error("Internal error. {reason}.")]
    InternalError {
        reason: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("No authenticator can handle the provided token.")]
    NoAuthenticatorCanHandleToken,
}

impl Error {
    pub fn unauthenticated(reason: impl Into<String>) -> Self {
        Self::Unauthenticated {
            reason: reason.into(),
        }
    }

    pub fn internal(
        reason: impl Into<String>,
        error: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::InternalError {
            reason: reason.into(),
            source: error.into(),
        }
    }
}
