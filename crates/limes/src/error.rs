pub type Result<T> = std::result::Result<T, Error>;

/// Why a cryptographically verified token was rejected.
///
/// Carries names only — never presented or expected claim values — so it is safe to log
/// and audit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionReason {
    /// The `aud` claim matched none of the accepted audiences.
    AudienceMismatch,
    /// The `iss` claim matched none of the accepted issuers.
    IssuerMismatch,
    /// The scope required by `set_scope` is not present.
    ScopeMissing,
    /// The named required-claim rule did not hold.
    ClaimRuleFailed { rule: String },
    /// None of the configured subject claims is present.
    SubjectClaimMissing,
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AudienceMismatch => f.write_str("audience is not accepted"),
            Self::IssuerMismatch => f.write_str("issuer is not accepted"),
            Self::ScopeMissing => f.write_str("required scope is missing"),
            Self::ClaimRuleFailed { rule } => write!(f, "required-claim rule `{rule}` failed"),
            Self::SubjectClaimMissing => f.write_str("subject claim is missing"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    /// A token whose signature verified was rejected by claim validation.
    #[error("Token rejected: {rejection}")]
    TokenRejected { rejection: RejectionReason },
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
    #[must_use]
    pub fn rejected(rejection: RejectionReason) -> Self {
        Self::TokenRejected { rejection }
    }

    /// The typed reason if this is a [`Error::TokenRejected`].
    #[must_use]
    pub fn rejection(&self) -> Option<&RejectionReason> {
        match self {
            Self::TokenRejected { rejection } => Some(rejection),
            _ => None,
        }
    }

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
