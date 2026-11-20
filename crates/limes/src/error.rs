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
    /// A claim required for validation is absent, or is present but fails to parse as the
    /// type its specification requires — the two are indistinguishable at this layer. Named
    /// by the JWT specification (`aud`, `iss`, `exp`, …), never by the token.
    ClaimMissing { claim: String },
    /// The `exp` claim lies in the past.
    Expired,
    /// The `nbf` claim lies in the future. Commonly clock drift between the identity
    /// provider and this host rather than a bad token.
    NotYetValid,
    /// A claim is present but not of the type its specification requires, and is not one of
    /// the claims required for validation — in practice only `nbf`, since a required claim
    /// that fails to parse is reported as [`ClaimMissing`](Self::ClaimMissing). The claim is
    /// named by the JWT specification, never by the token.
    ClaimMalformed { claim: String },
    /// The scope required by `set_scope` is not present.
    ScopeMissing,
    /// The named required-claim rule did not hold.
    ClaimRuleFailed { rule: String },
    /// None of the configured subject claims is present.
    SubjectClaimMissing,
}

impl std::error::Error for RejectionReason {}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AudienceMismatch => f.write_str("audience is not accepted"),
            Self::IssuerMismatch => f.write_str("issuer is not accepted"),
            Self::ClaimMissing { claim } => write!(f, "claim `{claim}` is missing"),
            Self::Expired => f.write_str("token has expired"),
            Self::NotYetValid => {
                f.write_str("token is not valid yet; check the clocks of this host and the issuer")
            }
            Self::ClaimMalformed { claim } => write!(f, "claim `{claim}` is malformed"),
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
    /// A scope passed to `set_scope` that no token could satisfy.
    #[error("Invalid scope: {source}")]
    InvalidScope {
        #[source]
        source: crate::claims::ClaimRuleError,
    },
    /// A token whose signature verified was rejected by claim validation.
    #[error("Token rejected: {rejection}")]
    TokenRejected {
        #[source]
        rejection: RejectionReason,
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
    /// No keys have loaded yet, and the latest fetch of the JWKS failed. The source is a
    /// [`reqwest::Error`], or an [`std::io::Error`] of kind `TimedOut` if the fetch did not
    /// finish in time.
    #[cfg(feature = "jwks")]
    #[error("Failed to fetch the JWKS from {url}: {source}")]
    FetchJwksError {
        url: String,
        #[source]
        source: std::sync::Arc<dyn std::error::Error + Send + Sync>,
    },
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

    /// What this error means for the client that presented the token.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            // The API server refused this server's own request, for example because RBAC
            // does not allow creating TokenReviews. Retrying does not help.
            #[cfg(feature = "kubernetes")]
            Self::KubernetesTokenReviewError(kube::Error::Api(status))
                if (400..500).contains(&status.code) && status.code != 429 =>
            {
                ErrorKind::Internal
            }
            #[cfg(feature = "kubernetes")]
            Self::KubernetesTokenReviewError(_) => ErrorKind::Unavailable,
            #[cfg(feature = "jwks")]
            Self::FetchJwksError { .. } | Self::FetchOpenIDWellKnownConfigError { .. } => {
                ErrorKind::Unavailable
            }
            #[cfg(feature = "kubernetes")]
            Self::KubernetesConfigError(_) => ErrorKind::Internal,
            #[cfg(feature = "jwks")]
            Self::InvalidWellKnownConfig { .. } => ErrorKind::Internal,
            #[cfg(feature = "jwks")]
            Self::JWTDecodeError { .. } => ErrorKind::Unauthenticated,
            Self::InternalError { .. } | Self::InvalidScope { .. } | Self::UrlParseError(_) => {
                ErrorKind::Internal
            }
            Self::InvalidSubject { .. }
            | Self::Unauthenticated { .. }
            | Self::TokenRejected { .. }
            | Self::NoAuthenticatorCanHandleToken => ErrorKind::Unauthenticated,
        }
    }
}

/// What an [`Error`] means for the client that presented the token, see [`Error::kind`].
///
/// A server answers [`Unauthenticated`](Self::Unauthenticated) with HTTP 401 / gRPC
/// `UNAUTHENTICATED`, [`Unavailable`](Self::Unavailable) with 503 / `UNAVAILABLE`, and
/// [`Internal`](Self::Internal) with 500 / `INTERNAL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The token is not accepted. Retrying with the same token does not help.
    Unauthenticated,
    /// A backend needed to check the token, such as the identity provider or the
    /// Kubernetes API, could not be reached. The token may be valid; the client should
    /// retry later and keep the token.
    Unavailable,
    /// This server is misconfigured or failed. Retrying does not help.
    Internal,
}
