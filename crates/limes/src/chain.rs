use crate::{
    Authentication, Authenticator,
    error::{Error, Result},
    introspect::{IntrospectionResult, introspect},
};

/// Enum to hold the different authenticators.
/// This is used for static dispatch in the [`AuthenticatorChain`].
///
/// To include custom [`Authenticator`]s, create a new enum and implement the [`Authenticator`] trait
/// for it.
#[derive(Debug, Clone)]
pub enum AuthenticatorEnum {
    #[cfg(feature = "kubernetes")]
    Kubernetes(crate::kubernetes::KubernetesAuthenticator),
    #[cfg(feature = "jwks")]
    Jwt(crate::jwks::JWKSWebAuthenticator),
}

/// Chain multiple authenticators together.
///
/// The first authenticator that returns true for [`Authenticator::can_handle_token()`] will be used
/// to authenticate the token.
///
/// We strongly recommend setting different `idp_id`s
/// for authenticators. Subject ids between different `IdPs` can overlap.
#[derive(Debug, Clone)]
pub struct AuthenticatorChain<T>
where
    T: Authenticator,
{
    authenticators: Vec<T>,
}

impl<T: Authenticator> AuthenticatorChain<T> {
    #[must_use]
    pub fn builder() -> AuthenticatorChainBuilder<T> {
        AuthenticatorChainBuilder {
            authenticators: Vec::new(),
        }
    }
}

impl<T> Authenticator for AuthenticatorChain<T>
where
    T: Authenticator,
{
    async fn authenticate(&self, token: &str) -> Result<Authentication> {
        let introspect_result = introspect(token);

        for authenticator in &self.authenticators {
            if authenticator.can_handle_token(token, &introspect_result) {
                return authenticator.authenticate(token).await;
            }
        }

        Err(Error::NoAuthenticatorCanHandleToken)
    }

    /// Get the identity provider ID from the first authenticator in the chain, if present.
    ///
    /// Returns the first authenticator's `idp_id()` value as `Option<&String>`.
    ///
    /// # Panics
    ///
    /// Panics if the chain contains no authenticators.
    fn idp_id(&self) -> Option<&String> {
        self.authenticators[0].idp_id()
    }

    /// Returns a vector of each contained authenticator's `idp_id` as `Option<&str>`.
    ///
    /// The returned vector preserves the order of authenticators; each element is
    /// either `Some(&str)` referencing the authenticator's `String` id, or `None`
    /// if that authenticator has no id.
    ///
    /// # Examples
    ///
    /// ```
    /// // Given an existing `chain: AuthenticatorChain<_>`, obtain all idp ids:
    /// let ids: Vec<Option<&str>> = chain.idp_ids();
    /// ```
    fn idp_ids(&self) -> Vec<Option<&str>> {
        self.authenticators
            .iter()
            .flat_map(Authenticator::idp_ids)
            .collect()
    }

    /// Returns whether any contained authenticator can handle the given token.
    ///
    /// Checks each authenticator in the chain with the provided introspection result and
    /// returns `true` as soon as one reports it can handle the token.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// // Assuming `chain` is an AuthenticatorChain and `introspect` is an IntrospectionResult:
    /// let token = "eyJ...";
    /// let can_handle = chain.can_handle_token(token, &introspect);
    /// ```
    fn can_handle_token(&self, token: &str, introspection_result: &IntrospectionResult) -> bool {
        self.authenticators
            .iter()
            .any(|authenticator| authenticator.can_handle_token(token, introspection_result))
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatorChainBuilder<T>
where
    T: Authenticator,
{
    authenticators: Vec<T>,
}

impl<T> AuthenticatorChainBuilder<T>
where
    T: Authenticator,
{
    #[must_use]
    pub fn add_authenticator(mut self, authenticator: impl Into<T>) -> Self {
        self.authenticators.push(authenticator.into());
        self
    }

    #[must_use]
    pub fn build(self) -> AuthenticatorChain<T> {
        AuthenticatorChain {
            authenticators: self.authenticators,
        }
    }
}

#[cfg(any(feature = "kubernetes", feature = "jwks"))]
impl Authenticator for AuthenticatorEnum {
    async fn authenticate(&self, token: &str) -> Result<Authentication> {
        match self {
            #[cfg(feature = "kubernetes")]
            Self::Kubernetes(authenticator) => authenticator.authenticate(token).await,
            #[cfg(feature = "jwks")]
            Self::Jwt(authenticator) => authenticator.authenticate(token).await,
        }
    }

    fn idp_id(&self) -> Option<&String> {
        match self {
            #[cfg(feature = "kubernetes")]
            Self::Kubernetes(authenticator) => authenticator.idp_id(),
            #[cfg(feature = "jwks")]
            Self::Jwt(authenticator) => authenticator.idp_id(),
        }
    }

    fn can_handle_token(&self, token: &str, introspection_result: &IntrospectionResult) -> bool {
        match self {
            #[cfg(feature = "kubernetes")]
            Self::Kubernetes(authenticator) => {
                authenticator.can_handle_token(token, introspection_result)
            }
            #[cfg(feature = "jwks")]
            Self::Jwt(authenticator) => authenticator.can_handle_token(token, introspection_result),
        }
    }
}

#[cfg(feature = "kubernetes")]
impl From<crate::kubernetes::KubernetesAuthenticator> for AuthenticatorEnum {
    fn from(authenticator: crate::kubernetes::KubernetesAuthenticator) -> Self {
        Self::Kubernetes(authenticator)
    }
}

#[cfg(feature = "jwks")]
impl From<crate::jwks::JWKSWebAuthenticator> for AuthenticatorEnum {
    fn from(authenticator: crate::jwks::JWKSWebAuthenticator) -> Self {
        Self::Jwt(authenticator)
    }
}
