use crate::{
    Authentication, Authenticator, Token,
    error::{Error, Result},
};

/// Enum to hold the different authenticators.
/// This is used for static dispatch in the [`AuthenticatorChain`].
///
/// To include custom [`Authenticator`]s, create a new enum and implement the [`Authenticator`] trait
/// for it.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
/// for authenticators. Subject ids between different identity providers can overlap.
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
    /// Authenticate a token using the first authenticator in the chain that can handle it.
    ///
    /// # Errors
    /// - No authenticator in the chain can handle the token.
    /// - The matching authenticator rejects the token.
    async fn authenticate(&self, token: &Token<'_>) -> Result<Authentication> {
        for authenticator in &self.authenticators {
            if authenticator.can_handle_token(token) {
                return authenticator.authenticate(token).await;
            }
        }

        Err(Error::NoAuthenticatorCanHandleToken)
    }

    /// Returns the `idp_id` of the first authenticator in the chain, or `None` if the chain is empty.
    fn idp_id(&self) -> Option<&str> {
        self.authenticators.first().and_then(Authenticator::idp_id)
    }

    /// Returns the `idp_id` of every authenticator in the chain, in order.
    /// Each element is `None` for authenticators that have no `idp_id` set.
    fn idp_ids(&self) -> Vec<Option<&str>> {
        self.authenticators
            .iter()
            .flat_map(Authenticator::idp_ids)
            .collect()
    }

    /// Returns `true` if any authenticator in the chain can handle the token.
    fn can_handle_token(&self, token: &Token<'_>) -> bool {
        self.authenticators
            .iter()
            .any(|authenticator| authenticator.can_handle_token(token))
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
    async fn authenticate(&self, token: &Token<'_>) -> Result<Authentication> {
        match self {
            #[cfg(feature = "kubernetes")]
            Self::Kubernetes(authenticator) => authenticator.authenticate(token).await,
            #[cfg(feature = "jwks")]
            Self::Jwt(authenticator) => authenticator.authenticate(token).await,
        }
    }

    fn idp_id(&self) -> Option<&str> {
        match self {
            #[cfg(feature = "kubernetes")]
            Self::Kubernetes(authenticator) => authenticator.idp_id(),
            #[cfg(feature = "jwks")]
            Self::Jwt(authenticator) => authenticator.idp_id(),
        }
    }

    fn can_handle_token(&self, token: &Token<'_>) -> bool {
        match self {
            #[cfg(feature = "kubernetes")]
            Self::Kubernetes(authenticator) => authenticator.can_handle_token(token),
            #[cfg(feature = "jwks")]
            Self::Jwt(authenticator) => authenticator.can_handle_token(token),
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
