use crate::{
    error::{Error, Result},
    introspect::{introspect, IntrospectionResult},
    Authentication, Authenticator,
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

    fn idp_id(&self) -> Option<&String> {
        self.authenticators[0].idp_id()
    }

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
