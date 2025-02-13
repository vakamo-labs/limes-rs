use crate::{error::Result, introspect::IntrospectionResult, Subject};
use core::{future::Future, marker::Sync};
pub(crate) use jsonwebtoken::Header;
use std::fmt::Debug;
use typed_builder::TypedBuilder;

pub trait Authenticator
where
    Self: Send + Sync + Clone,
{
    /// Authenticate a token. This must validate the tokens signature and claims.
    /// For opaque tokens, handlers may connect to the `IdP` to validate the token.
    ///
    /// # Errors
    /// - Token is not valid.
    fn authenticate(&self, token: &str) -> impl Future<Output = Result<Authentication>> + Send;

    /// Check if the authenticator can handle the token.
    /// This is used in the [`AuthenticatorChain`](`crate::AuthenticatorChain`) to determine which authenticator to use.
    /// This should be a quick check that doesn't involve cryptographic operations.
    fn can_handle_token(&self, token: &str, introspection_result: &IntrospectionResult) -> bool;

    /// Returns an id that uniquely identifies the `IdP` this authenticator is for.
    fn idp_id(&self) -> Option<&String>;
}

#[derive(Debug, PartialEq, Eq, Clone, TypedBuilder)]
/// Information about a successful authentication.
/// Use [`Authentication::subject()`] for a unique identifier of the user.
pub struct Authentication {
    // --------- Raw token data ---------
    /// Header of the provided token if any.
    /// Not all tokens have a header. JWTs do, but opaque tokens don't.
    token_header: Option<Header>,
    /// Claims of the provided token provided as a json Value.
    /// This struct also contains some popular claims as strongly typed fields,
    /// which should be preferred over accessing the claims directly.
    claims: serde_json::Value,
    /// Subject of the token - consists of a unique identifier of the idp
    /// and the id of the subject in the idp.
    subject: Subject,
    /// Full name of the user intended for human use.
    name: Option<String>,
    /// Email of the user.
    email: Option<String>,
    /// The type of the principal making the request.
    principal_type: Option<PrincipalType>,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
/// Type of the principal making the request.
pub enum PrincipalType {
    Human,
    Application,
}

impl Authentication {
    #[must_use]
    /// Get the token header if it exists.
    pub fn token_header(&self) -> Option<&Header> {
        self.token_header.as_ref()
    }

    #[must_use]
    /// Get the content of a claim from the token.
    /// If the claim does not exist, this will return None.
    pub fn claims(&self, key: &str) -> Option<&serde_json::Value> {
        self.claims.get(key)
    }

    #[must_use]
    /// Get the subject of the user.
    /// Use this to uniquely identify the user.
    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    #[must_use]
    /// Get the full name of the user.
    /// This is intended for human use. It is not guaranteed to be unique and may change.
    pub fn full_name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[must_use]
    /// Get the type of the principal making the request.
    /// This is estimated by the [`Authenticator`] implementation and may not be accurate in all cases.
    pub fn principal_type(&self) -> Option<PrincipalType> {
        self.principal_type
    }

    #[must_use]
    /// Get the email of the user.
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
}
