use std::sync::OnceLock;

use crate::introspect::{IntrospectionResult, introspect};

/// A bearer token as the client sent it.
///
/// The token reads its [`introspection`](Self::introspection) on first use and keeps it, so
/// the authenticators of an [`AuthenticatorChain`](crate::AuthenticatorChain) share one
/// parse. `Debug` omits the token itself.
pub struct Token<'a> {
    raw: &'a str,
    introspection: OnceLock<IntrospectionResult>,
}

impl<'a> Token<'a> {
    #[must_use]
    pub fn new(raw: &'a str) -> Self {
        Self {
            raw,
            introspection: OnceLock::new(),
        }
    }

    /// The token as the client sent it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.raw
    }

    /// What the token says about its format, issuer and audience, read without verifying it.
    #[must_use]
    pub fn introspection(&self) -> &IntrospectionResult {
        self.introspection.get_or_init(|| introspect(self.raw))
    }
}

impl<'a> From<&'a str> for Token<'a> {
    fn from(raw: &'a str) -> Self {
        Self::new(raw)
    }
}

impl std::fmt::Debug for Token<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("introspection", &self.introspection.get())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_omits_the_token() {
        let token = Token::new("secret-api-key");
        assert_eq!(token.introspection(), &IntrospectionResult::Unknown);
        assert_eq!(
            format!("{token:?}"),
            "Token { introspection: Some(Unknown), .. }"
        );
    }

    /// Futures that hold a `&Token` across an `.await` are `Send` only if `Token` is `Sync`.
    #[test]
    fn test_token_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Token<'static>>();
    }

    #[test]
    fn test_introspection_is_computed_once() {
        let token = Token::new("not-a-jwt");
        assert!(std::ptr::eq(token.introspection(), token.introspection()));
    }
}
