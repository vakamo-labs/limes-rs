use crate::{Identity, Subject, error::Result, introspect::IntrospectionResult};
use core::{future::Future, marker::Sync};
use std::collections::HashSet;
use std::fmt::Debug;
use typed_builder::TypedBuilder;

pub trait Authenticator
where
    Self: Send + Sync + Clone,
{
    /// Authenticate a token. This must validate the tokens signature and claims.
    /// For opaque tokens, handlers may connect to the identity provider to validate the token.
    ///
    /// `introspection` must be the result of [`introspect`](`crate::introspect::introspect`)
    /// for `token`. The caller computes it once and passes it in; the tower layer does this
    /// for you. [`AuthenticatorChain`](`crate::AuthenticatorChain`) forwards it to the
    /// authenticator it selects.
    ///
    /// # Errors
    /// - Token is not valid.
    fn authenticate(
        &self,
        token: &str,
        introspection: &IntrospectionResult,
    ) -> impl Future<Output = Result<Authentication>> + Send;

    /// Check if the authenticator can handle the token.
    /// This is used in the [`AuthenticatorChain`](`crate::AuthenticatorChain`) to determine which authenticator to use.
    /// This should be a quick check that doesn't involve cryptographic operations.
    fn can_handle_token(&self, token: &str, introspection_result: &IntrospectionResult) -> bool;

    /// An id that uniquely identifies the identity provider of this authenticator.
    fn idp_id(&self) -> Option<&str>;

    /// Collects the IdP identifier(s) associated with this authenticator.
    ///
    /// By default this yields a single-element vector containing the result of `self.idp_id()`
    /// for a standalone authenticator. Implementations that represent a chain of
    /// authenticators should return one element per child authenticator in chain order.
    ///
    /// # Returns
    ///
    /// A `Vec<Option<&str>>` where each element is the IdP identifier for one authenticator in the chain,
    /// or `None` when an authenticator does not have an IdP identifier.
    fn idp_ids(&self) -> Vec<Option<&str>> {
        vec![self.idp_id()]
    }
}

/// Information about a successful authentication.
/// Use [`Authentication::subject()`] for a unique identifier of the user.
#[derive(Debug, PartialEq, Eq, Clone, TypedBuilder)]
pub struct Authentication {
    /// Subject of the token: the id of the identity provider and the id of the subject there.
    subject: Subject,
    #[builder(default)]
    audiences: HashSet<String>,
    #[builder(setter(into))]
    identity: Identity,
}

impl Authentication {
    /// Get the subject of the user.
    /// Use this to uniquely identify the user.
    #[must_use]
    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    /// The audiences of the token: every `aud` of a JWT, or for a Kubernetes token the
    /// audiences the `TokenReview` validated.
    #[must_use]
    pub fn audiences(&self) -> &HashSet<String> {
        &self.audiences
    }

    /// What the identity provider states about the subject: the claims of the token, or the
    /// user of a Kubernetes `TokenReview`.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Whether the identity satisfies `rule`.
    ///
    /// The rule reads the claims of [`Identity::Claims`] the way a required-claim rule of the
    /// JWKS authenticator does. For [`Identity::Kubernetes`] it reads `user.extra`, where every
    /// key holds a list of strings.
    #[must_use]
    pub fn satisfies(&self, rule: &crate::ClaimRule) -> bool {
        match &self.identity {
            Identity::Claims(claims) => rule.matches(claims.as_json()),
            Identity::Kubernetes(user) => rule.matches(&user.extra_as_json()),
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{KubernetesUser, Subject, VerifiedClaims};

    fn auth_with_claims(claims: serde_json::Value) -> Authentication {
        Authentication::builder()
            .subject(Subject::new(None, "sub".to_string()))
            .identity(VerifiedClaims::try_from(claims).unwrap())
            .build()
    }

    #[test]
    fn test_satisfies_reads_nested_and_uri_named_claims() {
        let auth = auth_with_claims(serde_json::json!({
            "realm_access": { "roles": ["engine", "reader"] },
            "https://example.com/tier": "gold",
        }));

        let nested = crate::ClaimRule::any_of("realm_access.roles", ["engine"]).unwrap();
        assert!(auth.satisfies(&nested));
        let nested_miss = crate::ClaimRule::any_of("realm_access.roles", ["admin"]).unwrap();
        assert!(!auth.satisfies(&nested_miss));

        let uri = crate::ClaimRule::any_of("https://example.com/tier", ["gold"]).unwrap();
        assert!(auth.satisfies(&uri));
    }

    #[test]
    fn test_satisfies_fails_on_a_missing_claim() {
        let auth = auth_with_claims(serde_json::json!({ "sub": "x" }));
        let rule = crate::ClaimRule::any_of("azp", ["engine"]).unwrap();
        assert!(!auth.satisfies(&rule));
        let absent = crate::ClaimRule::exists("azp", false).unwrap();
        assert!(auth.satisfies(&absent));
    }

    #[test]
    fn test_satisfies_reads_the_extra_of_a_kubernetes_user() {
        let user = KubernetesUser::builder()
            .username("system:serviceaccount:ns:sa")
            .groups(vec!["system:serviceaccounts".to_string()])
            .extra(BTreeMap::from([(
                "team".to_string(),
                vec!["data".to_string()],
            )]))
            .build();
        let auth = Authentication::builder()
            .subject(Subject::new(
                Some("kubernetes".to_string()),
                "uid".to_string(),
            ))
            .identity(user)
            .build();

        assert!(auth.satisfies(&crate::ClaimRule::any_of("team", ["data"]).unwrap()));
        // `groups` is a field of the user, not a key of `extra`.
        assert!(auth.satisfies(&crate::ClaimRule::exists("groups", false).unwrap()));
    }
}
