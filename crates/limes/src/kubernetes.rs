//! Authenticate kubernetes tokens using the Kubernetes `TokenReview` API.

use crate::introspect::IntrospectionResult;
use crate::{
    Authentication, Authenticator, Subject,
    error::{Error, Result},
};
use k8s_openapi::api::authentication::v1::{
    TokenReview, TokenReviewSpec, TokenReviewStatus, UserInfo,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::PostParams;

#[derive(Clone)]
/// Authenticator for Kubernetes.
///
/// Validates tokens using the Kubernetes `TokenReview` API.
/// Ensure that the service account running the authenticator has the necessary permissions.
///
/// If no `client` is specified, the default client on the system will be used.
///
/// If you don't want to validate the audience or the issuer, pass an empty slice.
/// When using [`AuthenticatorChain`](`crate::AuthenticatorChain`), it is highly recommended to set
/// an audience or issuer as the [`KubernetesAuthenticator`] would otherwise always return true for
/// [`KubernetesAuthenticator::can_handle_token()`].
/// Many deployments can use `https://kubernetes.default.svc` as the audience.
///
/// If an issuer is set, the provided token must be a `JWTBearer` token with an issuer that matches.
/// Kubernetes `TokenReviewStatus` API does not provide information about the issuer.
/// We recommend using `audiences` instead of `issuers` for most Kubernetes setups.
///
///
/// **Field Mappings**:
/// - `name`: `user.username`
/// - `email`: `user.extra.email`
/// - `subject`: `user.uid` by default, or `user.username` when the subject
///   source is set to [`KubernetesSubjectSource::Username`] via
///   [`set_subject_source`](`KubernetesAuthenticator::set_subject_source`).
/// - `claims`: `user.extra`
/// - `principal_type`: Is always `Application` currently.
///
pub struct KubernetesAuthenticator {
    idp_id: Option<String>,
    client: kube::client::Client,
    audiences: Vec<String>,
    issuers: Vec<String>,
    subject_source: KubernetesSubjectSource,
}

/// Which field of the Kubernetes `TokenReview` response is used as the
/// authenticated user's subject (the provider-local part of the identity).
///
/// The default is [`KubernetesSubjectSource::Uid`], which preserves historical
/// behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum KubernetesSubjectSource {
    /// Use `user.uid` — the service account's Kubernetes UID. Unique and
    /// immutable within a cluster, but assigned by Kubernetes, so the same
    /// service account has a different UID in each cluster.
    #[default]
    Uid,
    /// Use `user.username` — for service account tokens this is
    /// `system:serviceaccount:<namespace>:<name>`. Stable across clusters,
    /// which makes it suitable for pre-provisioning identities.
    Username,
}

impl KubernetesAuthenticator {
    /// Create a new [`KubernetesAuthenticator`].
    ///
    /// This will use the default Kubernetes client, inferred from the environment.
    ///
    /// # Arguments
    /// - `idp_id`: The unique identifier of the IdP this authenticator is for.
    /// - `audiences`: The audiences to validate the token against. If empty, no audience validation is done.
    ///
    /// # Errors
    /// - `KubernetesConfigError`: If neither the local kubeconfig nor the in-cluster environment can be loaded
    pub async fn try_new_with_default_client(
        idp_id: Option<&str>,
        audiences: Vec<String>,
    ) -> Result<Self> {
        Ok(Self {
            idp_id: idp_id.map(ToString::to_string),
            client: Self::get_client().await?,
            audiences,
            issuers: vec![],
            subject_source: KubernetesSubjectSource::default(),
        })
    }

    /// Create a new [`KubernetesAuthenticator`].
    ///
    /// # Arguments
    /// - `idp_id`: The unique identifier of the IdP this authenticator is for.
    /// - `audiences`: The audiences to validate the token against. If empty, no audience validation is done.
    /// - `client`: The Kubernetes client to use. If `None`, the default client will be used.
    ///
    /// # Errors
    /// - `KubernetesConfigError`: If neither the local kubeconfig nor the in-cluster environment can be loaded
    pub fn new_with_client(
        idp_id: Option<&str>,
        audiences: Vec<String>,
        client: kube::client::Client,
    ) -> Result<Self> {
        Ok(Self {
            idp_id: idp_id.map(ToString::to_string),
            client,
            audiences,
            issuers: vec![],
            subject_source: KubernetesSubjectSource::default(),
        })
    }

    /// Set the accepted issuers for the authenticator.
    /// If not set, the authenticator will accept any issuer.
    pub fn set_issuers(&mut self, issuers: Vec<String>) {
        self.issuers = issuers;
    }

    /// Set which `TokenReview` field is used as the subject.
    /// Defaults to [`KubernetesSubjectSource::Uid`].
    pub fn set_subject_source(&mut self, subject_source: KubernetesSubjectSource) {
        self.subject_source = subject_source;
    }

    async fn get_client() -> Result<kube::client::Client> {
        kube::client::Client::try_default()
            .await
            .map_err(Error::KubernetesConfigError)
    }
}

impl Authenticator for KubernetesAuthenticator {
    async fn authenticate(
        &self,
        token: &str,
        introspection: &IntrospectionResult,
    ) -> Result<Authentication> {
        // If an issuer is set, the token must be JWT and the issuer must match
        if !self.issuers.is_empty() {
            match introspection {
                IntrospectionResult::Unknown => {
                    return Err(Error::unauthenticated(
                        "Expected JWT token for Kubernetes Authenticator as issuer is set",
                    ));
                }
                IntrospectionResult::JWTBearer { iss, .. } => {
                    if !self.issuers.iter().any(|i| iss.contains(i)) {
                        return Err(Error::IssuerMismatch {
                            expected: self.issuers.clone(),
                            actual: iss.iter().cloned().collect(),
                        });
                    }
                }
            }
        }

        let api = kube::api::Api::all(self.client.clone());
        let review = api
            .create(
                &PostParams::default(),
                &TokenReview {
                    metadata: ObjectMeta::default(),
                    spec: TokenReviewSpec {
                        audiences: Some(self.audiences.clone()),
                        token: Some(token.to_string()),
                    },
                    status: None,
                },
            )
            .await
            .map_err(Error::KubernetesTokenReviewError)?;

        parse_review_status(
            review.status,
            &self.audiences,
            self.idp_id.as_deref(),
            self.subject_source,
        )
    }

    fn can_handle_token(&self, token: &str, introspection_result: &IntrospectionResult) -> bool {
        if token.is_empty() {
            return false;
        }

        match introspection_result {
            IntrospectionResult::Unknown => false,
            IntrospectionResult::JWTBearer {
                iss,
                aud,
                header: _,
            } => {
                (self.issuers.is_empty() || self.issuers.iter().any(|i| iss.contains(i)))
                    && (self.audiences.is_empty() || self.audiences.iter().any(|a| aud.contains(a)))
            }
        }
    }

    fn idp_id(&self) -> Option<&String> {
        self.idp_id.as_ref()
    }
}

fn parse_review_status(
    token_review: Option<TokenReviewStatus>,
    audiences: &[String],
    idp_id: Option<&str>,
    subject_source: KubernetesSubjectSource,
) -> Result<Authentication> {
    let token_review: TokenReviewStatus = token_review
        .ok_or_else(|| Error::unauthenticated("Kubernetes TokenReview returned no status"))?;

    // Raise k8s error
    if let Some(error) = token_review.error {
        return Err(Error::unauthenticated(format!(
            "Kubernetes TokenReview failed: {error}"
        )));
    }

    // The token is only valid if Kubernetes explicitly marked it as authenticated.
    // Don't rely on the presence of `user` alone to infer this.
    if token_review.authenticated != Some(true) {
        return Err(Error::unauthenticated(
            "Kubernetes TokenReview did not authenticate the token",
        ));
    }

    // Validate Audience
    let actual_audiences = token_review.audiences.unwrap_or_default();
    validate_audience(audiences, &actual_audiences)?;

    // Parse claims
    let user_info: UserInfo = token_review
        .user
        .ok_or_else(|| Error::unauthenticated("No user in kubernetes token review"))?;
    let subject_in_idp = match subject_source {
        KubernetesSubjectSource::Uid => user_info
            .uid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::unauthenticated("No UID in kubernetes token review"))?
            .to_string(),
        KubernetesSubjectSource::Username => user_info
            .username
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::unauthenticated("No username in kubernetes token review"))?
            .to_string(),
    };

    let subject = Subject::new(idp_id.map(ToString::to_string), subject_in_idp);

    let claims = serde_json::to_value(user_info.extra).unwrap_or_default();
    Ok(Authentication::builder()
        .name(user_info.username)
        .email(
            claims
                .get("email")
                .and_then(|v| v.as_str().map(ToString::to_string)),
        )
        .subject(subject)
        .principal_type(Some(crate::PrincipalType::Application))
        .token_header(None)
        .claims(claims)
        .audiences(actual_audiences.into_iter().collect())
        .build())
}

impl std::fmt::Debug for KubernetesAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut r = f.debug_struct("KubernetesAuthenticator");
        let r = r.field("idp_id", &self.idp_id);
        r.field("audiences", &self.audiences)
            .field("client", &"kube::client::Client")
            .field("issuers", &self.issuers)
            .field("subject_source", &self.subject_source)
            .finish()
    }
}

fn validate_audience(expected: &[String], received: &[String]) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }

    if !expected.iter().any(|expected| received.contains(expected)) {
        return Err(Error::AudienceMismatch {
            expected: expected.to_vec(),
            actual: received.to_vec(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_parse_review_status() {
        let status = serde_json::json!({
        "audiences": [
            "https://kubernetes.default.svc"
        ],
        "authenticated": true,
        "user": {
            "extra": {
                "authentication.kubernetes.io/credential-id": [
                    "JTI=99f5aae5-3f36-4521-ad75-cb2bab21459a"
                ],
                "authentication.kubernetes.io/node-name": [
                    "ip-10-16-7-50.eu-central-1.compute.internal"
                ],
                "authentication.kubernetes.io/node-uid": [
                    "8de0d94d-b5fd-4c3a-a6e8-1eccf22a7b31"
                ],
                "authentication.kubernetes.io/pod-name": [
                    "my-pod"
                ],
                "authentication.kubernetes.io/pod-uid": [
                    "e9518537-b347-4264-a6bb-bc82db55ae65"
                ]
            },
            "groups": [
                "system:serviceaccounts",
                "system:serviceaccounts:my-namespace",
                "system:authenticated"
            ],
            "uid": "0e79c2ec-32eb-4a46-ab9b-f075fbbfbd43",
            "username": "system:serviceaccount:my-namespace:my-serviceaccount"
        }});
        let token_review_status: TokenReviewStatus = serde_json::from_value(status).unwrap();

        // Invalid audience
        parse_review_status(
            Some(token_review_status.clone()),
            &["nonexistant-audience".to_string()],
            Some("kubernetes"),
            KubernetesSubjectSource::Uid,
        )
        .unwrap_err();

        // Valid audience
        let payload = parse_review_status(
            Some(token_review_status),
            &["https://kubernetes.default.svc".to_string()],
            Some("my-k8s-cluster"),
            KubernetesSubjectSource::Uid,
        )
        .unwrap();

        assert_eq!(
            payload.full_name(),
            Some("system:serviceaccount:my-namespace:my-serviceaccount")
        );
        assert_eq!(
            payload.subject().subject_in_idp(),
            "0e79c2ec-32eb-4a46-ab9b-f075fbbfbd43"
        );
        assert_eq!(
            payload.subject().idp_id(),
            Some("my-k8s-cluster".to_string()).as_ref()
        );
        assert_eq!(
            payload.audiences(),
            &HashSet::from(["https://kubernetes.default.svc".to_string()])
        );
    }

    #[test]
    fn test_parse_review_status_rejects_unauthenticated() {
        // `authenticated: false` must be rejected even when user info is present.
        let status = serde_json::json!({
            "authenticated": false,
            "user": {
                "uid": "0e79c2ec-32eb-4a46-ab9b-f075fbbfbd43",
                "username": "system:serviceaccount:my-namespace:my-serviceaccount"
            }
        });
        let token_review_status: TokenReviewStatus = serde_json::from_value(status).unwrap();
        parse_review_status(
            Some(token_review_status),
            &[],
            Some("kubernetes"),
            KubernetesSubjectSource::Uid,
        )
        .unwrap_err();
    }

    #[test]
    fn test_parse_review_status_username_subject_source() {
        let status = serde_json::json!({
            "audiences": ["https://kubernetes.default.svc"],
            "authenticated": true,
            "user": {
                "uid": "0e79c2ec-32eb-4a46-ab9b-f075fbbfbd43",
                "username": "system:serviceaccount:my-namespace:my-serviceaccount"
            }
        });
        let token_review_status: TokenReviewStatus = serde_json::from_value(status).unwrap();

        let payload = parse_review_status(
            Some(token_review_status),
            &["https://kubernetes.default.svc".to_string()],
            Some("kubernetes"),
            KubernetesSubjectSource::Username,
        )
        .unwrap();

        // Subject is the username; display name is unaffected.
        assert_eq!(
            payload.subject().subject_in_idp(),
            "system:serviceaccount:my-namespace:my-serviceaccount"
        );
        assert_eq!(
            payload.full_name(),
            Some("system:serviceaccount:my-namespace:my-serviceaccount")
        );
    }

    #[test]
    fn test_parse_review_status_username_source_missing_username() {
        let status = serde_json::json!({
            "authenticated": true,
            "user": { "uid": "0e79c2ec-32eb-4a46-ab9b-f075fbbfbd43" }
        });
        let token_review_status: TokenReviewStatus = serde_json::from_value(status).unwrap();
        parse_review_status(
            Some(token_review_status),
            &[],
            Some("kubernetes"),
            KubernetesSubjectSource::Username,
        )
        .unwrap_err();
    }

    #[test]
    fn test_parse_review_status_rejects_empty_subject() {
        // A present-but-empty subject field must be rejected, not turned into
        // an empty subject (`kubernetes~`).
        for (source, user) in [
            (
                KubernetesSubjectSource::Uid,
                serde_json::json!({ "uid": "   ", "username": "system:serviceaccount:ns:sa" }),
            ),
            (
                KubernetesSubjectSource::Username,
                serde_json::json!({ "uid": "0e79c2ec", "username": "" }),
            ),
        ] {
            let status = serde_json::json!({ "authenticated": true, "user": user });
            let token_review_status: TokenReviewStatus = serde_json::from_value(status).unwrap();
            parse_review_status(Some(token_review_status), &[], Some("kubernetes"), source)
                .unwrap_err();
        }
    }

    #[test]
    fn test_parse_review_status_trims_subject() {
        // Padded values are stored trimmed (e.g. " abc " -> "abc").
        for (source, expected, user) in [
            (
                KubernetesSubjectSource::Uid,
                "abc",
                serde_json::json!({ "uid": "  abc  ", "username": "system:serviceaccount:ns:sa" }),
            ),
            (
                KubernetesSubjectSource::Username,
                "system:serviceaccount:ns:sa",
                serde_json::json!({ "uid": "0e79c2ec", "username": "  system:serviceaccount:ns:sa  " }),
            ),
        ] {
            let status = serde_json::json!({ "authenticated": true, "user": user });
            let token_review_status: TokenReviewStatus = serde_json::from_value(status).unwrap();
            let payload =
                parse_review_status(Some(token_review_status), &[], Some("kubernetes"), source)
                    .unwrap();
            assert_eq!(payload.subject().subject_in_idp(), expected);
        }
    }
}
