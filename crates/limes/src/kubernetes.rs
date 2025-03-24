//! Authenticate kubernetes tokens using the Kubernetes `TokenReview` API.

use crate::introspect::IntrospectionResult;
use crate::{
    error::{Error, Result},
    Authentication, Authenticator, Subject,
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
/// If you don't want to validate the audience, pass an empty slice.
/// When using [`AuthenticatorChain`](`crate::AuthenticatorChain`), it is highly recommended to set
/// an audience as the [`KubernetesAuthenticator`] would otherwise always return true for
/// [`KubernetesAuthenticator::can_handle_token()`].
/// Many deployments can use `https://kubernetes.default.svc` as the audience.
///
///
/// **Field Mappings**:
/// - `name`: `user.username`
/// - `email`: `user.extra.email`
/// - `subject`: `user.uid`
/// - `claims`: `user.extra`
/// - `principal_type`: Is always `Application` currently.
///
pub struct KubernetesAuthenticator {
    idp_id: Option<String>,
    client: kube::client::Client,
    audiences: Vec<String>,
    enable_long_lived_service_tokens: bool,
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
            enable_long_lived_service_tokens: false,
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
            enable_long_lived_service_tokens: false,
        })
    }

    /// Enable long-lived service tokens.
    ///
    /// If enabled, the authenticator will accept long-lived service tokens.
    ///
    /// Be aware that their use is discouraged as they are not automatically rotated.
    pub fn set_enable_long_lived_service_tokens(&mut self, val: bool) {
        self.enable_long_lived_service_tokens = val;
    }

    async fn get_client() -> Result<kube::client::Client> {
        kube::client::Client::try_default()
            .await
            .map_err(Error::KubernetesConfigError)
    }
}

impl Authenticator for KubernetesAuthenticator {
    async fn authenticate(&self, token: &str) -> Result<Authentication> {
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

        parse_review_status(review.status, &self.audiences, self.idp_id.as_deref())
    }

    fn can_handle_token(&self, token: &str, introspection_result: &IntrospectionResult) -> bool {
        if token.is_empty() {
            return false;
        }

        match introspection_result {
            IntrospectionResult::Opaque => false,
            IntrospectionResult::JWTBearer { aud, .. } => {
                self.audiences.is_empty() || self.audiences.iter().any(|a| aud.contains(a))
            }
            IntrospectionResult::KubernetesLongLivedJWT { .. } => {
                self.enable_long_lived_service_tokens
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
) -> Result<Authentication> {
    let token_review: TokenReviewStatus = token_review
        .ok_or_else(|| Error::unauthenticated("Kubernetes TokenReview returned no status"))?;

    // Validate Audience
    validate_audience(audiences, &token_review.audiences.unwrap_or_default())?;

    // Raise k8s error
    if let Some(error) = token_review.error {
        return Err(Error::unauthenticated(format!(
            "Kubernetes TokenReview failed: {error}"
        )));
    }

    // Parse claims
    let user_info: UserInfo = token_review
        .user
        .ok_or_else(|| Error::unauthenticated("No user in kubernetes token review"))?;
    let uid = user_info
        .uid
        .ok_or_else(|| Error::unauthenticated("No UID in kubernetes token review"))?;

    let subject = Subject::new(idp_id.map(ToString::to_string), uid);

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
        .build())
}

impl std::fmt::Debug for KubernetesAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut r = f.debug_struct("KubernetesAuthenticator");
        let r = r.field("idp_id", &self.idp_id);
        r.field("audiences", &self.audiences)
            .field("client", &"kube::client::Client")
            .field(
                "enable_long_lived_service_tokens",
                &self.enable_long_lived_service_tokens,
            )
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
        )
        .unwrap_err();

        // Valid audience
        let payload = parse_review_status(
            Some(token_review_status),
            &["https://kubernetes.default.svc".to_string()],
            Some("my-k8s-cluster"),
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
    }
}
