//! Authenticate kubernetes tokens using the Kubernetes `TokenReview` API.

use crate::introspect::IntrospectionResult;
use crate::{
    Authentication, Authenticator, KubernetesUser, Subject, Token,
    error::{Error, Result},
};
use k8s_openapi::api::authentication::v1::{
    TokenReview, TokenReviewSpec, TokenReviewStatus, UserInfo,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::PostParams;
use std::time::{Duration, SystemTime};

/// How long a `TokenReview` request may take.
const TOKEN_REVIEW_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
/// Authenticator for Kubernetes.
///
/// Validates tokens using the Kubernetes `TokenReview` API.
/// Ensure that the service account running the authenticator has the necessary permissions.
///
/// If no `client` is specified, the default client on the system will be used.
///
/// A `TokenReview` that does not finish within 10 seconds fails with
/// [`Error::KubernetesTokenReviewError`] of kind [`Unavailable`](crate::error::ErrorKind::Unavailable),
/// also if the client sets longer timeouts.
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
/// The [`Authentication`] carries the user of the `TokenReview` as
/// [`Identity::Kubernetes`](crate::Identity::Kubernetes).
/// Its subject is `user.uid` by default, or `user.username` when the subject source is set to
/// [`KubernetesSubjectSource::Username`] via
/// [`set_subject_source`](`KubernetesAuthenticator::set_subject_source`). Claim rules read
/// `user.extra`. It is [valid until](Authentication::valid_until) the `exp` of the token, if
/// the token is a JWT. A token without `exp`, such as a Secret-based service account token, has
/// no end, so a cache keeps it for its whole `time_to_live`. For a JWT whose payload limes
/// cannot read, the authentication is valid until the time of the review, so a cache does not
/// keep it.
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
/// The default is [`KubernetesSubjectSource::Uid`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
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
    /// - `idp_id`: The unique identifier of the identity provider this authenticator is for. An empty id is `None`.
    /// - `audiences`: The audiences to validate the token against. If empty, no audience validation is done.
    ///
    /// # Errors
    /// - `KubernetesConfigError`: If neither the local kubeconfig nor the in-cluster environment can be loaded
    pub async fn try_new_with_default_client(
        idp_id: Option<&str>,
        audiences: Vec<String>,
    ) -> Result<Self> {
        Ok(Self {
            idp_id: idp_id.filter(|id| !id.is_empty()).map(ToString::to_string),
            client: Self::get_client().await?,
            audiences,
            issuers: vec![],
            subject_source: KubernetesSubjectSource::default(),
        })
    }

    /// Create a new [`KubernetesAuthenticator`].
    ///
    /// # Arguments
    /// - `idp_id`: The unique identifier of the identity provider this authenticator is for. An empty id is `None`.
    /// - `audiences`: The audiences to validate the token against. If empty, no audience validation is done.
    /// - `client`: The Kubernetes client to use.
    ///
    /// # Errors
    /// Does not fail; it returns a `Result` like
    /// [`try_new_with_default_client`](Self::try_new_with_default_client).
    pub fn new_with_client(
        idp_id: Option<&str>,
        audiences: Vec<String>,
        client: kube::client::Client,
    ) -> Result<Self> {
        Ok(Self {
            idp_id: idp_id.filter(|id| !id.is_empty()).map(ToString::to_string),
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
    async fn authenticate(&self, token: &Token<'_>) -> Result<Authentication> {
        // The API server answers an empty token with 400, which reads as a problem of this
        // server.
        if token.as_str().is_empty() {
            return Err(Error::unauthenticated("Token is empty"));
        }

        // If an issuer is set, the token must be JWT and the issuer must match
        if !self.issuers.is_empty() {
            match token.introspection() {
                IntrospectionResult::Unknown => {
                    return Err(Error::unauthenticated(
                        "Expected JWT token for Kubernetes Authenticator as issuer is set",
                    ));
                }
                IntrospectionResult::JWTBearer { iss, .. } => {
                    // The token is not verified yet, so this is not a `TokenRejected`.
                    if !self.issuers.iter().any(|i| iss.contains(i)) {
                        return Err(Error::unauthenticated(
                            "Token issuer is not accepted by the Kubernetes Authenticator",
                        ));
                    }
                }
            }
        }

        let api = kube::api::Api::all(self.client.clone());
        let params = PostParams::default();
        let request = TokenReview {
            metadata: ObjectMeta::default(),
            spec: TokenReviewSpec {
                audiences: Some(self.audiences.clone()),
                // An `Option` up to Kubernetes 1.35, a `String` from 1.36.
                token: token.as_str().to_owned().into(),
            },
            status: None,
        };
        // kube's default client has no read timeout, so an API server that accepts the
        // connection and never answers would hold the request forever.
        let review = tokio::time::timeout(TOKEN_REVIEW_TIMEOUT, api.create(&params, &request))
            .await
            .map_err(|_| {
                Error::KubernetesTokenReviewError(kube::Error::Service(Box::new(
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "no answer within {} seconds",
                            TOKEN_REVIEW_TIMEOUT.as_secs()
                        ),
                    ),
                )))
            })?
            .map_err(Error::KubernetesTokenReviewError)?;

        parse_review_status(
            review.status,
            &self.audiences,
            self.idp_id.as_deref(),
            self.subject_source,
            token_expiry(token.as_str()),
        )
    }

    fn can_handle_token(&self, token: &Token<'_>) -> bool {
        if token.as_str().is_empty() {
            return false;
        }

        match token.introspection() {
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

    fn idp_id(&self) -> Option<&str> {
        self.idp_id.as_deref()
    }
}

/// Decodes the payload of a JWT as leniently as the API server does: base64 may keep trailing
/// bits or padding, and the header is not read.
const JWT_PART: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    base64::engine::GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
);

/// Until when a token is valid: the `exp` of a JWT, which the API server verified. Read from
/// the payload on its own, apart from the claims that route the token, so an `exp` of any shape
/// leaves routing alone. `None` for a token that is no JWT, or a JWT without `exp`.
///
/// The API server checks service account tokens with go-jose, which reads exactly `exp`, and
/// tokens of OpenID Connect providers with go-oidc, which reads the last key that equals `exp`
/// ignoring case. The earliest of all such keys is never later than either.
///
/// The API server also accepts payloads and `exp` values this cannot read, such as numbers too
/// large for a float, or a number in a string. Such a token is valid until now, so a cache does
/// not store it.
fn token_expiry(token: &str) -> Option<SystemTime> {
    use base64::Engine as _;
    let mut parts = token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let claims = JWT_PART
        .decode(payload)
        .ok()
        .and_then(|payload| serde_json::from_slice::<serde_json::Value>(&payload).ok());
    let Some(claims) = claims.as_ref().and_then(serde_json::Value::as_object) else {
        return Some(SystemTime::now());
    };
    let mut earliest: Option<SystemTime> = None;
    for (_, exp) in claims
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("exp"))
    {
        // go-oidc also reads a number in a string.
        let Some(exp) = crate::identity::numeric_date(exp) else {
            return Some(SystemTime::now());
        };
        earliest = Some(earliest.map_or(exp, |earliest| earliest.min(exp)));
    }
    earliest
}

fn parse_review_status(
    token_review: Option<TokenReviewStatus>,
    audiences: &[String],
    idp_id: Option<&str>,
    subject_source: KubernetesSubjectSource,
    valid_until: Option<SystemTime>,
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
    let user = KubernetesUser::builder()
        .username_opt(user_info.username)
        .uid_opt(user_info.uid)
        .groups(user_info.groups.unwrap_or_default())
        .extra(user_info.extra.unwrap_or_default())
        .build();

    Ok(Authentication::builder()
        .subject(subject)
        .audiences(actual_audiences.into_iter().collect())
        .identity(user)
        .valid_until_opt(valid_until)
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
        return Err(Error::rejected(
            crate::error::RejectionReason::AudienceMismatch,
        ));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error::ErrorKind;
    use std::collections::HashSet;

    /// An authenticator whose API server answers every request with `status`, or cannot be
    /// reached if `status` is `None`.
    fn authenticator_with_api(status: Option<u16>) -> KubernetesAuthenticator {
        let service = tower::service_fn(move |_: http::Request<kube::client::Body>| async move {
            let status = status.ok_or_else(|| std::io::Error::other("connection refused"))?;
            let body = serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure", "code": status
            });
            Ok::<_, std::io::Error>(
                http::Response::builder()
                    .status(status)
                    .body(http_body_util::Full::new(bytes::Bytes::from(
                        body.to_string(),
                    )))
                    .unwrap(),
            )
        });
        KubernetesAuthenticator::new_with_client(
            None,
            vec![],
            kube::client::Client::new(service, "default"),
        )
        .unwrap()
    }

    /// A token with the given payload, not signed.
    fn unsigned_jwt(payload: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"k1"}"#),
            URL_SAFE_NO_PAD.encode(payload)
        )
    }

    /// An authenticator whose API server authenticates every token.
    fn accepting_authenticator() -> KubernetesAuthenticator {
        let service = tower::service_fn(|_: http::Request<kube::client::Body>| async move {
            let body = serde_json::json!({
                "kind": "TokenReview",
                "apiVersion": "authentication.k8s.io/v1",
                "spec": {},
                "status": { "authenticated": true, "user": { "uid": "u-1" } }
            });
            Ok::<_, std::io::Error>(
                http::Response::builder()
                    .status(201)
                    .body(http_body_util::Full::new(bytes::Bytes::from(
                        body.to_string(),
                    )))
                    .unwrap(),
            )
        });
        KubernetesAuthenticator::new_with_client(
            None,
            vec![],
            kube::client::Client::new(service, "default"),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_authentication_is_valid_until_the_exp_of_the_token() {
        let authenticator = accepting_authenticator();
        let at = |seconds| Some(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(seconds));
        for (token, expected) in [
            (
                unsigned_jwt(r#"{"iss":"kubernetes/serviceaccount","exp":1730052519}"#),
                at(1_730_052_519),
            ),
            (
                unsigned_jwt(r#"{"iss":"kubernetes/serviceaccount","exp":1730052519.5}"#),
                at(1_730_052_519),
            ),
            // A Secret-based token has no `exp`; an opaque token is no JWT.
            (unsigned_jwt(r#"{"iss":"kubernetes/serviceaccount"}"#), None),
            ("opaque-token".to_string(), None),
        ] {
            let authentication = authenticator
                .authenticate(&Token::new(&token))
                .await
                .unwrap();
            assert_eq!(authentication.valid_until(), expected, "{token}");
        }
    }

    /// The API server accepts tokens that limes cannot route: an `alg` that jsonwebtoken does
    /// not know, or base64 with non-zero trailing bits, which go-jose decodes leniently.
    #[test]
    fn test_exp_is_read_from_tokens_that_routing_cannot_read() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let at = |seconds| Some(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(seconds));
        let payload = URL_SAFE_NO_PAD.encode(r#"{"exp":1730052519}"#);

        let es512 = format!(
            "{}.{payload}.signature",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES512"}"#)
        );
        assert_eq!(
            Token::new(&es512).introspection(),
            &IntrospectionResult::Unknown
        );
        assert_eq!(token_expiry(&es512), at(1_730_052_519));

        // 18 bytes encode to 24 characters with no unused bits, so use one byte less: 17 bytes
        // leave 2 unused bits in the last character.
        let payload = URL_SAFE_NO_PAD.encode(r#"{"exp":173005251}"#);
        let mut lenient = payload.clone().into_bytes();
        let last = lenient.last_mut().unwrap();
        *last = match *last {
            b'A' => b'B',
            other => other + 1,
        };
        let lenient = String::from_utf8(lenient).unwrap();
        assert!(URL_SAFE_NO_PAD.decode(&lenient).is_err(), "{lenient}");
        let token = format!(
            "{}.{lenient}.signature",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#)
        );
        assert_eq!(token_expiry(&token), at(173_005_251));

        // go-jose refuses a repeated `exp`; go-oidc reads the last key that equals `exp`
        // ignoring case.
        for (payload, expected) in [
            (r#"{"exp":1,"exp":2}"#, at(2)),
            (r#"{"exp":200,"EXP":100}"#, at(100)),
            (r#"{"Exp":100,"exp":200}"#, at(100)),
        ] {
            assert_eq!(token_expiry(&unsigned_jwt(payload)), expected, "{payload}");
        }

        assert_eq!(token_expiry("not-a-jwt"), None);
        assert_eq!(token_expiry("bootstrap.token"), None);
        assert_eq!(token_expiry(&format!("a.{payload}.b.c")), None);
    }

    /// A JWT whose payload or `exp` limes cannot read is valid until now, so a cache does not
    /// store it.
    #[test]
    fn test_a_jwt_with_a_payload_limes_cannot_read_is_valid_until_now() {
        let before = SystemTime::now();
        for payload in [
            r#"{"exp":"1800000000"}"#,
            r#"{"exp":9999999999,"EXP":"1800000000"}"#,
            r#"{"exp":1730052519,"big":1e400}"#,
            r#"{"exp":1730052519"#,
            "[1730052519]",
        ] {
            let valid_until = token_expiry(&unsigned_jwt(payload)).unwrap();
            assert!(valid_until >= before, "{payload}");
            assert!(valid_until <= SystemTime::now(), "{payload}");
        }
    }

    /// An empty IdP id is unset, as for [`Subject::new`] and the JWKS authenticator.
    #[tokio::test]
    async fn test_empty_idp_id_is_none() {
        let service = tower::service_fn(|_: http::Request<kube::client::Body>| {
            std::future::pending::<
                std::io::Result<http::Response<http_body_util::Full<bytes::Bytes>>>,
            >()
        });
        let client = kube::client::Client::new(service, "default");
        let authenticator =
            KubernetesAuthenticator::new_with_client(Some(""), vec![], client.clone()).unwrap();
        assert_eq!(authenticator.idp_id(), None);
        let authenticator =
            KubernetesAuthenticator::new_with_client(Some("k8s"), vec![], client).unwrap();
        assert_eq!(authenticator.idp_id(), Some("k8s"));
    }

    #[tokio::test]
    async fn test_token_review_failure_kinds() {
        for (status, expected) in [
            (Some(401), ErrorKind::Internal),
            (Some(403), ErrorKind::Internal),
            (Some(429), ErrorKind::Unavailable),
            (Some(500), ErrorKind::Unavailable),
            (Some(503), ErrorKind::Unavailable),
            (None, ErrorKind::Unavailable),
        ] {
            let err = authenticator_with_api(status)
                .authenticate(&Token::new("token"))
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::KubernetesTokenReviewError(_)),
                "{status:?}: {err}"
            );
            assert_eq!(err.kind(), expected, "{status:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_token_review_without_answer_is_unavailable() {
        let service = tower::service_fn(|_: http::Request<kube::client::Body>| {
            std::future::pending::<
                std::io::Result<http::Response<http_body_util::Full<bytes::Bytes>>>,
            >()
        });
        let authenticator = KubernetesAuthenticator::new_with_client(
            None,
            vec![],
            kube::client::Client::new(service, "default"),
        )
        .unwrap();

        let started = tokio::time::Instant::now();
        // Without a deadline in `authenticate`, the paused clock has no timer to advance to.
        let err = tokio::time::timeout(
            2 * TOKEN_REVIEW_TIMEOUT,
            authenticator.authenticate(&Token::new("token")),
        )
        .await
        .expect("authenticate has a deadline")
        .unwrap_err();

        assert_eq!(started.elapsed(), TOKEN_REVIEW_TIMEOUT);
        assert!(matches!(err, Error::KubernetesTokenReviewError(_)), "{err}");
        assert_eq!(err.kind(), ErrorKind::Unavailable);
        assert_eq!(
            err.to_string(),
            "Failed to validate token using kubernetes TokenReview: ServiceError: no answer within 10 seconds"
        );
    }

    #[tokio::test]
    async fn test_empty_token_is_rejected_before_token_review() {
        let err = authenticator_with_api(None)
            .authenticate(&Token::new(""))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "Authentication failed: Token is empty");
        assert_eq!(err.kind(), ErrorKind::Unauthenticated);
    }

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
            None,
        )
        .unwrap_err();

        // Valid audience
        let payload = parse_review_status(
            Some(token_review_status),
            &["https://kubernetes.default.svc".to_string()],
            Some("my-k8s-cluster"),
            KubernetesSubjectSource::Uid,
            None,
        )
        .unwrap();

        let crate::Identity::Kubernetes(user) = payload.identity() else {
            panic!("expected a Kubernetes user");
        };
        assert_eq!(
            user.username(),
            Some("system:serviceaccount:my-namespace:my-serviceaccount")
        );
        assert_eq!(user.uid(), Some("0e79c2ec-32eb-4a46-ab9b-f075fbbfbd43"));
        assert_eq!(
            user.groups(),
            [
                "system:serviceaccounts",
                "system:serviceaccounts:my-namespace",
                "system:authenticated"
            ]
        );
        assert_eq!(
            user.extra().get("authentication.kubernetes.io/pod-name"),
            Some(&vec!["my-pod".to_string()])
        );
        assert!(payload.satisfies(
            &crate::ClaimRule::any_of("authentication.kubernetes.io/pod-name", ["my-pod"]).unwrap()
        ));
        assert_eq!(
            payload.subject().subject_in_idp(),
            "0e79c2ec-32eb-4a46-ab9b-f075fbbfbd43"
        );
        assert_eq!(payload.subject().idp_id(), Some("my-k8s-cluster"));
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
            None,
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
            None,
        )
        .unwrap();

        assert_eq!(
            payload.subject().subject_in_idp(),
            "system:serviceaccount:my-namespace:my-serviceaccount"
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
            None,
        )
        .unwrap_err();
    }

    #[test]
    fn test_parse_review_status_rejects_empty_subject() {
        // A present-but-empty subject field must be rejected, not turned into
        // an empty subject.
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
            parse_review_status(
                Some(token_review_status),
                &[],
                Some("kubernetes"),
                source,
                None,
            )
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
            let payload = parse_review_status(
                Some(token_review_status),
                &[],
                Some("kubernetes"),
                source,
                None,
            )
            .unwrap();
            assert_eq!(payload.subject().subject_in_idp(), expected);
        }
    }
}
