//! Validate JWT tokens locally using JWKS keys fetched from a remote server.

use crate::identity::{ISSUER_CLAIM, SCOPE_CLAIM, SCP_CLAIM};
use crate::introspect::IntrospectionResult;
use crate::{
    Authentication, Authenticator, Subject, Token, VerifiedClaims,
    claims::{ClaimOperator, ClaimRule, Separator, navigate},
    error::RejectionReason,
    error::{Error, Result},
};
use jsonwebtoken::{Header, Validation, crypto::CryptoProvider};
use key_cache::KeyCache;
use keys::VerificationKey;
use std::sync::Arc;
use std::time::Duration;

mod key_cache;
mod keys;

/// Timeouts for requests to the identity provider.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const SUBJECT_CLAIM: &str = "sub";
const AUDIENCE_CLAIM: &str = "aud";

/// jsonwebtoken verifies signatures with its process-level crypto provider and panics on the
/// first token if it has none. Checked when an authenticator is created, so a build that
/// enables neither or both of its backends fails at startup.
fn require_crypto_provider(provider: Option<&CryptoProvider>) -> Result<()> {
    provider.map(|_| ()).ok_or(Error::NoJwtCryptoProvider)
}

/// Validate JWT tokens using JWKS keys fetched from a remote server.
///
/// The `issuer_url` must serve `/.well-known/openid-configuration`. A token's issuer must be
/// the `issuer` of that configuration or one added with
/// [`add_additional_issuers`](Self::add_additional_issuers), for an identity provider that
/// is reachable under several URLs.
///
/// The audience is checked only if [`set_accepted_audiences`](Self::set_accepted_audiences)
/// names some; then the token must carry one of them. [`set_scope`](Self::set_scope) requires
/// a scope.
///
/// The JWKS is fetched when the authenticator is created, in the background once the keys
/// are older than `ttl` (one hour if `ttl` is `None`), and when a token names a key id that
/// is not among them. Once keys have loaded, at most one fetch starts every 30 seconds.
///
/// A request for a key the authenticator holds does not wait for a fetch. After `ttl`, the
/// keys stay in use until a fetch succeeds, also while the identity provider cannot be
/// reached. A request for a key id the keys lack waits for the running fetch. A key that
/// the identity provider starts to use less than 30 seconds after a fetch is accepted once
/// the next fetch has run. Keys that cannot verify signatures, such as encryption keys and
/// symmetric keys, are not used.
///
/// The subject is the `sub` claim. Some identity providers, like Entra ID, identify users
/// across applications with `oid`; read it with [`with_subject_claim`](Self::with_subject_claim).
///
/// The [`Authentication`] carries the token's claims as [`Identity::Claims`](crate::Identity::Claims).
#[derive(Clone)]
pub struct JWKSWebAuthenticator {
    // Shared so that cloning the authenticator per request is a refcount bump.
    inner: std::sync::Arc<Inner>,
}

#[derive(Clone)]
struct Inner {
    idp_id: Option<String>,
    audiences: Vec<String>,
    keys: Arc<KeyCache>,
    issuers: Vec<String>,
    scope: Option<ScopeRule>,
    required_claims: Vec<(String, ClaimRule)>,
    config_url: url::Url,
    subject_claim: Vec<String>,
}

impl JWKSWebAuthenticator {
    const WELL_KNOWN_CONFIG: &'static str = ".well-known/openid-configuration";

    /// Create a new [`JWKSWebAuthenticator`].
    ///
    /// # Arguments
    /// - `issuer_url`: The URL of the identity provider to fetch the JWKS keys from. Must provide a `/.well-known/openid-configuration` endpoint.
    /// - `ttl`: After this time, the JWKS is fetched again in the background. If `None`, one hour. Below 30 seconds, it acts as 30 seconds.
    ///
    /// Name the identity provider with [`set_idp_id`](Self::set_idp_id) when you configure
    /// several.
    ///
    /// Also fetches the JWKS, which takes up to 10 seconds if the identity provider does not
    /// answer. If that fetch fails, the authenticator starts without keys and fetches them
    /// when a token needs one.
    ///
    /// # Errors
    /// - If jsonwebtoken has no crypto provider ([`Error::NoJwtCryptoProvider`]): the build
    ///   enables neither or both of its backends. The features `aws-lc-rs` and `rust-crypto`
    ///   select one; if another crate in the build enables the other, install one with
    ///   [`CryptoProvider::install_default`](jsonwebtoken::crypto::CryptoProvider::install_default)
    ///   before calling `new`.
    /// - If the `issuer_url` is not a valid URL.
    /// - If the `issuer_url` does not provide a `/.well-known/openid-configuration` endpoint.
    /// - If the fetched configuration does not contain the required fields.
    pub async fn new(issuer_url: &str, ttl: Option<Duration>) -> Result<Self> {
        require_crypto_provider(CryptoProvider::try_get_default())?;
        let (keys, issuer, config_url) = JWKSWebAuthenticator::discover(issuer_url, ttl).await?;
        Ok(Self {
            inner: std::sync::Arc::new(Inner {
                idp_id: None,
                keys,
                issuers: vec![issuer],
                audiences: Vec::new(),
                scope: None,
                required_claims: Vec::new(),
                config_url,
                subject_claim: vec![SUBJECT_CLAIM.to_string()],
            }),
        })
    }

    /// Set the IdP id for the authenticator. Required when you configure several identity
    /// providers. An empty id leaves it unset.
    #[must_use]
    pub fn set_idp_id(mut self, idp_id: &str) -> Self {
        if !idp_id.is_empty() {
            std::sync::Arc::make_mut(&mut self.inner).idp_id = Some(idp_id.to_string());
        }
        self
    }

    /// The issuers this authenticator accepts: the one discovered from the provider's
    /// `.well-known` document, followed by any added with
    /// [`add_additional_issuers`](Self::add_additional_issuers).
    ///
    /// This is what [`can_handle_token`](Authenticator::can_handle_token) routes on, so a
    /// caller assembling several authenticators can check here whether two of them would
    /// compete for the same tokens.
    #[must_use]
    pub fn issuers(&self) -> &[String] {
        &self.inner.issuers
    }

    /// The audiences this authenticator accepts; empty means any.
    #[must_use]
    pub fn audiences(&self) -> &[String] {
        &self.inner.audiences
    }

    /// Set the accepted audiences.
    /// If empty / not called, no audience validation is done.
    #[must_use]
    pub fn set_accepted_audiences(mut self, audiences: Vec<String>) -> Self {
        std::sync::Arc::make_mut(&mut self.inner).audiences = audiences;
        self
    }

    /// Add additional issuers to the authenticator.
    /// If empty, only the issuer from the fetched configuration is accepted.
    #[must_use]
    pub fn add_additional_issuers(mut self, additional_issuers: Vec<String>) -> Self {
        // Make sure to not add duplicates
        let additional_issuers: Vec<_> = additional_issuers
            .into_iter()
            .filter(|issuer| !self.inner.issuers.contains(issuer))
            .collect();
        std::sync::Arc::make_mut(&mut self.inner)
            .issuers
            .extend(additional_issuers);
        self
    }

    /// Require a scope. Calling again replaces the previously required scope.
    ///
    /// Read from the `scope` claim, or `scp` if `scope` is absent or carries no scopes; a
    /// whitespace-delimited string or an array of strings, whose values must be strings.
    /// Evaluated before
    /// [`with_required_claims`](Self::with_required_claims); a failure is reported as
    /// [`RejectionReason::ScopeMissing`].
    ///
    /// # Errors
    /// If `scope` is empty or contains whitespace — such a scope could never be satisfied.
    pub fn set_scope(mut self, scope: String) -> Result<Self> {
        std::sync::Arc::make_mut(&mut self.inner).scope = Some(ScopeRule::new(scope)?);
        Ok(self)
    }

    /// Require claim rules, evaluated in order after signature, issuer, audience and scope
    /// checks. All rules must hold. Names appear only in errors and logs. Calling again
    /// replaces the previously set rules.
    ///
    /// Audience validation accepts a token whose `aud` merely intersects the accepted set —
    /// a token minted for several audiences authenticates here too. To bind tokens to one
    /// client, additionally require the authorized party:
    /// `ClaimRule::any_of("azp", [client_id])`.
    #[must_use]
    pub fn with_required_claims(
        mut self,
        rules: impl IntoIterator<Item = (String, ClaimRule)>,
    ) -> Self {
        std::sync::Arc::make_mut(&mut self.inner).required_claims = rules.into_iter().collect();
        self
    }

    /// Set the claim to use as the subjects id.
    /// If `None`, the `sub` claim will be used.
    ///
    /// The claim is a path: it nests on every dot (`resource_access.account.id`), or names one
    /// claim outright when it contains `/` or `:`. A token is rejected unless the claim holds
    /// a string that is not blank — a non-string, `""` and `"   "` are all no subject.
    #[must_use]
    pub fn with_subject_claim(mut self, subject_claim: String) -> Self {
        std::sync::Arc::make_mut(&mut self.inner).subject_claim = vec![subject_claim];
        self
    }

    /// Set multiple claims to use as the subjects id.
    /// Overrides any previously set claims.
    /// If multiple claims are set, the first one holding a string that is not blank will be
    /// used; a claim that is absent, non-string, empty or whitespace-only is passed over for
    /// the next.
    ///
    /// If this function is called with an empty vector, the previously set claim will be used,
    /// by default this is the `sub` claim.
    ///
    /// Each claim is a path, read the same way as [`Self::with_subject_claim`].
    #[must_use]
    pub fn with_subject_claims(mut self, subject_claims: Vec<String>) -> Self {
        // Setting multiple claims can be useful in multi-tenant applications.
        // For entra-id most applications that
        // interact with other applications should prefer the `oid` claim over the `sub` claim.
        if !subject_claims.is_empty() {
            std::sync::Arc::make_mut(&mut self.inner).subject_claim = subject_claims;
        }
        self
    }

    /// Reads the provider's `.well-known` configuration: the issuer, and where its keys are.
    async fn discover(
        issuer_url: &str,
        ttl: Option<Duration>,
    ) -> Result<(Arc<KeyCache>, String, url::Url)> {
        let mut url = url::Url::parse(issuer_url)
            .inspect_err(|e| tracing::debug!("Failed to parse issuer url: {e}"))?;
        if !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }

        url = if url.path().ends_with(Self::WELL_KNOWN_CONFIG) {
            url
        } else {
            url.join(Self::WELL_KNOWN_CONFIG).inspect_err(|e| {
                tracing::debug!(
                    "Failed to join well-known configuration '{}' to issuer url '{}': {e}",
                    Self::WELL_KNOWN_CONFIG,
                    url
                );
            })?
        };

        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| Error::internal("Failed to build the HTTP client", e))?;
        let config = http
            .get(url.clone())
            .send()
            .await
            .map_err(|e| Error::FetchOpenIDWellKnownConfigError {
                url: url.to_string(),
                source: e,
            })?
            .json::<WellKnownConfig>()
            .await
            .map_err(|e| {
                tracing::debug!("Failed to parse openid configuration: {e}");
                Error::InvalidWellKnownConfig {
                    expected_fields: &["jwks_uri", "issuer"],
                    source: e,
                }
            })?;
        let fetch = key_cache::http_fetch(http, config.jwks_uri.clone());
        let keys = Arc::new(KeyCache::new(fetch, config.jwks_uri, ttl));
        keys.prefetch().await;
        Ok((keys, config.issuer, url))
    }
}

impl Authenticator for JWKSWebAuthenticator {
    async fn authenticate(&self, token: &Token<'_>) -> Result<Authentication> {
        let IntrospectionResult::JWTBearer { header, .. } = token.introspection() else {
            return Err(Error::JWTDecodeError {
                reason: "Token is not a JWT bearer token.".to_string(),
            });
        };
        let key_id = header.kid.as_deref().ok_or_else(|| Error::JWTDecodeError {
            reason: "Token does not contain a key id".to_string(),
        })?;
        let key = self.inner.keys.get(key_id).await?;
        let token_data = authenticate_jwt(
            token.as_str(),
            header,
            &key,
            &self.inner.audiences,
            &self.inner.issuers,
            self.inner.scope.as_ref(),
            &self.inner.required_claims,
        )?;

        extract_authentication(self.idp_id(), token_data, &self.inner.subject_claim)
    }

    fn idp_id(&self) -> Option<&str> {
        self.inner.idp_id.as_deref()
    }

    fn can_handle_token(&self, token: &Token<'_>) -> bool {
        if token.as_str().is_empty() {
            return false;
        }

        match token.introspection() {
            IntrospectionResult::JWTBearer {
                iss,
                aud,
                header: _,
            } => {
                (self.inner.issuers.is_empty()
                    || self.inner.issuers.iter().any(|i| iss.contains(i)))
                    && (self.inner.audiences.is_empty()
                        || self.inner.audiences.iter().any(|a| aud.contains(a)))
            }
            IntrospectionResult::Unknown => false,
        }
    }
}

fn authenticate_jwt(
    token: &str,
    header: &Header,
    key: &VerificationKey,
    audiences: &[String],
    issuers: &[String],
    scope: Option<&ScopeRule>,
    required_claims: &[(String, ClaimRule)],
) -> Result<jsonwebtoken::TokenData<serde_json::Value>> {
    // Some identity providers, like Entra ID, don't include the alg field in the jwks endpoint.
    // In this case we trust the provided algorithm in the clients token.
    let mut validation = Validation::new(key.algorithm.unwrap_or(header.alg));

    // jsonwebtoken checks `aud`/`iss` only when the claim parses; requiring them makes an
    // absent or malformed claim a rejection instead of a pass.
    if audiences.is_empty() {
        validation.validate_aud = false;
    } else {
        validation.set_audience(audiences);
        validation.validate_aud = true;
        validation
            .required_spec_claims
            .insert(AUDIENCE_CLAIM.to_string());
    }
    validation.set_issuer(issuers);
    validation
        .required_spec_claims
        .insert(ISSUER_CLAIM.to_string());
    // `exp` is validated by default; `nbf` (RFC 7519 §4.1.5) is opt-in. A token before its
    // `nbf` is not yet valid. An absent `nbf` stays acceptable.
    validation.validate_nbf = true;

    // jsonwebtoken verifies the signature before validating claims, so audience and
    // issuer failures are rejections of a genuine token; everything else is unverifiable.
    let token_data = jsonwebtoken::decode::<serde_json::Value>(
        token,
        &key.decoding_key,
        &validation,
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::InvalidAudience => {
            tracing::debug!(accepted_audiences = ?audiences, "Token audience rejected: {e}");
            Error::rejected(RejectionReason::AudienceMismatch)
        }
        jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
            tracing::debug!(accepted_issuers = ?issuers, "Token issuer rejected: {e}");
            Error::rejected(RejectionReason::IssuerMismatch)
        }
        jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claim) => {
            Error::rejected(RejectionReason::ClaimMissing {
                claim: claim.clone(),
            })
        }
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            Error::rejected(RejectionReason::Expired)
        }
        jsonwebtoken::errors::ErrorKind::ImmatureSignature => {
            Error::rejected(RejectionReason::NotYetValid)
        }
        jsonwebtoken::errors::ErrorKind::InvalidClaimFormat(claim) => {
            Error::rejected(RejectionReason::ClaimMalformed {
                claim: claim.clone(),
            })
        }
        _ => Error::JWTDecodeError {
            reason: format!("Failed to decode JWT token. {e}"),
        },
    })?;

    if scope.is_some_and(|scope| !scope.matches(&token_data.claims)) {
        tracing::debug!("Required scope missing");
        return Err(Error::rejected(RejectionReason::ScopeMissing));
    }
    for (name, rule) in required_claims {
        if !rule.matches(&token_data.claims) {
            tracing::debug!(rule = name, "Required-claim rule failed");
            return Err(Error::rejected(RejectionReason::ClaimRuleFailed {
                rule: name.clone(),
            }));
        }
    }

    Ok(token_data)
}

fn extract_authentication(
    idp_id: Option<&str>,
    token_data: jsonwebtoken::TokenData<serde_json::Value>,
    subject_claim: &[String],
) -> Result<Authentication> {
    let subject_in_idp = get_subject(&token_data, subject_claim)?;
    let audiences = crate::introspect::parse_aud(token_data.claims.get(AUDIENCE_CLAIM));
    // jsonwebtoken reads exactly `exp` and refuses a payload that repeats it.
    let valid_until = token_data
        .claims
        .get("exp")
        .and_then(crate::identity::numeric_date);
    // A payload with a subject claim is a JSON object.
    let claims = VerifiedClaims::try_from(token_data.claims)
        .map_err(|_| Error::rejected(RejectionReason::SubjectClaimMissing))?;
    let subject = Subject::new(idp_id.map(ToString::to_string), subject_in_idp);

    Ok(Authentication::builder()
        .subject(subject)
        .audiences(audiences)
        .identity(claims)
        .valid_until_opt(valid_until)
        .build())
}

fn get_subject(
    token_data: &jsonwebtoken::TokenData<serde_json::Value>,
    subject_claim: &[String],
) -> Result<String> {
    for claim in subject_claim {
        // The same path grammar every claim path uses, so one configured string means one
        // thing for the subject, the rules and `VerifiedClaims::claim`.
        let subject = navigate(&token_data.claims, claim)
            .and_then(value_as_string)
            // A blank subject is not an identity: it would collapse every token carrying one
            // onto a single principal.
            .filter(|subject| !subject.trim().is_empty());
        if let Some(subject) = subject {
            return Ok(subject);
        }
    }
    Err(Error::rejected(RejectionReason::SubjectClaimMissing))
}

#[derive(serde::Deserialize, Clone, Debug)]
struct WellKnownConfig {
    pub jwks_uri: url::Url,
    pub issuer: String,
}

impl std::fmt::Debug for JWKSWebAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut r = f.debug_struct("JWKSWebAuthenticator");

        let r = r.field("idp_id", &self.inner.idp_id);

        r.field("audiences", &self.inner.audiences)
            .field("issuers", &self.inner.issuers)
            .field("scope", &self.inner.scope.as_ref().map(|s| s.0.claims()))
            .field(
                "required_claims",
                &self
                    .inner
                    .required_claims
                    .iter()
                    .map(|(name, rule)| (name.as_str(), rule.claims()))
                    .collect::<Vec<_>>(),
            )
            .field("config_url", &self.inner.config_url)
            .field("subject_claim", &self.inner.subject_claim)
            .field("keys", &self.inner.keys)
            .finish()
    }
}

fn value_as_string(value: &serde_json::Value) -> Option<String> {
    value.as_str().map(std::string::ToString::to_string)
}

/// The `set_scope` requirement: a whitespace-split `all_of` rule on `scope`/`scp`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopeRule(ClaimRule);

impl ScopeRule {
    fn new(scope: String) -> Result<Self> {
        ClaimRule::new(
            SCOPE_CLAIM,
            Some(Separator::Whitespace),
            ClaimOperator::AllOf(std::collections::HashSet::from([scope])),
        )
        .and_then(|r| r.or_claim(SCP_CLAIM))
        .map(Self)
        .map_err(|e| Error::InvalidScope { source: e })
    }

    /// Scopes are strings: a claim holding numbers or booleans is malformed and never
    /// satisfies the requirement, matching [`VerifiedClaims::scopes`].
    ///
    /// The guard reads the claim the rule itself resolved. Resolving it a second time would
    /// let the guard vet one claim while the rule evaluates another.
    fn matches(&self, claims: &serde_json::Value) -> bool {
        self.0
            .resolve(claims)
            .and_then(crate::claims::strings)
            .is_some()
            && self.0.matches(claims)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use jsonwebtoken::Algorithm;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    // ---- signed-token fixtures ----

    fn ed25519_fixture() -> (jsonwebtoken::EncodingKey, serde_json::Value) {
        use base64::Engine as _;
        crate::install_test_jwt_crypto_provider();
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::generate().unwrap();
        let pkcs8 = key_pair.to_pkcs8().unwrap();
        let encoding_key = jsonwebtoken::EncodingKey::from_ed_der(pkcs8.as_ref());
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(aws_lc_rs::signature::KeyPair::public_key(&key_pair).as_ref());
        let jwk = serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": "k1", "x": x
        });
        (encoding_key, jwk)
    }

    fn sign(key: &jsonwebtoken::EncodingKey, mut claims: serde_json::Value) -> (String, Header) {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        claims["exp"] = serde_json::json!(exp);
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("k1".to_string());
        let token = jsonwebtoken::encode(&header, &claims, key).unwrap();
        (token, header)
    }

    fn sign_without_exp(
        key: &jsonwebtoken::EncodingKey,
        claims: &serde_json::Value,
    ) -> (String, Header) {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("k1".to_string());
        let token = jsonwebtoken::encode(&header, claims, key).unwrap();
        (token, header)
    }

    const ISS: &str = "https://idp.example.com";
    const AUD: &str = "lakekeeper";

    fn org_rule(org: &str) -> (String, ClaimRule) {
        (
            "org".to_string(),
            ClaimRule::new(
                "organizations",
                None,
                ClaimOperator::AnyOf(HashSet::from([org.to_string()])),
            )
            .unwrap(),
        )
    }

    fn verify(
        jwk: &serde_json::Value,
        token: &str,
        header: &Header,
        rules: &[(String, ClaimRule)],
    ) -> Result<jsonwebtoken::TokenData<serde_json::Value>> {
        verify_with_scope(jwk, token, header, None, rules)
    }

    fn verify_with_scope(
        jwk: &serde_json::Value,
        token: &str,
        header: &Header,
        scope: Option<&ScopeRule>,
        rules: &[(String, ClaimRule)],
    ) -> Result<jsonwebtoken::TokenData<serde_json::Value>> {
        let (_, key) = keys::prepare_key(jwk.clone()).unwrap();
        authenticate_jwt(
            token,
            header,
            &key,
            &[AUD.to_string()],
            &[ISS.to_string()],
            scope,
            rules,
        )
    }

    fn org_failed() -> RejectionReason {
        RejectionReason::ClaimRuleFailed {
            rule: "org".to_string(),
        }
    }

    #[test]
    fn test_authenticate_jwt_accepts_token_satisfying_rules() {
        let (enc, jwk) = ed25519_fixture();
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "organizations": ["tenant-a"] }),
        );
        let data = verify(&jwk, &token, &header, &[org_rule("tenant-a")]).unwrap();
        assert_eq!(data.claims["sub"], "u");
    }

    #[test]
    fn test_authenticate_jwt_rejects_failed_rule_with_typed_reason_and_no_values() {
        let (enc, jwk) = ed25519_fixture();
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "organizations": ["tenant-b"] }),
        );
        let err = verify(&jwk, &token, &header, &[org_rule("tenant-a")]).unwrap_err();
        assert_eq!(err.rejection(), Some(&org_failed()));
        let rendered = format!("{err} {err:?}");
        assert!(!rendered.contains("tenant-a"), "{rendered}");
        assert!(!rendered.contains("organizations"), "{rendered}");
        assert!(!rendered.contains("tenant-b"), "{rendered}");
    }

    #[test]
    fn test_authenticate_jwt_missing_claim_fails_closed() {
        let (enc, jwk) = ed25519_fixture();
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u" }),
        );
        let err = verify(&jwk, &token, &header, &[org_rule("tenant-a")]).unwrap_err();
        assert_eq!(err.rejection(), Some(&org_failed()));
    }

    #[test]
    fn test_authenticate_jwt_reports_first_failing_rule_in_order() {
        let (enc, jwk) = ed25519_fixture();
        // Both rules fail; the first configured one is reported.
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "organizations": ["tenant-b"] }),
        );
        let scope = (
            "scopes".to_string(),
            ClaimRule::new(
                "scope",
                Some(Separator::Whitespace),
                ClaimOperator::AllOf(HashSet::from(["openid".to_string()])),
            )
            .unwrap(),
        );
        let err = verify(
            &jwk,
            &token,
            &header,
            &[org_rule("tenant-a"), scope.clone()],
        )
        .unwrap_err();
        assert_eq!(err.rejection(), Some(&org_failed()));
        let err = verify(&jwk, &token, &header, &[scope, org_rule("tenant-a")]).unwrap_err();
        assert_eq!(
            err.rejection(),
            Some(&RejectionReason::ClaimRuleFailed {
                rule: "scopes".to_string(),
            })
        );
    }

    #[test]
    fn test_authenticate_jwt_accepts_token_without_aud_when_no_audience_configured() {
        let (enc, jwk) = ed25519_fixture();
        let (token, header) = sign(&enc, serde_json::json!({ "iss": ISS, "sub": "u" }));
        let (_, key) = keys::prepare_key(jwk).unwrap();
        let data =
            authenticate_jwt(&token, &header, &key, &[], &[ISS.to_string()], None, &[]).unwrap();
        assert_eq!(data.claims["sub"], "u");
    }

    #[test]
    fn test_authenticate_jwt_classifies_audience_mismatch_without_values() {
        let (enc, jwk) = ed25519_fixture();
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": "someone-else", "sub": "u" }),
        );
        let err = verify(&jwk, &token, &header, &[]).unwrap_err();
        assert_eq!(err.rejection(), Some(&RejectionReason::AudienceMismatch));
        let rendered = format!("{err} {err:?}");
        assert!(!rendered.contains("someone-else"), "{rendered}");
        assert!(!rendered.contains(AUD), "{rendered}");
    }

    #[test]
    fn test_authenticate_jwt_classifies_issuer_mismatch() {
        let (enc, jwk) = ed25519_fixture();
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": "https://evil.example.com", "aud": AUD, "sub": "u" }),
        );
        let err = verify(&jwk, &token, &header, &[]).unwrap_err();
        assert_eq!(err.rejection(), Some(&RejectionReason::IssuerMismatch));
    }

    #[test]
    fn test_authenticate_jwt_distinguishes_missing_from_mismatched_audience() {
        let (enc, jwk) = ed25519_fixture();
        let (token, header) = sign(&enc, serde_json::json!({ "iss": ISS, "sub": "u" }));
        let err = verify(&jwk, &token, &header, &[]).unwrap_err();
        assert_eq!(
            err.rejection(),
            Some(&RejectionReason::ClaimMissing {
                claim: "aud".to_string()
            })
        );

        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": "someone-else", "sub": "u" }),
        );
        let err = verify(&jwk, &token, &header, &[]).unwrap_err();
        assert_eq!(err.rejection(), Some(&RejectionReason::AudienceMismatch));
    }

    #[test]
    fn test_authenticate_jwt_expired_token_is_a_rejection() {
        let (enc, jwk) = ed25519_fixture();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("k1".to_string());
        let token = jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "exp": 1 }),
            &enc,
        )
        .unwrap();
        let err = verify(&jwk, &token, &header, &[]).unwrap_err();
        assert_eq!(err.rejection(), Some(&RejectionReason::Expired));
    }

    /// jsonwebtoken accepts an `exp` with a fraction. The authentication is never valid longer
    /// than jsonwebtoken verified.
    #[test]
    fn test_authentication_is_valid_until_a_float_exp_rounded_down() {
        let (enc, jwk) = ed25519_fixture();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("k1".to_string());
        let exp = 9_999_999_999.75_f64;
        let token = jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "exp": exp }),
            &enc,
        )
        .unwrap();
        let token_data = verify(&jwk, &token, &header, &[]).unwrap();
        let authentication =
            extract_authentication(None, token_data, &[SUBJECT_CLAIM.to_string()]).unwrap();
        assert_eq!(
            authentication.valid_until(),
            Some(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(9_999_999_999))
        );
    }

    #[test]
    fn test_authenticate_jwt_not_yet_valid_token_is_a_rejection() {
        let (enc, jwk) = ed25519_fixture();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "nbf": now + 3600 }),
        );
        let err = verify(&jwk, &token, &header, &[]).unwrap_err();
        assert_eq!(err.rejection(), Some(&RejectionReason::NotYetValid));
    }

    #[test]
    fn test_authenticate_jwt_unusable_expiry_is_a_rejection() {
        let (enc, jwk) = ed25519_fixture();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("k1".to_string());
        let token = jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "exp": "soon" }),
            &enc,
        )
        .unwrap();
        let err = verify(&jwk, &token, &header, &[]).unwrap_err();
        assert_eq!(
            err.rejection(),
            Some(&RejectionReason::ClaimMissing {
                claim: "exp".to_string()
            })
        );
        // A token with no expiry at all is rejected the same way.
        let (token, header) = sign_without_exp(
            &enc,
            &serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u" }),
        );
        let err = verify(&jwk, &token, &header, &[]).unwrap_err();
        assert_eq!(
            err.rejection(),
            Some(&RejectionReason::ClaimMissing {
                claim: "exp".to_string()
            })
        );
    }

    #[test]
    fn test_authenticate_jwt_bad_signature_is_not_a_rejection() {
        let (enc, _) = ed25519_fixture();
        let (_, other_jwk) = ed25519_fixture();
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u" }),
        );
        let err = verify(&other_jwk, &token, &header, &[]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Failed to decode JWT Token. Failed to decode JWT token. InvalidSignature"
        );
        assert_eq!(err.rejection(), None);
    }

    /// Time claims carry `jsonwebtoken`'s default 60 second leeway, which absorbs ordinary
    /// clock drift between the issuer and this host. Pinned so a default change is visible.
    #[test]
    fn test_authenticate_jwt_tolerates_sixty_seconds_of_clock_drift() {
        let (enc, jwk) = ed25519_fixture();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Not valid for another 30 s: within the leeway, accepted.
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "nbf": now + 30 }),
        );
        assert!(verify(&jwk, &token, &header, &[]).is_ok());

        // Expired 30 s ago: within the leeway, accepted.
        let (token, header) = sign_without_exp(
            &enc,
            &serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "exp": now - 30 }),
        );
        assert!(verify(&jwk, &token, &header, &[]).is_ok());

        // Expired 10 min ago: beyond the leeway.
        let (token, header) = sign_without_exp(
            &enc,
            &serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "exp": now - 600 }),
        );
        let err = verify(&jwk, &token, &header, &[]).unwrap_err();
        assert_eq!(err.rejection(), Some(&RejectionReason::Expired));
    }

    #[test]
    fn test_authenticate_jwt_accepts_past_nbf_and_absent_nbf() {
        let (enc, jwk) = ed25519_fixture();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for claims in [
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "nbf": now - 60 }),
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u" }),
        ] {
            let (token, header) = sign(&enc, claims);
            let data = verify(&jwk, &token, &header, &[]).unwrap();
            assert_eq!(data.claims["sub"], "u");
        }
    }

    #[test]
    fn test_authenticate_jwt_uses_token_alg_when_jwk_has_none() {
        use base64::Engine as _;
        crate::install_test_jwt_crypto_provider();
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::generate().unwrap();
        let pkcs8 = key_pair.to_pkcs8().unwrap();
        let enc = jsonwebtoken::EncodingKey::from_ed_der(pkcs8.as_ref());
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(aws_lc_rs::signature::KeyPair::public_key(&key_pair).as_ref());
        let jwk = serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": x });
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u" }),
        );
        let data = verify(&jwk, &token, &header, &[]).unwrap();
        assert_eq!(data.claims["sub"], "u");
    }

    #[test]
    fn test_authenticate_jwt_uses_the_algorithm_the_jwks_names() {
        let (enc, jwk) = ed25519_fixture();
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u" }),
        );
        let (_, mut key) = keys::prepare_key(jwk).unwrap();
        // The JWKS names another algorithm than the token's header.
        key.algorithm = Some(Algorithm::ES256);
        let err = authenticate_jwt(
            &token,
            &header,
            &key,
            &[AUD.to_string()],
            &[ISS.to_string()],
            None,
            &[],
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Failed to decode JWT Token. Failed to decode JWT token. InvalidAlgorithm"
        );
    }

    // ---- scope sugar ----

    #[test]
    fn test_scope_rule_is_a_whitespace_all_of_with_scp_fallback() {
        assert_eq!(
            ScopeRule::new("openid".to_string()).unwrap(),
            ScopeRule(
                ClaimRule::new(
                    SCOPE_CLAIM,
                    Some(Separator::Whitespace),
                    ClaimOperator::AllOf(HashSet::from(["openid".to_string()])),
                )
                .unwrap()
                .or_claim("scp")
                .unwrap()
            )
        );
    }

    /// A scope that no token could ever satisfy is a configuration error, rejected at
    /// construction like the equivalent required-claim rule.
    #[test]
    fn test_unsatisfiable_scopes_are_rejected_at_construction() {
        assert_eq!(
            ScopeRule::new(String::new()).unwrap_err().to_string(),
            "Invalid scope: all_of must not contain blank values"
        );
        assert_eq!(
            ScopeRule::new("   ".to_string()).unwrap_err().to_string(),
            "Invalid scope: all_of must not contain blank values"
        );
        assert_eq!(
            ScopeRule::new("read write".to_string())
                .unwrap_err()
                .to_string(),
            "Invalid scope: all_of value `read write` contains the separator"
        );
        assert_eq!(
            ScopeRule::new(" admin".to_string())
                .unwrap_err()
                .to_string(),
            "Invalid scope: all_of value ` admin` contains the separator"
        );
    }

    #[test]
    fn test_scope_rule_matches_previous_scope_check_cases() {
        let scope = ScopeRule::new("profile".to_string()).unwrap();
        let ok = |v: serde_json::Value| scope.matches(&serde_json::json!({ "scope": v }));
        assert!(ok(serde_json::json!("openid profile email")));
        assert!(ok(serde_json::json!("openid  profile\temail")));
        assert!(ok(serde_json::json!("profile")));
        assert!(!ok(serde_json::json!("openid email")));
        // Whole scope, not a prefix.
        assert!(!ok(serde_json::json!("profiles")));
        assert!(!ok(serde_json::json!("")));
        assert!(!scope.matches(&serde_json::json!({ "sub": "u" })));
        // New: array-shaped scope claims and the `scp` claim.
        assert!(ok(serde_json::json!(["openid", "profile"])));
        assert!(scope.matches(&serde_json::json!({ "scp": ["profile"] })));
        assert!(scope.matches(&serde_json::json!({ "scp": "openid profile" })));
    }

    #[test]
    fn test_scope_rule_rejects_non_string_scope_values() {
        let scope = ScopeRule::new("42".to_string()).unwrap();
        assert!(!scope.matches(&serde_json::json!({ "scope": 42 })));
        assert!(scope.matches(&serde_json::json!({ "scope": ["42"] })));
        let scope = ScopeRule::new("admin".to_string()).unwrap();
        assert!(!scope.matches(&serde_json::json!({ "scope": ["admin", 42] })));
        assert!(!scope.matches(&serde_json::json!({ "scope": ["admin", true] })));
    }

    /// The subject reads the same path grammar as every rule and `VerifiedClaims::claim`, so
    /// one configured string means one thing across all three.
    #[test]
    fn test_subject_claim_is_a_path() {
        let claims = serde_json::json!({
            "resource_access": { "account": { "id": "nested-id" } },
            "https://example.com/uid": "uri-id",
            "sub": "flat-id",
        });
        let subject = |paths: &[&str]| {
            get_subject(
                &jsonwebtoken::TokenData {
                    header: Header::new(Algorithm::EdDSA),
                    claims: claims.clone(),
                },
                &paths.iter().map(|p| (*p).to_string()).collect::<Vec<_>>(),
            )
        };
        assert_eq!(
            subject(&["resource_access.account.id"]).unwrap(),
            "nested-id"
        );
        // A path containing `/` or `:` names one claim outright.
        assert_eq!(subject(&["https://example.com/uid"]).unwrap(), "uri-id");
        assert_eq!(subject(&["sub"]).unwrap(), "flat-id");
        // The first path that resolves decides; unresolvable ones fall through.
        assert_eq!(
            subject(&["resource_access.missing", "sub"]).unwrap(),
            "flat-id"
        );
        assert_eq!(
            subject(&["missing"]).unwrap_err().rejection(),
            Some(&RejectionReason::SubjectClaimMissing)
        );
    }

    /// A blank subject is not an identity: every token carrying one would share a principal.
    #[test]
    fn test_blank_subject_is_rejected() {
        for blank in [
            serde_json::json!(""),
            serde_json::json!("   "),
            serde_json::json!("\t"),
        ] {
            let token_data = jsonwebtoken::TokenData {
                header: Header::new(Algorithm::EdDSA),
                claims: serde_json::json!({ "sub": blank, "oid": "real" }),
            };
            assert_eq!(
                get_subject(&token_data, &["sub".to_string()])
                    .unwrap_err()
                    .rejection(),
                Some(&RejectionReason::SubjectClaimMissing),
                "{blank} must not be a subject"
            );
            // A blank claim falls through to the next path.
            assert_eq!(
                get_subject(&token_data, &["sub".to_string(), "oid".to_string()]).unwrap(),
                "real"
            );
        }
    }

    /// The guard and the rule must read the same claim. When they resolve independently, a
    /// `scope` that carries nothing sends the rule to `scp` while the guard still vets
    /// `scope`, and a malformed `scp` passes unchecked.
    #[test]
    fn test_scope_rule_guards_the_claim_it_evaluates() {
        let scope = ScopeRule::new("admin".to_string()).unwrap();
        for empty in [
            serde_json::json!(""),
            serde_json::json!("   "),
            serde_json::json!([]),
            serde_json::json!([""]),
            serde_json::json!({}),
        ] {
            for malformed in [
                serde_json::json!(["admin", 42]),
                serde_json::json!(["admin", true]),
                serde_json::json!(["admin", null]),
            ] {
                let claims = serde_json::json!({ "scope": empty, "scp": malformed });
                assert!(
                    !scope.matches(&claims),
                    "{claims} must not satisfy the scope"
                );
            }
            // The same fallback with well-formed scopes does satisfy it.
            let claims = serde_json::json!({ "scope": empty, "scp": ["admin"] });
            assert!(scope.matches(&claims), "{claims} must satisfy the scope");
        }
    }

    /// `VerifiedClaims::scopes` must report the scopes the requirement enforced against.
    #[test]
    fn test_reported_scopes_are_the_enforced_scopes() {
        let scope = ScopeRule::new("admin".to_string()).unwrap();
        for claims in [
            serde_json::json!({ "scope": "", "scp": ["admin"] }),
            serde_json::json!({ "scope": "   ", "scp": ["admin"] }),
            serde_json::json!({ "scope": [], "scp": ["admin"] }),
            serde_json::json!({ "scope": "admin", "scp": ["other"] }),
        ] {
            let verified = VerifiedClaims::try_from(claims.clone()).unwrap();
            assert_eq!(
                verified.scopes().any(|s| s == "admin"),
                scope.matches(&claims),
                "{claims}: reported scopes disagree with enforcement"
            );
        }
    }

    #[test]
    fn test_scope_failure_is_reported_before_required_claims() {
        let (enc, jwk) = ed25519_fixture();
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "scope": "openid" }),
        );
        let scope = ScopeRule::new("admin".to_string()).unwrap();
        let err =
            verify_with_scope(&jwk, &token, &header, Some(&scope), &[org_rule("x")]).unwrap_err();
        assert_eq!(err.rejection(), Some(&RejectionReason::ScopeMissing));
    }

    #[test]
    fn test_scope_and_caller_rule_failures_are_distinguishable() {
        let (enc, jwk) = ed25519_fixture();
        let scope = ScopeRule::new("admin".to_string()).unwrap();
        let caller = ("scope".to_string(), org_rule("tenant-a").1);
        // Scope satisfied, caller rule fails.
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "scope": "admin" }),
        );
        let err = verify_with_scope(
            &jwk,
            &token,
            &header,
            Some(&scope),
            std::slice::from_ref(&caller),
        )
        .unwrap_err();
        assert_eq!(
            err.rejection(),
            Some(&RejectionReason::ClaimRuleFailed {
                rule: "scope".to_string(),
            })
        );
        // Scope fails, caller rule satisfied.
        let (token, header) = sign(
            &enc,
            serde_json::json!({ "iss": ISS, "aud": AUD, "sub": "u", "organizations": ["tenant-a"] }),
        );
        let err = verify_with_scope(&jwk, &token, &header, Some(&scope), &[caller]).unwrap_err();
        assert_eq!(err.rejection(), Some(&RejectionReason::ScopeMissing));
    }

    // ---- through `Authenticator::authenticate` (introspection + JWKS fetch) ----

    async fn spawn_idp(jwks: serde_json::Value) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{Json, Router, routing::get};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}/", listener.local_addr().unwrap());
        let config = serde_json::json!({ "issuer": issuer, "jwks_uri": format!("{issuer}jwks") });
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { Json(config) }),
            )
            .route("/jwks", get(move || async move { Json(jwks) }));
        let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (issuer, handle)
    }

    /// A JWKS that cannot be fetched at startup does not fail the authenticator. Until a
    /// fetch succeeds, tokens cannot be checked.
    #[tokio::test]
    async fn test_new_succeeds_when_the_jwks_cannot_be_fetched() {
        let (enc, _) = ed25519_fixture();
        let (issuer, server) = spawn_idp(serde_json::json!({ "not": "a JWKS" })).await;
        let authenticator = JWKSWebAuthenticator::new(&issuer, None).await.unwrap();

        let (token, _) = sign(&enc, serde_json::json!({ "iss": issuer, "sub": "u" }));
        let err = authenticator
            .authenticate(&Token::new(&token))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), crate::error::ErrorKind::Unavailable);
        server.abort();
    }

    fn jwks_for(jwk: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "keys": [jwk] })
    }

    /// Without a chain there is no `can_handle_token` routing: a token that omits `aud`
    /// used to pass audience validation and now is rejected.
    #[tokio::test]
    async fn test_authenticate_rejects_token_without_aud_when_audience_configured() {
        let (enc, jwk) = ed25519_fixture();
        let (issuer, server) = spawn_idp(jwks_for(&jwk)).await;
        let authenticator = JWKSWebAuthenticator::new(&issuer, None)
            .await
            .unwrap()
            .set_accepted_audiences(vec![AUD.to_string()]);

        let (token, _) = sign(&enc, serde_json::json!({ "iss": issuer, "sub": "u" }));
        let err = authenticator
            .authenticate(&Token::new(&token))
            .await
            .unwrap_err();
        assert_eq!(
            err.rejection(),
            Some(&RejectionReason::ClaimMissing {
                claim: "aud".to_string()
            })
        );

        let (token, _) = sign(
            &enc,
            serde_json::json!({ "iss": issuer, "aud": AUD, "sub": "u" }),
        );
        let auth = authenticator
            .authenticate(&Token::new(&token))
            .await
            .unwrap();
        assert_eq!(auth.subject().subject_in_idp(), "u");
        server.abort();
    }

    /// The effective issuer list includes the issuer discovered from the provider's
    /// `.well-known` document, which a caller cannot derive from its own configuration.
    #[tokio::test]
    async fn test_effective_issuers_and_audiences_are_readable() {
        let (_, jwk) = ed25519_fixture();
        let (issuer, server) = spawn_idp(jwks_for(&jwk)).await;
        let authenticator = JWKSWebAuthenticator::new(&issuer, None)
            .await
            .unwrap()
            .set_accepted_audiences(vec![AUD.to_string()])
            .add_additional_issuers(vec!["https://sts.example.com".to_string()]);
        assert_eq!(
            authenticator.issuers(),
            [issuer.clone(), "https://sts.example.com".to_string()]
        );
        assert_eq!(authenticator.audiences(), [AUD.to_string()]);
        server.abort();
    }

    /// A token naming a key the IdP does not publish fails to authenticate; the IdP is fine.
    #[tokio::test]
    async fn test_unknown_key_id_is_an_authentication_failure() {
        let (enc, jwk) = ed25519_fixture();
        let (issuer, server) = spawn_idp(jwks_for(&jwk)).await;
        let authenticator = JWKSWebAuthenticator::new(&issuer, None).await.unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("not-in-the-jwks".to_string());
        let token = jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "iss": issuer, "sub": "u", "exp": 9_999_999_999_i64 }),
            &enc,
        )
        .unwrap();
        let err = authenticator
            .authenticate(&Token::new(&token))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Authentication failed: Token key id not found in JWKS."
        );
        assert_eq!(err.kind(), crate::error::ErrorKind::Unauthenticated);
        server.abort();
    }

    /// Without a jsonwebtoken crypto provider, creating the authenticator fails.
    #[test]
    fn test_an_authenticator_needs_a_jwt_crypto_provider() {
        let err = require_crypto_provider(None).unwrap_err();
        assert!(matches!(err, Error::NoJwtCryptoProvider), "{err:?}");
        assert_eq!(err.kind(), crate::error::ErrorKind::Internal);
        crate::install_test_jwt_crypto_provider();
        assert!(require_crypto_provider(CryptoProvider::try_get_default()).is_ok());
    }

    /// A token can name any key the IdP publishes, including an encryption key, which is
    /// not used to verify signatures.
    #[tokio::test]
    async fn test_token_naming_an_encryption_key_is_an_authentication_failure() {
        let (enc, jwk) = ed25519_fixture();
        let mut jwks = jwks_for(&jwk);
        jwks["keys"].as_array_mut().unwrap().push(serde_json::json!({
            "kty": "RSA", "use": "enc", "alg": "RSA-OAEP", "kid": "enc", "n": "AQAB", "e": "AQAB"
        }));
        let (issuer, server) = spawn_idp(jwks).await;
        let authenticator = JWKSWebAuthenticator::new(&issuer, None).await.unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("enc".to_string());
        let token = jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "iss": issuer, "sub": "u", "exp": 9_999_999_999_i64 }),
            &enc,
        )
        .unwrap();
        let err = authenticator
            .authenticate(&Token::new(&token))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Authentication failed: Token key id not found in JWKS."
        );
        assert_eq!(err.kind(), crate::error::ErrorKind::Unauthenticated);
        server.abort();
    }

    #[tokio::test]
    async fn test_clone_shares_configuration() {
        let (_, jwk) = ed25519_fixture();
        let (issuer, server) = spawn_idp(jwks_for(&jwk)).await;
        let authenticator = JWKSWebAuthenticator::new(&issuer, None)
            .await
            .unwrap()
            .set_accepted_audiences(vec![AUD.to_string()]);
        let clone = authenticator.clone();
        assert!(std::sync::Arc::ptr_eq(&authenticator.inner, &clone.inner));
        // Configuring a clone does not affect the original.
        let changed = clone.set_scope("x".to_string()).unwrap();
        assert!(authenticator.inner.scope.is_none());
        assert!(changed.inner.scope.is_some());
        server.abort();
    }

    #[test]
    fn test_get_subject_missing_is_typed_rejection() {
        let token_data = jsonwebtoken::TokenData {
            header: Header::new(Algorithm::EdDSA),
            claims: serde_json::json!({ "iss": ISS }),
        };
        let err = get_subject(&token_data, &["sub".to_string()]).unwrap_err();
        assert_eq!(err.rejection(), Some(&RejectionReason::SubjectClaimMissing));
    }

    #[test]
    fn test_payload_entra_application() {
        let claims = serde_json::json!({
                    "aio": "k2BgYGiZGnb+zdtzaReDdlQfWjHBAgA=",
                    "app_displayname": "ht-testing-lakekeeper-oauth",
                    "appid": "d53edae2-1b58-4c56-a243-xxxxxxxxxxxx",
                    "appidacr": "1",
                    "aud": "00000003-0000-0000-c000-000000000000",
                    "exp": 1_730_052_519,
                    "iat": 1_730_048_619,
                    "idp": "https://sts.windows.net/00000003-1234-0000-c000-000000000000/",
                    "idtyp": "app",
                    "iss": "https://sts.windows.net/00000003-1234-0000-c000-000000000000/",
                    "nbf": 1_730_048_619,
                    "oid": "f621fc83-4ec9-4bf8-bc8d-xxxxxxxxxxxx",
                    "rh": "0.AU8A4hqJeoi7wkGOJROkB9ygQAMAAAAAAAAAwAAAAAAAAABPAAA.",
                    "sub": "f621fc83-4ec9-4bf8-bc8d-xxxxxxxxxxxx",
                    "tenant_region_scope": "EU",
                    "tid": "00000003-1234-0000-c000-000000000000",
                    "uti": "mBOqwjvzLUqboKm591ccAA",
                    "ver": "1.0",
                    "wids": ["0997a1d0-0d1d-4acb-b408-xxxxxxxxxxxx"],
                    "xms_idrel": "7 24",
                    "xms_tcdt": 1_638_946_153,
                    "xms_tdbr": "EU"
        });

        let token_data = jsonwebtoken::TokenData {
            header: Header::new(Algorithm::RS256),
            claims: claims.clone(),
        };

        let payload = extract_authentication(
            Some("idp"),
            token_data,
            &["oid".to_string(), "sub".to_string()],
        )
        .unwrap();

        let subject = Subject::new(
            Some("idp".to_string()),
            "f621fc83-4ec9-4bf8-bc8d-xxxxxxxxxxxx".to_string(),
        );
        let expected_payload = Authentication::builder()
            .subject(subject)
            .identity(VerifiedClaims::try_from(claims.clone()).unwrap())
            .valid_until(
                std::time::SystemTime::UNIX_EPOCH
                    + Duration::from_secs(claims["exp"].as_u64().unwrap()),
            )
            .audiences(HashSet::from([
                "00000003-0000-0000-c000-000000000000".to_string()
            ]))
            .build();

        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn test_payload_entra_human_1() {
        let claims = serde_json::json!({
          "aud": "api://xyz",
          "iss": "https://sts.windows.net/my-tenant-id/",
          "iat": 1_733_673_952,
          "nbf": 1_733_673_952,
          "exp": 1_733_679_587,
          "acr": "1",
          "aio": "...",
          "amr": [
            "pwd",
            "mfa"
          ],
          "appid": "xyz",
          "appidacr": "0",
          "family_name": "Peter",
          "given_name": "Cold",
          "ipaddr": "192.168.5.1",
          "name": "Peter Cold",
          "oid": "user-oid",
          "pwd_exp": "49828",
          "pwd_url": "https://portal.microsoftonline.com/ChangePassword.aspx",
          "scp": "lakekeeper",
          "sub": "user-sub",
          "tid": "my-tenant-id",
          "unique_name": "peter@example.com",
          "upn": "peter@example.com",
          "uti": "...",
          "ver": "1.0"
        });

        let token_data = jsonwebtoken::TokenData {
            header: Header::new(Algorithm::RS256),
            claims: claims.clone(),
        };

        let payload =
            extract_authentication(Some("idp"), token_data, &["oid".to_string()]).unwrap();

        let subject = Subject::new(Some("idp".to_string()), "user-oid".to_string());

        let expected_payload = Authentication::builder()
            .subject(subject)
            .identity(VerifiedClaims::try_from(claims.clone()).unwrap())
            .valid_until(
                std::time::SystemTime::UNIX_EPOCH
                    + Duration::from_secs(claims["exp"].as_u64().unwrap()),
            )
            .audiences(HashSet::from(["api://xyz".to_string()]))
            .build();

        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn test_payload_entra_human_2() {
        let claims = serde_json::json!({
            "acct": 0,
            "acr": "1",
            "aio": "...",
            "amr": ["pwd", "mfa"],
            "app_displayname": "ht-testing-lakekeeper-oauth",
            "appid": "d53edae2-1b58-4c56-a243-xxxxxxxxxxxx",
            "appidacr": "0",
            "aud": "00000003-0000-0000-c000-000000000000",
            "exp": 1_730_054_207,
            "family_name": "Frost",
            "given_name": "Jack",
            "iat": 1_730_049_088,
            "idtyp": "user",
            "ipaddr": "12.206.221.219",
            "iss": "https://sts.windows.net/00000003-1234-0000-c000-000000000000/",
            "name": "Jack Frost",
            "nbf": 1_730_049_088,
            "oid": "eb54b4f5-0d20-46eb-b703-b1c910262e89",
            "platf": "14",
            "puid": "100320025A52FAC4",
            "rh": "0.AU8A4hqJeoi7wkGOJROkB9ygQAMAAAAAAAAAwAAAAAAAAABPAJo.",
            "scp": "openid profile User.Read email",
            "signin_state": ["kmsi"],
            "sub": "SFUpMUKjypW6q3w3Vc9u8N3LNAGlZmIrmGdvQVN53AI",
            "tenant_region_scope": "EU",
            "tid": "00000003-1234-0000-c000-000000000000",
            "unique_name": "jack@example.com",
            "upn": "jack@example.com",
            "uti": "FXRr3wnAA0e8YADs1adQAA",
            "ver": "1.0",
            "wids": ["62e90394-69f5-4237-9190-xxxxxxxxxxxx",
                    "b79fbf4d-3ef9-4689-8143-xxxxxxxxxxxx"],
            "xms_idrel": "1 8",
            "xms_st": {"sub": "VZ5XLBqhasu6qISBjalO9e45lQjr_EyLLtKzCFcWw-8"},
            "xms_tcdt": 1_638_946_153,
            "xms_tdbr": "EU"
        });

        let token_data = jsonwebtoken::TokenData {
            header: Header::new(Algorithm::RS256),
            claims: claims.clone(),
        };

        let payload =
            extract_authentication(Some("idp"), token_data, &["oid".to_string()]).unwrap();

        let subject = Subject::new(
            Some("idp".to_string()),
            "eb54b4f5-0d20-46eb-b703-b1c910262e89".to_string(),
        );

        let expected_payload = Authentication::builder()
            .subject(subject)
            .identity(VerifiedClaims::try_from(claims.clone()).unwrap())
            .valid_until(
                std::time::SystemTime::UNIX_EPOCH
                    + Duration::from_secs(claims["exp"].as_u64().unwrap()),
            )
            .audiences(HashSet::from([
                "00000003-0000-0000-c000-000000000000".to_string()
            ]))
            .build();

        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn test_payload_keycloak_human() {
        let claims = serde_json::json!({
          "exp": 1_729_990_458,
          "iat": 1_729_990_158,
          "jti": "97cdc5d9-8717-4826-a425-30c6682342b4",
          "iss": "http://localhost:30080/realms/iceberg",
          "aud": "account",
          "sub": "f1616ed0-18d8-48ea-9fb3-832f42db0b1b",
          "typ": "Bearer",
          "azp": "iceberg-catalog",
          "sid": "6f2ca33d-2513-43fe-ab53-4a945c78a66d",
          "acr": "1",
          "allowed-origins": [
            "*"
          ],
          "realm_access": {
            "roles": [
              "offline_access",
              "uma_authorization",
              "default-roles-iceberg"
            ]
          },
          "resource_access": {
            "account": {
              "roles": [
                "manage-account",
                "manage-account-links",
                "view-profile"
              ]
            }
          },
          "scope": "openid email profile",
          "email_verified": true,
          "name": "Peter Cold",
          "preferred_username": "peter",
          "given_name": "Peter",
          "family_name": "Cold",
          "email": "peter@example.com"
        });

        let token_data = jsonwebtoken::TokenData {
            header: Header::new(Algorithm::RS256),
            claims: claims.clone(),
        };

        let payload =
            extract_authentication(Some("idp"), token_data.clone(), &["sub".to_string()]).unwrap();

        let subject = Subject::new(
            Some("idp".to_string()),
            "f1616ed0-18d8-48ea-9fb3-832f42db0b1b".to_string(),
        );

        let expected_payload = Authentication::builder()
            .subject(subject.clone())
            .identity(VerifiedClaims::try_from(claims.clone()).unwrap())
            .valid_until(
                std::time::SystemTime::UNIX_EPOCH
                    + Duration::from_secs(claims["exp"].as_u64().unwrap()),
            )
            .audiences(HashSet::from(["account".to_string()]))
            .build();

        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn test_payload_keycloak_machine() {
        let claims = serde_json::json!({
          "exp": 1_730_050_563,
          "iat": 1_730_050_563,
          "jti": "b1e96701-b718-4714-88a2-d25d985c38ed",
          "iss": "http://keycloak:8080/realms/iceberg",
          "aud": [
            "iceberg-catalog",
            "account"
          ],
          "sub": "b6cc7aa0-1af0-460e-9174-e05c881fb6d4",
          "typ": "Bearer",
          "azp": "iceberg-machine-client",
          "acr": "1",
          "allowed-origins": [
            "/*"
          ],
          "realm_access": {
            "roles": [
              "offline_access",
              "uma_authorization",
              "default-roles-iceberg"
            ]
          },
          "resource_access": {
            "iceberg-machine-client": {
              "roles": [
                "uma_protection"
              ]
            },
            "account": {
              "roles": [
                "manage-account",
                "manage-account-links",
                "view-profile"
              ]
            }
          },
          "scope": "email profile",
          "clientHost": "10.89.0.2",
          "email_verified": false,
          "preferred_username": "service-account-iceberg-machine-client",
          "clientAddress": "10.89.0.2",
          "client_id": "iceberg-machine-client"
        });

        let token_data = jsonwebtoken::TokenData {
            header: Header::new(Algorithm::RS256),
            claims: claims.clone(),
        };

        let payload =
            extract_authentication(Some("idp"), token_data.clone(), &["sub".to_string()]).unwrap();

        let subject = Subject::new(
            Some("idp".to_string()),
            "b6cc7aa0-1af0-460e-9174-e05c881fb6d4".to_string(),
        );

        let expected_payload = Authentication::builder()
            .subject(subject.clone())
            .identity(VerifiedClaims::try_from(claims.clone()).unwrap())
            .valid_until(
                std::time::SystemTime::UNIX_EPOCH
                    + Duration::from_secs(claims["exp"].as_u64().unwrap()),
            )
            .audiences(HashSet::from([
                "iceberg-catalog".to_string(),
                "account".to_string(),
            ]))
            .build();

        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn test_payload_missing_aud_claim_yields_empty_audiences() {
        // A token with no "aud" field at all.  parse_aud() receives None and must
        // fall through its unwrap_or_default() branch, returning an empty HashSet
        // without panicking.
        let claims = serde_json::json!({
            "sub": "some-subject",
            "iss": "https://example.com/",
            "iat": 1_730_048_619,
            "exp": 1_730_052_519,
            "name": "Test User"
        });

        let token_data = jsonwebtoken::TokenData {
            header: Header::new(Algorithm::RS256),
            claims: claims.clone(),
        };

        let payload =
            extract_authentication(Some("idp"), token_data, &["sub".to_string()]).unwrap();

        assert_eq!(payload.audiences(), &HashSet::new());
    }
}
