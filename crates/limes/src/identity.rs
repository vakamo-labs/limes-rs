use std::{collections::BTreeMap, sync::Arc};

use typed_builder::TypedBuilder;

/// The issuer claim, which JWT validation requires.
pub(crate) const ISSUER_CLAIM: &str = "iss";
/// The space-delimited OAuth `scope` claim.
pub(crate) const SCOPE_CLAIM: &str = "scope";
/// Array-shaped alternative to `scope` emitted by some identity providers; read when `scope` is
/// absent or carries no scopes.
pub(crate) const SCP_CLAIM: &str = "scp";

/// The `scope` claim, or `scp` if `scope` carries no scopes.
///
/// Resolved through [`crate::claims::resolve`], the one owner of that choice, so the scope
/// requirement and [`VerifiedClaims::scopes`] always read the same claim.
pub(crate) fn scope_claim(claims: &serde_json::Value) -> Option<&serde_json::Value> {
    crate::claims::resolve(claims, [SCOPE_CLAIM, SCP_CLAIM])
}

/// A time claim of a JWT, such as `exp`, as a time rounded down to the second.
///
/// Reads every JSON number, so it is never later than the reading of a verifier: jsonwebtoken
/// accepts an integer or a non-negative float and rounds it; the Kubernetes API server truncates.
/// A negative value is the Unix epoch. `None` if the value is not a number, or too far in the
/// future for a [`SystemTime`](std::time::SystemTime).
#[cfg(any(feature = "jwks", feature = "kubernetes"))]
pub(crate) fn numeric_date(value: &serde_json::Value) -> Option<std::time::SystemTime> {
    use std::time::{Duration, SystemTime};
    let exp = value;
    let seconds = match exp.as_u64() {
        Some(seconds) => seconds,
        // A negative `exp`, or one with a fraction. JSON numbers are finite.
        None => Duration::try_from_secs_f64(exp.as_f64()?.max(0.0))
            .ok()?
            .as_secs(),
    };
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
}

/// What the identity provider states about the subject of a token, as it stated it.
///
/// limes adds variants for new kinds of identity providers, so match with a wildcard arm.
/// An [`Authenticator`](crate::Authenticator) of your own reports the attributes it verified
/// as [`Identity::Claims`].
///
/// ```
/// use limes::{Authentication, Identity};
///
/// fn display_name(authentication: &Authentication) -> Option<&str> {
///     match authentication.identity() {
///         Identity::Claims(claims) => claims.name(),
///         Identity::Kubernetes(user) => user.username(),
///         _ => None,
///     }
/// }
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum Identity {
    /// The claims of a verified token, such as the payload of a JWT.
    Claims(VerifiedClaims),
    /// The user a Kubernetes `TokenReview` authenticated.
    Kubernetes(KubernetesUser),
}

impl From<VerifiedClaims> for Identity {
    fn from(claims: VerifiedClaims) -> Self {
        Self::Claims(claims)
    }
}

impl From<KubernetesUser> for Identity {
    fn from(user: KubernetesUser) -> Self {
        Self::Kubernetes(user)
    }
}

/// The claims of a token, as a JSON object.
///
/// "Verified" is the promise of the [`Authenticator`](crate::Authenticator) that returns them:
/// it checked the token's signature or asked its issuer. Clones share the claims.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VerifiedClaims(Arc<serde_json::Value>);

impl VerifiedClaims {
    /// Claims an authenticator verified. For a JWT, the payload.
    #[must_use]
    pub fn new(claims: serde_json::Map<String, serde_json::Value>) -> Self {
        Self(Arc::new(serde_json::Value::Object(claims)))
    }

    /// All claims, a JSON object.
    #[must_use]
    pub fn as_json(&self) -> &serde_json::Value {
        &self.0
    }

    /// The claim at `path`. The path nests on every dot (`resource_access.account.roles`),
    /// or names one claim outright when it contains `/` or `:`, as in claim rules.
    #[must_use]
    pub fn claim(&self, path: &str) -> Option<&serde_json::Value> {
        crate::claims::navigate(&self.0, path)
    }

    /// The OpenID Connect `name` claim, if it is a string.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.string("name")
    }

    /// The OpenID Connect `email` claim, if it is a string.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.string("email")
    }

    /// The OpenID Connect `email_verified` claim, if it is a boolean.
    #[must_use]
    pub fn email_verified(&self) -> Option<bool> {
        self.0
            .get("email_verified")
            .and_then(serde_json::Value::as_bool)
    }

    /// The OpenID Connect `preferred_username` claim, if it is a string.
    #[must_use]
    pub fn preferred_username(&self) -> Option<&str> {
        self.string("preferred_username")
    }

    /// The issuer (`iss`), if it is a string.
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.string(ISSUER_CLAIM)
    }

    /// The expiry (`exp`) in seconds since the Unix epoch, if it is an integer.
    #[must_use]
    pub fn expires_at(&self) -> Option<i64> {
        self.0.get("exp").and_then(serde_json::Value::as_i64)
    }

    /// The issue time (`iat`) in seconds since the Unix epoch, if it is an integer.
    #[must_use]
    pub fn issued_at(&self) -> Option<i64> {
        self.0.get("iat").and_then(serde_json::Value::as_i64)
    }

    /// The start of validity (`nbf`) in seconds since the Unix epoch, if it is an integer.
    #[must_use]
    pub fn not_before(&self) -> Option<i64> {
        self.0.get("nbf").and_then(serde_json::Value::as_i64)
    }

    /// The scopes from the `scope` claim, or `scp` if `scope` is absent or carries no scopes.
    ///
    /// Values are read exactly as scope enforcement reads them: a lone string is split on
    /// whitespace, while an array states one scope per element, so its strings are returned
    /// whole and never split. Anything else (an object, a number, or an array holding
    /// non-strings) is malformed and yields nothing. Returns an empty iterator if neither
    /// claim is present.
    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        let (items, split) = scope_claim(&self.0)
            .and_then(crate::claims::strings)
            .unwrap_or((&[], false));
        // `strings` rejects non-strings, so a malformed claim yields nothing — the same
        // reading the scope requirement enforces.
        crate::claims::ClaimValues::new(items, Some(&crate::claims::Separator::Whitespace), split)
            .filter_map(|v| match v {
                std::borrow::Cow::Borrowed(s) => Some(s),
                std::borrow::Cow::Owned(_) => None,
            })
    }

    fn string(&self, claim: &str) -> Option<&str> {
        self.0.get(claim).and_then(serde_json::Value::as_str)
    }
}

impl Default for VerifiedClaims {
    /// No claims.
    fn default() -> Self {
        Self::new(serde_json::Map::new())
    }
}

impl TryFrom<serde_json::Value> for VerifiedClaims {
    /// The value, if it is not a JSON object.
    type Error = serde_json::Value;

    fn try_from(claims: serde_json::Value) -> Result<Self, Self::Error> {
        match claims {
            serde_json::Value::Object(claims) => Ok(Self::new(claims)),
            other => Err(other),
        }
    }
}

/// The user a Kubernetes `TokenReview` authenticated, as the API server returned it.
#[derive(Debug, PartialEq, Eq, Clone, TypedBuilder)]
pub struct KubernetesUser {
    #[builder(default, setter(into, strip_option(fallback = username_opt)))]
    username: Option<String>,
    #[builder(default, setter(into, strip_option(fallback = uid_opt)))]
    uid: Option<String>,
    #[builder(default)]
    groups: Vec<String>,
    #[builder(default)]
    extra: BTreeMap<String, Vec<String>>,
}

impl KubernetesUser {
    /// The name of the user, for a service account `system:serviceaccount:<namespace>:<name>`.
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// A unique id of the user, if the authenticator of the API server provides one.
    #[must_use]
    pub fn uid(&self) -> Option<&str> {
        self.uid.as_deref()
    }

    /// The groups the user belongs to.
    #[must_use]
    pub fn groups(&self) -> &[String] {
        &self.groups
    }

    /// Further information the authenticator of the API server provided.
    #[must_use]
    pub fn extra(&self) -> &BTreeMap<String, Vec<String>> {
        &self.extra
    }

    /// `extra` as a JSON object, the claims that claim rules read.
    pub(crate) fn extra_as_json(&self) -> serde_json::Value {
        serde_json::Value::Object(
            self.extra
                .iter()
                .map(|(key, values)| (key.clone(), values.clone().into()))
                .collect(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn claims(claims: serde_json::Value) -> VerifiedClaims {
        VerifiedClaims::try_from(claims).unwrap()
    }

    #[test]
    fn test_verified_claims_read_the_standard_claims_as_given() {
        let claims = claims(serde_json::json!({
            "name": "Jane Doe",
            "email": "jane@example.com",
            "email_verified": true,
            "preferred_username": "jane",
            "realm_access": { "roles": ["reader"] },
            "https://example.com/tier": "gold",
        }));
        assert_eq!(claims.name(), Some("Jane Doe"));
        assert_eq!(claims.email(), Some("jane@example.com"));
        assert_eq!(claims.email_verified(), Some(true));
        assert_eq!(claims.preferred_username(), Some("jane"));
        assert_eq!(
            claims.claim("realm_access.roles"),
            Some(&serde_json::json!(["reader"]))
        );
        assert_eq!(
            claims.claim("https://example.com/tier"),
            Some(&serde_json::json!("gold"))
        );
    }

    #[test]
    fn test_verified_claims_of_other_types_are_absent() {
        let claims = claims(serde_json::json!({
            "name": 42,
            "email": ["jane@example.com"],
            "email_verified": "true",
        }));
        assert_eq!(claims.name(), None);
        assert_eq!(claims.email(), None);
        assert_eq!(claims.email_verified(), None);
        assert_eq!(claims.preferred_username(), None);
    }

    #[test]
    fn test_verified_claims_are_a_json_object() {
        assert_eq!(
            VerifiedClaims::try_from(serde_json::json!(["a"])),
            Err(serde_json::json!(["a"]))
        );
        assert_eq!(VerifiedClaims::default().as_json(), &serde_json::json!({}));
    }

    #[test]
    fn test_metadata_accessors_present() {
        let claims = claims(serde_json::json!({
            "iss": "https://issuer.example.com",
            "exp": 1_730_052_519,
            "iat": 1_730_048_619,
            "nbf": 1_730_048_619,
            "scope": "openid profile email",
        }));

        assert_eq!(claims.issuer(), Some("https://issuer.example.com"));
        assert_eq!(claims.expires_at(), Some(1_730_052_519));
        assert_eq!(claims.issued_at(), Some(1_730_048_619));
        assert_eq!(claims.not_before(), Some(1_730_048_619));
        assert_eq!(
            claims.scopes().collect::<Vec<_>>(),
            ["openid", "profile", "email"]
        );
    }

    #[test]
    fn test_metadata_accessors_absent() {
        let claims = claims(serde_json::json!({ "sub": "x" }));

        assert_eq!(claims.issuer(), None);
        assert_eq!(claims.expires_at(), None);
        assert_eq!(claims.issued_at(), None);
        assert_eq!(claims.not_before(), None);
        assert_eq!(claims.scopes().count(), 0);
    }

    #[test]
    fn test_scopes_accepts_array_claim() {
        let claims = claims(serde_json::json!({ "scope": ["openid", "email"] }));
        assert_eq!(claims.scopes().collect::<Vec<_>>(), ["openid", "email"]);
    }

    #[test]
    fn test_scopes_falls_back_to_scp() {
        let scopes = |value| claims(value).scopes().map(String::from).collect::<Vec<_>>();
        assert_eq!(
            scopes(serde_json::json!({ "scp": ["openid", "email"] })),
            ["openid", "email"]
        );
        assert_eq!(
            scopes(serde_json::json!({ "scp": "openid email" })),
            ["openid", "email"]
        );
        // `scope` present wins, even when `scp` is also present.
        assert_eq!(
            scopes(serde_json::json!({ "scope": "a", "scp": "b" })),
            ["a"]
        );
    }

    /// The array form of `scope` states one scope per element, so elements are not split.
    #[test]
    fn test_scopes_does_not_split_array_elements() {
        let claims = claims(serde_json::json!({ "scope": ["openid profile", "email"] }));
        assert_eq!(
            claims.scopes().collect::<Vec<_>>(),
            ["openid profile", "email"]
        );
    }

    #[test]
    fn test_scopes_of_claim_with_numbers_or_booleans_are_empty_like_enforcement() {
        let claims_with = |value| claims(serde_json::json!({ "scope": value }));
        assert_eq!(
            claims_with(serde_json::json!(["admin", 42, true]))
                .scopes()
                .count(),
            0
        );
        assert_eq!(claims_with(serde_json::json!(42)).scopes().count(), 0);
    }

    #[test]
    fn test_scopes_of_malformed_claim_are_empty_like_enforcement() {
        let claims_with = |value| claims(serde_json::json!({ "scope": value }));
        assert_eq!(
            claims_with(serde_json::json!(["admin", {"k": "v"}]))
                .scopes()
                .count(),
            0
        );
        assert_eq!(
            claims_with(serde_json::json!(["admin", null]))
                .scopes()
                .count(),
            0
        );
    }

    #[test]
    #[cfg(any(feature = "jwks", feature = "kubernetes"))]
    fn test_numeric_date_reads_every_number_rounded_down() {
        use std::time::{Duration, SystemTime};
        let at = |seconds| Some(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds));
        let expiry = |exp: serde_json::Value| numeric_date(&exp);
        assert_eq!(expiry(serde_json::json!(1_730_052_519)), at(1_730_052_519));
        assert_eq!(
            expiry(serde_json::json!(1_730_052_519.9)),
            at(1_730_052_519)
        );
        assert_eq!(expiry(serde_json::json!(-5)), at(0));
        assert_eq!(expiry(serde_json::json!(-5.5)), at(0));
        assert_eq!(expiry(serde_json::json!("1730052519")), None);
        assert_eq!(expiry(serde_json::json!(null)), None);
        assert_eq!(expiry(serde_json::json!(1e300)), None);
    }

    #[test]
    fn test_kubernetes_user_extra_as_json() {
        let user = KubernetesUser::builder()
            .username("system:serviceaccount:ns:sa")
            .uid_opt(None)
            .extra(BTreeMap::from([(
                "email".to_string(),
                vec!["sa@example.com".to_string()],
            )]))
            .build();
        assert_eq!(user.username(), Some("system:serviceaccount:ns:sa"));
        assert_eq!(user.uid(), None);
        assert_eq!(
            user.extra_as_json(),
            serde_json::json!({ "email": ["sa@example.com"] })
        );
    }
}
