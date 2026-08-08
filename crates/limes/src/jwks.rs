//! Validate JWT tokens locally using JWKS keys fetched from a remote server.

use crate::authenticator::SCOPE_CLAIM;
use crate::introspect::IntrospectionResult;
use crate::{
    Authentication, Authenticator, PrincipalType, Subject,
    error::{Error, Result},
};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use jwks_client_rs::source::WebSource;
use jwks_client_rs::{JsonWebKey, JwksClient};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const SUBJECT_CLAIM: &str = "sub";
const IDTYP_CLAIM: &str = "idtyp";
const APP_DISPLAYNAME_CLAIM: &str = "app_displayname";
const NAME_CLAIM: &str = "name";
const AUD_CLAIM: &str = "aud";

#[derive(Clone)]
/// Validate JWT tokens using JWKS keys fetched from a remote server.
/// Keys are refreshed regularly if `ttl` is set during initialization.
///
/// If you don't want to validate the audience, pass an empty slice for `audiences`.
/// Audience check passes if the token audience is among the provided audiences.
///
/// The provided `issuer_url` must provide a `/.well-known/openid-configuration` endpoint.
/// Provided tokens must have their issuer set to the `issuer` field of the fetched configuration
/// or to one of the `additional_issuers`.
///
/// `additional_issuers` can be used to add additional issuers to the list of issuers that are
/// accepted. This is useful if the `IdP` is reachable under multiple URLs.
///
/// If `scope` is provided, the token must contain the provided scope.
///
/// If `ttl` is provided, the JWKS keys will be cached for the provided duration.
/// Otherwise, the keys will be cached indefinitely. We recommend setting a TTL, as
/// the keys may change over time.
///
/// Some `IdPs`, like Azure, use the `oid` field to identify users across applications.
/// Set `subject_claim` to `oid` if you want to use this field as the subject.
/// If `subject_claim` is not set, the `sub` field will be used as the subject. (Default)
///
///
/// **Payload Field Mappings**:
/// - `name`: `name` or `given_name`/ `first_name` and `family_name`/ `last_name` or `app_displayname` or `preferred_username`;
///   if none are present and a display-name template is configured, it is rendered from the claims (see [`JWKSWebAuthenticator::with_display_name_template`])
/// - `subject`: `sub` unless `subject_claim` is set, then it will be the value of the claim.
/// - `claims`: all claims
/// - `email`: `email` or `upn` if it contains an `@` or `preferred_username` if it contains an `@`
/// - `principal_type`: inferred from the claims - `idtyp`, then the presence of a human-name
///   claim (`Human`), an `app_displayname`/`client_id` claim (`Application`); `None` if undetermined.
///
pub struct JWKSWebAuthenticator {
    idp_id: Option<String>,
    audiences: Vec<String>,
    client: JwksClient<WebSource>,
    issuers: Vec<String>,
    scope: Option<String>,
    config_url: url::Url,
    subject_claim: Vec<String>,
    role_claims: Option<Vec<String>>,
    display_name_template: Option<DisplayNameTemplate>,
}

impl JWKSWebAuthenticator {
    const WELL_KNOWN_CONFIG: &'static str = ".well-known/openid-configuration";

    /// Create a new [`JWKSWebAuthenticator`].
    ///
    /// # Arguments
    /// - `idp_id`: The unique identifier of the IdP this authenticator is for. Use `None` for single tenant applications.
    /// - `issuer_url`: The URL of the `IdP` to fetch the JWKS keys from. Must provide a `/.well-known/openid-configuration` endpoint.
    /// - `ttl`: The time to live for the JWKS keys. If `None`, the keys will be cached indefinitely (not recommended).
    ///
    /// # Errors
    /// - If the `issuer_url` is not a valid URL.
    /// - If the `issuer_url` does not provide a `/.well-known/openid-configuration` endpoint.
    /// - If the fetched configuration does not contain the required fields.
    pub async fn new(issuer_url: &str, ttl: Option<Duration>) -> Result<Self> {
        let (client, issuer, config_url) =
            JWKSWebAuthenticator::initialize_client(issuer_url, ttl).await?;
        Ok(Self {
            idp_id: None,
            client,
            issuers: vec![issuer],
            audiences: Vec::new(),
            scope: None,
            config_url,
            subject_claim: vec![SUBJECT_CLAIM.to_string()],
            role_claims: None,
            display_name_template: None,
        })
    }

    /// Set the IdP id for the authenticator.
    /// Setting the id is required for multi-tenant applications.
    #[must_use]
    pub fn set_idp_id(mut self, idp_id: &str) -> Self {
        if !idp_id.is_empty() {
            self.idp_id = Some(idp_id.to_string());
        }
        self
    }

    /// Set the accepted audiences.
    /// If empty / not called, no audience validation is done.
    #[must_use]
    pub fn set_accepted_audiences(mut self, audiences: Vec<String>) -> Self {
        self.audiences = audiences;
        self
    }

    /// Add additional issuers to the authenticator.
    /// If empty, only the issuer from the fetched configuration is accepted.
    #[must_use]
    pub fn add_additional_issuers(mut self, additional_issuers: Vec<String>) -> Self {
        // Make sure to not add duplicates
        let additional_issuers: Vec<_> = additional_issuers
            .into_iter()
            .filter(|issuer| !self.issuers.contains(issuer))
            .collect();
        self.issuers.extend(additional_issuers);
        self
    }

    /// Add a scope to the authenticator.
    /// If not called, no scope validation is done.
    #[must_use]
    pub fn set_scope(mut self, scope: String) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Set the claim to use as the subjects id.
    /// If `None`, the `sub` claim will be used.
    #[must_use]
    pub fn with_subject_claim(mut self, subject_claim: String) -> Self {
        self.subject_claim = vec![subject_claim];
        self
    }

    /// Set multiple claims to use as the subjects id.
    /// Overrides any previously set claims.
    /// If multiple claims are set, the first one that is found in the token will be used.
    ///
    /// If this function is called with an empty vector, the previously set claim will be used,
    /// by default this is the `sub` claim.
    #[must_use]
    pub fn with_subject_claims(mut self, subject_claims: Vec<String>) -> Self {
        // Setting multiple claims can be useful in multi-tenant applications.
        // For entra-id most applications that
        // interact with other applications should prefer the `oid` claim over the `sub` claim.
        if !subject_claims.is_empty() {
            self.subject_claim = subject_claims;
        }
        self
    }

    /// Set the field in the claims to extract roles from.
    /// If not called, no roles will be extracted.
    ///
    /// The field should contain an array of strings or a single string.
    /// Supports nested claims using dot notation, e.g., "resource_access.account.roles"
    ///
    /// Empty strings are ignored. If an empty string is provided, role claims will not be set.
    #[must_use]
    pub fn with_role_claim(self, role_claim: String) -> Self {
        self.with_role_claims(vec![role_claim])
    }

    /// Set multiple claims in the token to extract roles from.
    /// Overrides any previously set role claims.
    /// If multiple claims are set, the first one that is found in the token will be used.
    ///
    /// Supports nested claims using dot notation, e.g., "resource_access.account.roles"
    ///
    /// Empty strings are filtered out. If only empty strings are provided, role claims will not be set.
    #[must_use]
    pub fn with_role_claims(mut self, role_claims: Vec<String>) -> Self {
        let filtered: Vec<String> = role_claims.into_iter().filter(|s| !s.is_empty()).collect();
        if filtered.is_empty() {
            self.role_claims = None;
        } else {
            self.role_claims = Some(filtered);
        }
        self
    }

    /// Set a template used to derive the display name when a token carries no
    /// name claim (none of `name` / `given_name`+`family_name` / `app_displayname` /
    /// `preferred_username`). Placeholders of the form `{claim.path}` are
    /// substituted with the string value at that (dot-notation) claim path;
    /// `{email}` and `{sub}` are the common cases. Write a literal brace by
    /// doubling it (`{{`/`}}`), as in [`std::fmt`]. If any referenced claim is
    /// absent or not a string the template does not apply and the name is left
    /// unset (so the caller keeps its own fallback).
    ///
    /// Takes an already-parsed [`DisplayNameTemplate`] (build one with
    /// [`DisplayNameTemplate::parse`] or `str::parse`), so this setter is
    /// infallible: the template is valid by construction, and a malformed one is
    /// rejected at parse time rather than silently never rendering.
    ///
    /// Typical use is a machine / service-account issuer, e.g.
    /// `DisplayNameTemplate::parse("Service Account {email}")`.
    #[must_use]
    pub fn with_display_name_template(mut self, template: DisplayNameTemplate) -> Self {
        self.display_name_template = Some(template);
        self
    }

    async fn initialize_client(
        issuer_url: &str,
        ttl: Option<Duration>,
    ) -> Result<(JwksClient<WebSource>, String, url::Url)> {
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

        let config = Arc::new(
            reqwest::get(url.clone())
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
                })?,
        );
        let issuer = config.issuer.clone();
        let source = WebSource::builder()
            .build(config.jwks_uri.clone())
            .map_err(|e| {
                tracing::debug!("Failed to fetch openid configuration from '{url}': {e}");
                Error::FetchOpenIDWellKnownConfigError {
                    url: url.to_string(),
                    source: e,
                }
            })?;
        let client = JwksClient::builder();
        let client = if let Some(ttl) = ttl {
            client.time_to_live(ttl)
        } else {
            client
        };
        let client = client.build(source);
        Ok((client, issuer, url))
    }
}

impl Authenticator for JWKSWebAuthenticator {
    async fn authenticate(
        &self,
        token: &str,
        introspection: &IntrospectionResult,
    ) -> Result<Authentication> {
        // Reuse the header decoded during introspection instead of decoding the token again.
        let IntrospectionResult::JWTBearer { header, .. } = introspection else {
            return Err(Error::JWTDecodeError {
                reason: "Token is not a JWT bearer token.".to_string(),
            });
        };
        let key_id = header.kid.as_deref().ok_or_else(|| Error::JWTDecodeError {
            reason: "Token does not contain a key id".to_string(),
        })?;
        let key = self
            .client
            .get_opt(key_id)
            .await
            .map_err(|e| Error::RefreshOpenIDWellKnownConfigError {
                url: self.config_url.to_string(),
                reason: e.to_string(),
            })?
            .ok_or_else(|| {
                Error::unauthenticated(format!("Key id `{key_id}` not found in JWKS."))
            })?;
        let token_data = authenticate_jwt(
            token,
            header,
            &key,
            &self.audiences,
            &self.issuers,
            self.scope.as_deref(),
        )?;

        extract_authentication(
            self.idp_id().map(String::as_str),
            token_data,
            &self.subject_claim,
            self.role_claims.as_deref(),
            self.display_name_template.as_ref(),
        )
    }

    fn idp_id(&self) -> Option<&String> {
        self.idp_id.as_ref()
    }

    fn can_handle_token(&self, token: &str, introspection_result: &IntrospectionResult) -> bool {
        if token.is_empty() {
            return false;
        }

        match introspection_result {
            IntrospectionResult::JWTBearer {
                iss,
                aud,
                header: _,
            } => {
                (self.issuers.is_empty() || self.issuers.iter().any(|i| iss.contains(i)))
                    && (self.audiences.is_empty() || self.audiences.iter().any(|a| aud.contains(a)))
            }
            IntrospectionResult::Unknown => false,
        }
    }
}

fn authenticate_jwt(
    token: &str,
    header: &Header,
    key: &JsonWebKey,
    audiences: &[String],
    issuers: &[String],
    scope: Option<&str>,
) -> Result<jsonwebtoken::TokenData<serde_json::Value>> {
    let mut validation = if let Some(alg) = key.alg() {
        Validation::new(Algorithm::from_str(alg).map_err(|e| {
            Error::internal(
                format!(
                    "Failed to parse algorithm `{alg}` from key obtained from the jwks endpoint."
                ),
                e,
            )
        })?)
    } else {
        // Some IdPs, like Azure, don't include the alg field in the jwks endpoint.
        // In this case we trust the provided algorithm in the clients token.
        Validation::new(header.alg)
    };

    if audiences.is_empty() {
        validation.validate_aud = false;
    } else {
        validation.set_audience(audiences);
        validation.validate_aud = true;
    }
    validation.set_issuer(issuers);

    let decoding_key = match key {
        JsonWebKey::Rsa(jwk) => DecodingKey::from_rsa_components(jwk.modulus(), jwk.exponent())
            .map_err(|e| {
                Error::internal("Failed to create rsa decoding key from key components.", e)
            })?,
        JsonWebKey::Ec(jwk) => DecodingKey::from_ec_components(jwk.x(), jwk.y()).map_err(|e| {
            Error::internal("Failed to create ec decoding key from key components.", e)
        })?,
        JsonWebKey::Okp(jwk) => DecodingKey::from_ed_components(jwk.x()).map_err(|e| {
            Error::internal("Failed to create okp decoding key from key components.", e)
        })?,
    };

    let token_data = jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
        .map_err(|e| Error::JWTDecodeError {
        reason: format!("Failed to decode JWT token. {e}"),
    })?;

    if let Some(required_scope) = scope {
        let scope_claim = token_data
            .claims
            .get(SCOPE_CLAIM)
            .and_then(serde_json::Value::as_str);
        if !scope_claim_contains(scope_claim, required_scope) {
            return Err(Error::unauthenticated(format!(
                "Token does not contain required scope `{required_scope}`."
            )));
        }
    }

    Ok(token_data)
}

fn extract_authentication(
    idp_id: Option<&str>,
    token_data: jsonwebtoken::TokenData<serde_json::Value>,
    subject_claim: &[String],
    role_claims: Option<&[String]>,
    display_name_template: Option<&DisplayNameTemplate>,
) -> Result<Authentication> {
    let subject_in_idp = get_subject(&token_data, subject_claim)?;
    let header = token_data.header;
    let claims = token_data.claims;

    let subject = Subject::new(idp_id.map(ToString::to_string), subject_in_idp);

    // `parse_human_name` already returns the `name` claim when present, so a separate
    // `name` lookup would be redundant.
    let human_name = parse_human_name(&claims);
    let app_name = claims.get(APP_DISPLAYNAME_CLAIM).and_then(value_as_string);

    let principal_type = get_idp_type(&claims)
        // If idp type is not set, try to infer it from the claims
        .or(human_name.as_ref().map(|_t| PrincipalType::Human))
        .or(app_name.as_ref().map(|_t| PrincipalType::Application))
        // In Keycloak the client_id is the requesting application
        .or(claims.get("client_id").map(|_t| PrincipalType::Application));

    // Fall back lazily so we only allocate the username string when nothing better matched.
    let name = human_name
        .or(app_name)
        .or_else(|| claims.get("preferred_username").and_then(value_as_string))
        // Last resort for tokens that carry no name claim at all (e.g. machine /
        // service-account tokens): render the configured display-name template.
        .or_else(|| display_name_template.and_then(|t| t.render(&claims)));

    let roles = get_roles(&claims, role_claims);
    let audiences = crate::introspect::parse_aud(claims.get(AUD_CLAIM));
    let email = get_email(&claims);

    Ok(Authentication::builder()
        .token_header(Some(header))
        .name(name)
        .email(email)
        .subject(subject)
        .principal_type(principal_type)
        .roles(roles)
        .audiences(audiences)
        // Move the claims in last; everything above only borrows them, so no clone is needed.
        .claims(claims)
        .build())
}

fn get_idp_type(claims: &serde_json::Value) -> Option<PrincipalType> {
    match claims.get(IDTYP_CLAIM).and_then(|v| v.as_str()) {
        Some("user") => Some(PrincipalType::Human),
        Some("app" | "device") => Some(PrincipalType::Application),
        _ => None,
    }
}

fn get_email(claims: &serde_json::Value) -> Option<String> {
    claims
        .get("email")
        .and_then(value_as_string)
        .or(claims
            .get("upn")
            .and_then(value_as_string)
            .filter(|s| s.contains('@')))
        .or(claims
            .get("preferred_username")
            .and_then(value_as_string)
            .filter(|s| s.contains('@')))
}

/// Extracts roles from JWT claims by checking configured claim paths.
///
/// # Behavior
/// - Iterates through provided claim paths in order, returning the first non-empty match
/// - For array values: filters out non-string elements (numbers, objects, nulls, etc.)
/// - If an array exists but contains only non-strings, continues to the next path
/// - If an explicitly empty array is found, continues to the next path
/// - For single values: returns if the value is a string, otherwise continues
/// - Returns `None` if no claim paths contain valid string roles
/// - Logs a debug message if role claims were configured but none were found in the token
///
/// This ensures that malformed or empty role claims don't prevent fallback to alternate
/// claim paths, while still extracting valid string roles when they exist.
fn get_roles(claims: &serde_json::Value, role_claims: Option<&[String]>) -> Option<Vec<String>> {
    let role_claim_paths = role_claims?;

    if role_claim_paths.is_empty() {
        return None;
    }

    for claim_path in role_claim_paths {
        // Navigate nested claims (dot-notation, e.g. "resource_access.account.roles").
        let Some(current) = navigate(claims, claim_path) else {
            continue;
        };

        // Handle array of strings
        if let Some(roles_array) = current.as_array() {
            // Filter to only string values, ignoring numbers, objects, nulls, etc.
            let roles: Vec<String> = roles_array.iter().filter_map(value_as_string).collect();
            if !roles.is_empty() {
                return Some(roles);
            }
            // If array exists but contains no valid strings (or is empty),
            // continue to next claim path rather than returning None immediately.
            // This allows fallback to alternate claim paths.
        }
        // Handle single string (less common but possible)
        else if let Some(role) = value_as_string(current) {
            return Some(vec![role]);
        }
        // If the value is neither an array nor a string (e.g., object, number),
        // continue to the next claim path.
    }

    // If we configured role claims but found none, issue a warning
    tracing::debug!(
        "Role claims `{role_claim_paths:?}` were configured but no valid roles were found in the token. \
         Configured paths may be missing or contain non-string values."
    );

    None
}

fn get_subject(
    token_data: &jsonwebtoken::TokenData<serde_json::Value>,
    subject_claim: &[String],
) -> Result<String> {
    for claim in subject_claim {
        if let Some(subject) = token_data.claims.get(claim).and_then(value_as_string) {
            return Ok(subject);
        }
    }
    Err(Error::unauthenticated(
        "Could not find the subject claim in the JWT token.".to_string(),
    ))
}

fn parse_human_name(claims: &serde_json::Value) -> Option<String> {
    let first_name = claims
        .get("given_name")
        .or(claims.get("first_name"))
        .and_then(value_as_string);
    let last_name = claims
        .get("family_name")
        .or(claims.get("last_name"))
        .and_then(value_as_string);

    claims
        .get(NAME_CLAIM)
        .and_then(value_as_string)
        .or_else(|| match (first_name, last_name) {
            (Some(first), Some(last)) => Some(format!("{first} {last}")),
            (Some(first), None) => Some(first),
            (None, Some(last)) => Some(last),
            (None, None) => None,
        })
}

#[derive(serde::Deserialize, Clone, Debug)]
struct WellKnownConfig {
    pub jwks_uri: url::Url,
    pub issuer: String,
}

impl std::fmt::Debug for JWKSWebAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut r = f.debug_struct("JWKSWebAuthenticator");

        let r = r.field("idp_id", &self.idp_id);

        r.field("audiences", &self.audiences)
            .field("issuers", &self.issuers)
            .field("scope", &self.scope)
            .field("config_url", &self.config_url)
            .field("subject_claim", &self.subject_claim)
            .field("client", &"jwks_client_rs::JwksClient<WebSource>")
            .field("role_claims", &self.role_claims)
            .field("display_name_template", &self.display_name_template)
            .finish()
    }
}

fn value_as_string(value: &serde_json::Value) -> Option<String> {
    value.as_str().map(std::string::ToString::to_string)
}

/// Navigate nested JSON claims using dot-notation (e.g. `resource_access.account.roles`).
/// Returns the value at the path, or `None` if any segment is absent.
fn navigate<'a>(claims: &'a serde_json::Value, dot_path: &str) -> Option<&'a serde_json::Value> {
    let mut current = claims;
    for part in dot_path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

/// A structurally invalid display-name template — one that can never render for
/// any token, independent of its claims. (A well-formed template whose claim is
/// merely absent from a given token is *not* an error; it simply doesn't apply
/// to that token.) Returned by [`DisplayNameTemplate::parse`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DisplayNameTemplateError {
    /// A `{` with no matching `}` (write a literal brace as `{{`).
    #[error("unmatched `{{` in display-name template (write a literal brace as `{{{{`)")]
    UnmatchedOpenBrace,
    /// A `}` with no matching `{` (write a literal brace as `}}`).
    #[error("unmatched `}}` in display-name template (write a literal brace as `}}}}`)")]
    UnmatchedCloseBrace,
    /// An empty `{}` placeholder — a placeholder must name a claim.
    #[error("empty `{{}}` placeholder in display-name template (name a claim, e.g. `{{email}}`)")]
    EmptyPlaceholder,
}

/// One piece of a parsed display-name template.
enum TemplateEvent<'a> {
    /// Verbatim text, with any `{{`/`}}` already unescaped to a single brace.
    Literal(&'a str),
    /// A `{claim.path}` placeholder — the dot-notation path, without braces.
    Claim(&'a str),
}

/// Walk `template`, invoking `sink` for each literal chunk and placeholder in
/// order (`{{`/`}}` are emitted as single-brace literals). This is the single
/// source of the template grammar; [`DisplayNameTemplate::parse`] drives it to
/// build the validated segment list.
fn parse_display_name_template(
    template: &str,
    mut sink: impl FnMut(TemplateEvent<'_>),
) -> std::result::Result<(), DisplayNameTemplateError> {
    let mut rest = template;
    loop {
        let Some(idx) = rest.find(['{', '}']) else {
            sink(TemplateEvent::Literal(rest));
            return Ok(());
        };
        sink(TemplateEvent::Literal(&rest[..idx]));
        let brace = rest.as_bytes()[idx];
        rest = &rest[idx + 1..];

        if brace == b'}' {
            // A `}` is only valid as the escape `}}`; a lone `}` is malformed.
            let Some(stripped) = rest.strip_prefix('}') else {
                return Err(DisplayNameTemplateError::UnmatchedCloseBrace);
            };
            sink(TemplateEvent::Literal("}"));
            rest = stripped;
            continue;
        }

        // `brace == b'{'`: either the escape `{{` or the start of a placeholder.
        if let Some(stripped) = rest.strip_prefix('{') {
            sink(TemplateEvent::Literal("{"));
            rest = stripped;
            continue;
        }
        let Some(close) = rest.find('}') else {
            return Err(DisplayNameTemplateError::UnmatchedOpenBrace);
        };
        let path = &rest[..close];
        // A `{` before the closing `}` means an earlier `{` was never closed.
        if path.contains('{') {
            return Err(DisplayNameTemplateError::UnmatchedOpenBrace);
        }
        // Empty or whitespace-only placeholders name no claim.
        if path.trim().is_empty() {
            return Err(DisplayNameTemplateError::EmptyPlaceholder);
        }
        sink(TemplateEvent::Claim(path));
        rest = &rest[close + 1..];
    }
}

/// A validated display-name template: a sequence of literal text and
/// `{claim.path}` placeholders. Constructed via [`DisplayNameTemplate::parse`]
/// (or [`str::parse`]), so holding one is proof its syntax is valid — which is
/// why [`JWKSWebAuthenticator::with_display_name_template`] can accept it
/// infallibly. Resolved against a token's claims during authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayNameTemplate {
    source: String,
    segments: Vec<Segment>,
}

/// One piece of a parsed [`DisplayNameTemplate`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// Verbatim text, with any `{{`/`}}` already unescaped to a single brace.
    Literal(String),
    /// A claim path (dot-notation) to resolve at render time.
    Claim(String),
}

impl DisplayNameTemplate {
    /// Parse and validate a display-name template.
    ///
    /// Placeholders are `{claim.path}` (dot-notation); write a literal brace by
    /// doubling it (`{{`/`}}`), as in [`std::fmt`]. The *structure* is validated
    /// here — braces must balance and every placeholder must name a claim — but
    /// whether a referenced claim exists is token-dependent and is checked only at
    /// render time.
    ///
    /// # Errors
    /// Returns [`DisplayNameTemplateError`] for an unmatched `{`, a stray `}`, or
    /// an empty `{}` placeholder.
    pub fn parse(template: &str) -> std::result::Result<Self, DisplayNameTemplateError> {
        let mut segments = Vec::new();
        let mut literal = String::new();
        parse_display_name_template(template, |event| match event {
            TemplateEvent::Literal(text) => literal.push_str(text),
            TemplateEvent::Claim(path) => {
                if !literal.is_empty() {
                    segments.push(Segment::Literal(std::mem::take(&mut literal)));
                }
                segments.push(Segment::Claim(path.to_string()));
            }
        })?;
        if !literal.is_empty() {
            segments.push(Segment::Literal(literal));
        }
        Ok(Self {
            source: template.to_string(),
            segments,
        })
    }

    /// Render the template against `claims`. Returns `None` — so the caller keeps
    /// its own default — when a referenced claim is missing or not a string
    /// (logged at `debug`), or when the result is empty or all-whitespace.
    /// Surrounding whitespace is trimmed.
    fn render(&self, claims: &serde_json::Value) -> Option<String> {
        let mut out = String::with_capacity(self.source.len());
        for segment in &self.segments {
            match segment {
                Segment::Literal(text) => out.push_str(text),
                Segment::Claim(path) => {
                    let Some(value) = navigate(claims, path).and_then(value_as_string) else {
                        tracing::debug!(
                            "Display name template `{}` not applied: claim `{path}` is missing or not a string.",
                            self.source
                        );
                        return None;
                    };
                    out.push_str(&value);
                }
            }
        }
        let trimmed = out.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }
}

impl std::str::FromStr for DisplayNameTemplate {
    type Err = DisplayNameTemplateError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Returns `true` if the space-delimited `scope` claim contains `required`.
/// Matches without allocating an intermediate collection.
fn scope_claim_contains(scope_claim: Option<&str>, required: &str) -> bool {
    scope_claim.is_some_and(|scopes| scopes.split_whitespace().any(|s| s == required))
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    #[test]
    fn test_scope_claim_contains_multi() {
        assert!(scope_claim_contains(
            Some("openid profile email"),
            "profile"
        ));
        assert!(!scope_claim_contains(Some("openid profile email"), "admin"));
    }

    #[test]
    fn test_scope_claim_contains_single() {
        assert!(scope_claim_contains(Some("openid"), "openid"));
        // Must match a whole scope, not a prefix.
        assert!(!scope_claim_contains(Some("openid"), "open"));
    }

    #[test]
    fn test_scope_claim_contains_absent() {
        assert!(!scope_claim_contains(None, "openid"));
        assert!(!scope_claim_contains(Some(""), "openid"));
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

        let token_header = jsonwebtoken::Header::new(Algorithm::RS256);
        let token_data = jsonwebtoken::TokenData {
            header: token_header.clone(),
            claims: claims.clone(),
        };

        let payload = extract_authentication(
            Some("idp"),
            token_data,
            &["oid".to_string(), "sub".to_string()],
            None,
            None,
        )
        .unwrap();

        let subject = Subject::new(
            Some("idp".to_string()),
            "f621fc83-4ec9-4bf8-bc8d-xxxxxxxxxxxx".to_string(),
        );
        let expected_payload = Authentication::builder()
            .token_header(Some(token_header))
            .claims(claims.clone())
            .name(Some("ht-testing-lakekeeper-oauth".to_string()))
            .email(None)
            .subject(subject)
            .principal_type(Some(PrincipalType::Application))
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

        let token_header = jsonwebtoken::Header::new(Algorithm::RS256);
        let token_data = jsonwebtoken::TokenData {
            header: token_header.clone(),
            claims: claims.clone(),
        };

        let payload =
            extract_authentication(Some("idp"), token_data, &["oid".to_string()], None, None)
                .unwrap();

        let subject = Subject::new(Some("idp".to_string()), "user-oid".to_string());

        let expected_payload = Authentication::builder()
            .token_header(Some(token_header))
            .claims(claims.clone())
            .name(Some("Peter Cold".to_string()))
            .email(Some("peter@example.com".to_string()))
            .subject(subject)
            .principal_type(Some(PrincipalType::Human))
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

        let token_header = jsonwebtoken::Header::new(Algorithm::RS256);
        let token_data = jsonwebtoken::TokenData {
            header: token_header.clone(),
            claims: claims.clone(),
        };

        let payload =
            extract_authentication(Some("idp"), token_data, &["oid".to_string()], None, None)
                .unwrap();

        let subject = Subject::new(
            Some("idp".to_string()),
            "eb54b4f5-0d20-46eb-b703-b1c910262e89".to_string(),
        );

        let expected_payload = Authentication::builder()
            .token_header(Some(token_header))
            .claims(claims.clone())
            .name(Some("Jack Frost".to_string()))
            .email(Some("jack@example.com".to_string()))
            .subject(subject)
            .principal_type(Some(PrincipalType::Human))
            .audiences(HashSet::from([
                "00000003-0000-0000-c000-000000000000".to_string()
            ]))
            .build();

        assert_eq!(payload, expected_payload);
    }

    #[test]
    fn test_get_roles_simple_claim() {
        let claims = serde_json::json!({
            "roles": ["admin", "user", "editor"]
        });

        let roles = get_roles(&claims, Some(&["roles".to_string()]));
        assert_eq!(
            roles,
            Some(vec![
                "admin".to_string(),
                "user".to_string(),
                "editor".to_string()
            ])
        );
    }

    #[test]
    fn test_get_roles_nested_claim() {
        let claims = serde_json::json!({
            "resource_access": {
                "account": {
                    "roles": ["manage-account", "view-profile"]
                }
            }
        });

        let roles = get_roles(
            &claims,
            Some(&["resource_access.account.roles".to_string()]),
        );
        assert_eq!(
            roles,
            Some(vec![
                "manage-account".to_string(),
                "view-profile".to_string()
            ])
        );
    }

    #[test]
    fn test_get_roles_multiple_paths_first_match() {
        let claims = serde_json::json!({
            "realm_access": {
                "roles": ["realm-role"]
            },
            "resource_access": {
                "account": {
                    "roles": ["account-role"]
                }
            }
        });

        // Should return first match
        let roles = get_roles(
            &claims,
            Some(&[
                "realm_access.roles".to_string(),
                "resource_access.account.roles".to_string(),
            ]),
        );
        assert_eq!(roles, Some(vec!["realm-role".to_string()]));
    }

    #[test]
    fn test_get_roles_fallback_to_second_path() {
        let claims = serde_json::json!({
            "resource_access": {
                "account": {
                    "roles": ["account-role"]
                }
            }
        });

        // First path doesn't exist, should fall back to second
        let roles = get_roles(
            &claims,
            Some(&[
                "realm_access.roles".to_string(),
                "resource_access.account.roles".to_string(),
            ]),
        );
        assert_eq!(roles, Some(vec!["account-role".to_string()]));
    }

    #[test]
    fn test_get_roles_no_match() {
        let claims = serde_json::json!({
            "other_field": "value"
        });

        let roles = get_roles(&claims, Some(&["roles".to_string()]));
        assert_eq!(roles, None);
    }

    #[test]
    fn test_get_roles_single_string() {
        let claims = serde_json::json!({
            "role": "admin"
        });

        let roles = get_roles(&claims, Some(&["role".to_string()]));
        assert_eq!(roles, Some(vec!["admin".to_string()]));
    }

    #[test]
    fn test_get_roles_array_with_non_strings() {
        // Array contains only non-string values (numbers, objects, nulls)
        let claims = serde_json::json!({
            "roles": [42, {"name": "admin"}, null, true]
        });

        // Should return None, not Some(vec![]), because no valid strings found
        let roles = get_roles(&claims, Some(&["roles".to_string()]));
        assert_eq!(roles, None);
    }

    #[test]
    fn test_get_roles_empty_array() {
        // Explicitly empty array
        let claims = serde_json::json!({
            "roles": []
        });

        // Should return None, not Some(vec![]), treating empty like non-existent
        let roles = get_roles(&claims, Some(&["roles".to_string()]));
        assert_eq!(roles, None);
    }

    #[test]
    fn test_get_roles_mixed_array() {
        // Array contains both strings and non-strings
        let claims = serde_json::json!({
            "roles": ["admin", 42, "user", null, "editor", {"name": "invalid"}]
        });

        // Should extract only the string values, filtering out non-strings
        let roles = get_roles(&claims, Some(&["roles".to_string()]));
        assert_eq!(
            roles,
            Some(vec![
                "admin".to_string(),
                "user".to_string(),
                "editor".to_string()
            ])
        );
    }

    #[test]
    fn test_get_roles_fallback_from_non_strings() {
        // First path has only non-strings, second path has valid strings
        let claims = serde_json::json!({
            "invalid_roles": [42, null, {"role": "admin"}],
            "valid_roles": ["user", "viewer"]
        });

        // Should skip first path (no valid strings) and use second path
        let roles = get_roles(
            &claims,
            Some(&["invalid_roles".to_string(), "valid_roles".to_string()]),
        );
        assert_eq!(roles, Some(vec!["user".to_string(), "viewer".to_string()]));
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

        let token_header = jsonwebtoken::Header::new(Algorithm::RS256);
        let token_data = jsonwebtoken::TokenData {
            header: token_header.clone(),
            claims: claims.clone(),
        };

        let payload = extract_authentication(
            Some("idp"),
            token_data.clone(),
            &["sub".to_string()],
            None,
            None,
        )
        .unwrap();

        let subject = Subject::new(
            Some("idp".to_string()),
            "f1616ed0-18d8-48ea-9fb3-832f42db0b1b".to_string(),
        );

        let expected_payload = Authentication::builder()
            .token_header(Some(token_header.clone()))
            .claims(claims.clone())
            .name(Some("Peter Cold".to_string()))
            .email(Some("peter@example.com".to_string()))
            .subject(subject.clone())
            .principal_type(Some(PrincipalType::Human))
            .audiences(HashSet::from(["account".to_string()]))
            .build();

        assert_eq!(payload, expected_payload);

        // Test with realm_access.roles extraction
        let payload_with_roles = extract_authentication(
            Some("idp"),
            token_data,
            &["sub".to_string()],
            Some(&["realm_access.roles".to_string()]),
            None,
        )
        .unwrap();

        let expected_with_roles = Authentication::builder()
            .token_header(Some(token_header))
            .claims(claims.clone())
            .name(Some("Peter Cold".to_string()))
            .email(Some("peter@example.com".to_string()))
            .subject(subject)
            .principal_type(Some(PrincipalType::Human))
            .roles(Some(vec![
                "offline_access".to_string(),
                "uma_authorization".to_string(),
                "default-roles-iceberg".to_string(),
            ]))
            .audiences(HashSet::from(["account".to_string()]))
            .build();

        assert_eq!(payload_with_roles, expected_with_roles);
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

        let token_header = jsonwebtoken::Header::new(Algorithm::RS256);
        let token_data = jsonwebtoken::TokenData {
            header: token_header.clone(),
            claims: claims.clone(),
        };

        let payload = extract_authentication(
            Some("idp"),
            token_data.clone(),
            &["sub".to_string()],
            None,
            None,
        )
        .unwrap();

        let subject = Subject::new(
            Some("idp".to_string()),
            "b6cc7aa0-1af0-460e-9174-e05c881fb6d4".to_string(),
        );

        let expected_payload = Authentication::builder()
            .token_header(Some(token_header.clone()))
            .claims(claims.clone())
            .name(Some("service-account-iceberg-machine-client".to_string()))
            .email(None)
            .subject(subject.clone())
            .principal_type(Some(PrincipalType::Application))
            .audiences(HashSet::from([
                "iceberg-catalog".to_string(),
                "account".to_string(),
            ]))
            .build();

        assert_eq!(payload, expected_payload);

        // Test with resource_access.account.roles extraction
        let payload_with_roles = extract_authentication(
            Some("idp"),
            token_data,
            &["sub".to_string()],
            Some(&["resource_access.account.roles".to_string()]),
            None,
        )
        .unwrap();

        let expected_with_roles = Authentication::builder()
            .token_header(Some(token_header))
            .claims(claims.clone())
            .name(Some("service-account-iceberg-machine-client".to_string()))
            .email(None)
            .subject(subject)
            .principal_type(Some(PrincipalType::Application))
            .roles(Some(vec![
                "manage-account".to_string(),
                "manage-account-links".to_string(),
                "view-profile".to_string(),
            ]))
            .audiences(HashSet::from([
                "iceberg-catalog".to_string(),
                "account".to_string(),
            ]))
            .build();

        assert_eq!(payload_with_roles, expected_with_roles);
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

        let token_header = jsonwebtoken::Header::new(Algorithm::RS256);
        let token_data = jsonwebtoken::TokenData {
            header: token_header.clone(),
            claims: claims.clone(),
        };

        let payload =
            extract_authentication(Some("idp"), token_data, &["sub".to_string()], None, None)
                .unwrap();

        assert_eq!(payload.audiences(), &HashSet::new());
    }

    fn parse_ok(template: &str) -> DisplayNameTemplate {
        DisplayNameTemplate::parse(template).expect("template should be valid")
    }

    #[test]
    fn test_display_name_template_parse_accepts_well_formed() {
        assert!(DisplayNameTemplate::parse("Service Account {email}").is_ok());
        assert!(DisplayNameTemplate::parse("{sub}").is_ok());
        assert!(DisplayNameTemplate::parse("literal, no placeholders").is_ok());
        assert!(DisplayNameTemplate::parse("{{escaped}} {sub}").is_ok());
        // Claim existence is token-dependent and deliberately NOT checked at parse.
        assert!(DisplayNameTemplate::parse("{a.b.c}").is_ok());
    }

    #[test]
    fn test_display_name_template_parse_rejects_structural_errors() {
        assert_eq!(
            DisplayNameTemplate::parse("Team {Alpha"),
            Err(DisplayNameTemplateError::UnmatchedOpenBrace)
        );
        assert_eq!(
            DisplayNameTemplate::parse("Team Alpha}"),
            Err(DisplayNameTemplateError::UnmatchedCloseBrace)
        );
        assert_eq!(
            DisplayNameTemplate::parse("{}"),
            Err(DisplayNameTemplateError::EmptyPlaceholder)
        );
        // A `{` inside a placeholder means an earlier `{` was never closed.
        assert_eq!(
            DisplayNameTemplate::parse("{a{b}"),
            Err(DisplayNameTemplateError::UnmatchedOpenBrace)
        );
        // A whitespace-only placeholder names no claim.
        assert_eq!(
            DisplayNameTemplate::parse("{ }"),
            Err(DisplayNameTemplateError::EmptyPlaceholder)
        );
        assert_eq!(
            DisplayNameTemplate::parse("{   }"),
            Err(DisplayNameTemplateError::EmptyPlaceholder)
        );
    }

    #[test]
    fn test_display_name_template_from_str() {
        let template: DisplayNameTemplate = "Service Account {email}".parse().unwrap();
        let claims = serde_json::json!({ "email": "sa@example.com" });
        assert_eq!(
            template.render(&claims),
            Some("Service Account sa@example.com".to_string())
        );
    }

    #[test]
    fn test_render_substitutes_email() {
        let claims = serde_json::json!({ "email": "sa@example.com", "sub": "abc" });
        assert_eq!(
            parse_ok("Service Account {email}").render(&claims),
            Some("Service Account sa@example.com".to_string())
        );
    }

    #[test]
    fn test_render_substitutes_sub() {
        let claims = serde_json::json!({ "sub": "abc-123" });
        assert_eq!(
            parse_ok("{sub}").render(&claims),
            Some("abc-123".to_string())
        );
    }

    #[test]
    fn test_render_navigates_nested_claim() {
        let claims = serde_json::json!({ "a": { "b": { "c": "deep" } } });
        assert_eq!(
            parse_ok("name={a.b.c}").render(&claims),
            Some("name=deep".to_string())
        );
    }

    #[test]
    fn test_render_escaped_braces() {
        let claims = serde_json::json!({ "sub": "abc" });
        // `{{`/`}}` are literal braces, matching `format!` semantics.
        assert_eq!(parse_ok("{{}}").render(&claims), Some("{}".to_string()));
        assert_eq!(
            parse_ok("{{{sub}}}").render(&claims),
            Some("{abc}".to_string())
        );
        assert_eq!(
            parse_ok("Team {{Alpha}}").render(&claims),
            Some("Team {Alpha}".to_string())
        );
    }

    #[test]
    fn test_render_literal_only() {
        let claims = serde_json::json!({ "sub": "abc" });
        assert_eq!(
            parse_ok("Machine Account").render(&claims),
            Some("Machine Account".to_string())
        );
    }

    #[test]
    fn test_render_missing_claim_yields_none() {
        // `email` is absent, so the template does not apply and the caller falls
        // back to its own default rather than rendering a half-filled string.
        let claims = serde_json::json!({ "sub": "abc" });
        assert_eq!(parse_ok("Service Account {email}").render(&claims), None);
    }

    #[test]
    fn test_render_non_string_claim_yields_none() {
        // A claim that exists but is not a string (e.g. an array) does not apply.
        let claims = serde_json::json!({ "organizations": ["org-1"] });
        assert_eq!(parse_ok("{organizations}").render(&claims), None);
    }

    #[test]
    fn test_render_does_not_rescan_substituted_value() {
        // A claim value that itself contains braces must never be re-interpreted
        // as a placeholder — render walks pre-parsed segments, not the output.
        let claims = serde_json::json!({ "org": "Team {X}" });
        assert_eq!(
            parse_ok("{org}").render(&claims),
            Some("Team {X}".to_string())
        );
    }

    #[test]
    fn test_render_trims_surrounding_whitespace() {
        let claims = serde_json::json!({ "sub": "abc" });
        assert_eq!(
            parse_ok("  {sub}  ").render(&claims),
            Some("abc".to_string())
        );
    }

    #[test]
    fn test_display_name_template_applied_when_no_name_claim() {
        // A bare machine token (no name/given_name/app_displayname/preferred_username)
        // — as issued by e.g. service-account IdPs — falls back to the template.
        let claims = serde_json::json!({
            "sub": "00000000-0000-0000-0000-000000000000",
            "email": "service-account@example.com",
            "iss": "https://issuer.example.com",
        });
        let token_data = jsonwebtoken::TokenData {
            header: jsonwebtoken::Header::new(Algorithm::RS256),
            claims,
        };
        let template = parse_ok("Service Account {email}");
        let payload = extract_authentication(
            Some("oidc"),
            token_data,
            &["sub".to_string()],
            None,
            Some(&template),
        )
        .unwrap();
        assert_eq!(
            payload.full_name(),
            Some("Service Account service-account@example.com")
        );
    }

    #[test]
    fn test_display_name_template_ignored_when_name_claim_present() {
        // A real human-name claim always wins; the template is a fallback only.
        let claims = serde_json::json!({
            "sub": "x",
            "name": "Jane Doe",
            "email": "jane@example.com",
        });
        let token_data = jsonwebtoken::TokenData {
            header: jsonwebtoken::Header::new(Algorithm::RS256),
            claims,
        };
        let template = parse_ok("Service Account {email}");
        let payload = extract_authentication(
            Some("oidc"),
            token_data,
            &["sub".to_string()],
            None,
            Some(&template),
        )
        .unwrap();
        assert_eq!(payload.full_name(), Some("Jane Doe"));
    }
}
