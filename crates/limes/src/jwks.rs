//! Validate JWT tokens locally using JWKS keys fetched from a remote server.

use crate::introspect::IntrospectionResult;
use crate::{
    error::{Error, Result},
    Authentication, Authenticator, PrincipalType, Subject,
};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use jwks_client_rs::source::WebSource;
use jwks_client_rs::{JsonWebKey, JwksClient};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const SCOPE_CLAIM: &str = "scope";
const SUBJECT_CLAIM: &str = "sub";
const IDTYP_CLAIM: &str = "idtyp";
const APP_DISPLAYNAME_CLAIM: &str = "app_displayname";
const NAME_CLAIM: &str = "name";

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
/// - `name`: `name` or `given_name`/ `first_name` and `family_name`/ `last_name` or `app_displayname` or `preferred_username`
/// - `subject`: `sub` unless `subject_claim` is set, then it will be the value of the claim.
/// - `claims`: all claims
/// - `email`: `email` or `upn` if it contains an `@` or `preferred_username` if it contains an `@`
/// - `principal_type`: Is always `Application` currently.
///
pub struct JWKSWebAuthenticator {
    idp_id: Option<String>,
    audiences: Vec<String>,
    client: JwksClient<WebSource>,
    issuers: Vec<String>,
    scope: Option<String>,
    config_url: url::Url,
    subject_claim: Vec<String>,
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
    /// If this function is called with an empty vector, the default `sub` claim will be used.
    #[must_use]
    pub fn with_subject_claims(mut self, subject_claims: Vec<String>) -> Self {
        // Can be useful in multi-tenant applications. For entra-id most applications that
        // interact with other applications should prefer the `oid` claim over the `sub` claim.
        if subject_claims.is_empty() {
            self.subject_claim = vec![SUBJECT_CLAIM.to_string()];
        } else {
            self.subject_claim = subject_claims;
        }
        self
    }

    async fn initialize_client(
        issuer_url: &str,
        ttl: Option<Duration>,
    ) -> Result<(JwksClient<WebSource>, String, url::Url)> {
        let mut url = url::Url::parse(issuer_url)?;
        if !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }

        if !url.path().ends_with(Self::WELL_KNOWN_CONFIG) {
            url.set_path(&format!("{}/{}", url.path(), Self::WELL_KNOWN_CONFIG));
        }

        let config = Arc::new(
            reqwest::get(url.clone())
                .await
                .map_err(|e| Error::FetchOpenIDWellKnownConfigError {
                    url: url.to_string(),
                    source: e,
                })?
                .json::<WellKnownConfig>()
                .await
                .map_err(|e| Error::InvalidWellKnownConfig {
                    expected_fields: &["jwks_uri", "issuer"],
                    source: e,
                })?,
        );
        let issuer = config.issuer.clone();
        let source = WebSource::builder()
            .build(config.jwks_uri.clone())
            .map_err(|e| Error::FetchOpenIDWellKnownConfigError {
                url: url.to_string(),
                source: e,
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
    async fn authenticate(&self, token: &str) -> Result<Authentication> {
        let header = decode_jwt_header(token)?;
        let key_id = require_jwt_key_id(&header)?;
        let key = self
            .client
            .get_opt(&key_id)
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
            &header,
            &key,
            &self.audiences,
            &self.issuers,
            self.scope.as_deref(),
        )?;

        get_payload(
            self.idp_id().map(String::as_str),
            token_data,
            &self.subject_claim,
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

fn decode_jwt_header(token: &str) -> Result<Header> {
    jsonwebtoken::decode_header(token).map_err(|e| Error::JWTDecodeError {
        reason: format!("Failed to decode JWT header: {e}").to_string(),
    })
}

fn require_jwt_key_id(header: &Header) -> Result<String> {
    header.kid.clone().ok_or_else(|| Error::JWTDecodeError {
        reason: "Token does not contain a key id".to_string(),
    })
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
    };

    let token_data = jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation)
        .map_err(|e| Error::JWTDecodeError {
        reason: format!("Failed to decode JWT token. {e}"),
    })?;

    if let Some(scope) = scope {
        let token_scopes =
            parse_scope(token_data.claims.get(SCOPE_CLAIM).and_then(value_as_string));
        if !token_scopes.contains(&scope.to_string()) {
            return Err(Error::unauthenticated(format!(
                "Token does not contain required scope `{scope}`."
            )));
        }
    }

    Ok(token_data)
}

fn get_payload(
    idp_id: Option<&str>,
    token_data: jsonwebtoken::TokenData<serde_json::Value>,
    subject_claim: &Vec<String>,
) -> Result<Authentication> {
    let subject_in_idp = get_subject(&token_data, subject_claim)?;
    let claims = token_data.claims;

    let subject = Subject::new(idp_id.map(ToString::to_string), subject_in_idp);

    let name = claims.get(NAME_CLAIM).and_then(value_as_string);
    let human_name = parse_human_name(&claims);
    let app_name = claims.get(APP_DISPLAYNAME_CLAIM).and_then(value_as_string);
    let preferred_username = claims.get("preferred_username").and_then(value_as_string);

    let principal_type = get_idp_type(&claims)
        // If idp type is not set, try to infer it from the claims
        .or(human_name.as_ref().map(|_t| PrincipalType::Human))
        .or(app_name.as_ref().map(|_t| PrincipalType::Application))
        // In Keycloak the client_id is the requesting application
        .or(claims.get("client_id").map(|_t| PrincipalType::Application));

    Ok(Authentication::builder()
        .token_header(Some(token_data.header))
        .claims(claims.clone())
        .name(name.or(human_name).or(app_name).or(preferred_username))
        .email(get_email(&claims))
        .subject(subject)
        .principal_type(principal_type)
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

fn get_subject(
    token_data: &jsonwebtoken::TokenData<serde_json::Value>,
    subject_claim: &Vec<String>,
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
        .get("name")
        .and_then(value_as_string)
        .or_else(|| match (first_name, last_name) {
            (Some(first), Some(last)) => Some(format!("{first} {last}")),
            (Some(first), None) => Some(first),
            (None, Some(last)) => Some(last),
            (None, None) => None,
        })
}

fn parse_scope(scope_in_claims: Option<String>) -> Vec<String> {
    scope_in_claims
        .map(|scope| {
            scope
                .split(' ')
                .map(std::string::ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
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
            .finish()
    }
}

fn value_as_string(value: &serde_json::Value) -> Option<String> {
    value.as_str().map(std::string::ToString::to_string)
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_scope_multi() {
        let scope = Some("openid profile email".to_string());
        let parsed = parse_scope(scope);
        assert_eq!(parsed, vec!["openid", "profile", "email"]);
    }

    #[test]
    fn test_parse_scope_empty() {
        let scope = None;
        let parsed = parse_scope(scope);
        assert_eq!(parsed, Vec::<String>::new());
    }

    #[test]
    fn test_parse_scope_single() {
        let scope = Some("openid".to_string());
        let parsed = parse_scope(scope);
        assert_eq!(parsed, vec!["openid"]);
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

        let payload = get_payload(
            Some("idp"),
            token_data,
            &vec!["oid".to_string(), "sub".to_string()],
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

        let payload = get_payload(Some("idp"), token_data, &vec!["oid".to_string()]).unwrap();

        let subject = Subject::new(Some("idp".to_string()), "user-oid".to_string());

        let expected_payload = Authentication::builder()
            .token_header(Some(token_header))
            .claims(claims.clone())
            .name(Some("Peter Cold".to_string()))
            .email(Some("peter@example.com".to_string()))
            .subject(subject)
            .principal_type(Some(PrincipalType::Human))
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

        let payload = get_payload(Some("idp"), token_data, &vec!["oid".to_string()]).unwrap();

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

        let token_header = jsonwebtoken::Header::new(Algorithm::RS256);
        let token_data = jsonwebtoken::TokenData {
            header: token_header.clone(),
            claims: claims.clone(),
        };

        let payload = get_payload(Some("idp"), token_data, &vec!["sub".to_string()]).unwrap();

        let subject = Subject::new(
            Some("idp".to_string()),
            "f1616ed0-18d8-48ea-9fb3-832f42db0b1b".to_string(),
        );

        let expected_payload = Authentication::builder()
            .token_header(Some(token_header))
            .claims(claims.clone())
            .name(Some("Peter Cold".to_string()))
            .email(Some("peter@example.com".to_string()))
            .subject(subject)
            .principal_type(Some(PrincipalType::Human))
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

        let token_header = jsonwebtoken::Header::new(Algorithm::RS256);
        let token_data = jsonwebtoken::TokenData {
            header: token_header.clone(),
            claims: claims.clone(),
        };

        let payload = get_payload(Some("idp"), token_data, &vec!["sub".to_string()]).unwrap();

        let subject = Subject::new(
            Some("idp".to_string()),
            "b6cc7aa0-1af0-460e-9174-e05c881fb6d4".to_string(),
        );

        let expected_payload = Authentication::builder()
            .token_header(Some(token_header))
            .claims(claims.clone())
            .name(Some("service-account-iceberg-machine-client".to_string()))
            .email(None)
            .subject(subject)
            .principal_type(Some(PrincipalType::Application))
            .build();

        assert_eq!(payload, expected_payload);
    }
}
