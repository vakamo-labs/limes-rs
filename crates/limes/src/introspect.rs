use jsonwebtoken::{DecodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashSet;

static EMPTY_DECODE_KEY: Lazy<DecodingKey> = Lazy::new(|| DecodingKey::from_secret(&[]));

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum IntrospectionResult {
    /// The token is a JWT Bearer token according to RFC 7523.
    JWTBearer {
        /// Token header
        header: Header,
        /// Issuer of the token
        iss: HashSet<String>,
        /// Audience of the token
        aud: HashSet<String>,
    },
    /// Unknown token format
    Unknown,
}

/// Introspect a token to determine its type and issuer.
///
/// **Warning**
/// This function does not validate the token, it only introspects it.
#[must_use]
pub fn introspect(token: &str) -> IntrospectionResult {
    let header = jsonwebtoken::decode_header(token);
    if let Ok(header) = header {
        let mut validation = Validation::new(header.alg);
        validation.insecure_disable_signature_validation();

        let result: JWTBearer = match jsonwebtoken::decode(token, &EMPTY_DECODE_KEY, &validation) {
            Ok(token_data) => token_data.claims,
            Err(_) => return IntrospectionResult::Unknown,
        };

        IntrospectionResult::JWTBearer {
            header,
            iss: result.iss.into_set(),
            aud: result.aud.into_set(),
        }
    } else {
        IntrospectionResult::Unknown
    }
}

#[derive(Deserialize)]
pub(crate) struct JWTBearer {
    _sub: String,
    iss: Issuer,
    aud: Audience,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(HashSet<String>),
}

impl Audience {
    fn into_set(self) -> HashSet<String> {
        match self {
            Audience::Single(s) => HashSet::from([s]),
            Audience::Multiple(s) => s,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Issuer {
    Single(String),
    Multiple(HashSet<String>),
}

impl Issuer {
    fn into_set(self) -> HashSet<String> {
        match self {
            Issuer::Single(s) => HashSet::from([s]),
            Issuer::Multiple(s) => s,
        }
    }
}
