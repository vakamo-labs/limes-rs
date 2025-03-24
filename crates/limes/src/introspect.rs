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
    match header {
        Ok(header) => {
            let mut validation = Validation::new(header.alg);
            validation.insecure_disable_signature_validation();
            validation.required_spec_claims = HashSet::from(["iss".to_string(), "sub".to_string()]);
            validation.validate_aud = false;
            validation.validate_exp = false;

            let result: JWTBearer =
                match jsonwebtoken::decode(token, &EMPTY_DECODE_KEY, &validation) {
                    Ok(token_data) => token_data.claims,
                    Err(e) => {
                        tracing::trace!(
                            "Token is not a JWT Bearer token. Could not decode claims: {e}"
                        );

                        return IntrospectionResult::Unknown;
                    }
                };

            IntrospectionResult::JWTBearer {
                header,
                iss: result.iss.into_set(),
                aud: result.aud.into_set(),
            }
        }
        Err(e) => {
            tracing::trace!("Token is not a JWT Bearer token. Could not decode header: {e}");
            IntrospectionResult::Unknown
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct JWTBearer {
    #[allow(unused)]
    sub: String,
    iss: Issuer,
    #[serde(default)]
    aud: Audience,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(HashSet<String>),
}

impl Default for Audience {
    fn default() -> Self {
        Audience::Multiple(HashSet::new())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn test_introspect_jwt_bearer() {
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJGSXdWb1hsQnlEd1hEWEFyOW5QaU44aUlpb05hc2lIVjhKWlFIMHQ2TDZvIn0.eyJleHAiOjE3NDA0ODk0MzgsImlhdCI6MTc0MDQ4OTEzOCwiYXV0aF90aW1lIjoxNzQwNDg5MTM4LCJqdGkiOiI3NTdlZjljNS0xYTE3LTRhNzEtYjVkMS1lZTg5NGFiY2VhZGQiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDgwL3JlYWxtcy9pY2ViZXJnIiwiYXVkIjpbImxha2VrZWVwZXIiLCJhY2NvdW50Il0sInN1YiI6ImNmYjU1YmY2LWZjYmItNGExZS1iZmVjLTMwYzY2NDliNTJmOCIsInR5cCI6IkJlYXJlciIsImF6cCI6Imxha2VrZWVwZXIiLCJzaWQiOiJlNzM5ODg4OS0xYzQ4LTRlYmQtOTUxZi05YWRmMGU1NjI5ZjMiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJkZWZhdWx0LXJvbGVzLWljZWJlcmciXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJQZXRlciBDb2xkIiwicHJlZmVycmVkX3VzZXJuYW1lIjoicGV0ZXIiLCJnaXZlbl9uYW1lIjoiUGV0ZXIiLCJmYW1pbHlfbmFtZSI6IkNvbGQiLCJlbWFpbCI6InBldGVyQGV4YW1wbGUuY29tIn0.JDjjQbVklK3v7XQqFwxpzaXZylgQSjszdbSx2UUx6-XKSNMa0o64TGNVkpRioj--JJ5ZSGtMVyioT_hMnT_hTUayStZNZ1Is80n3Pg11kh8qam6mZHvmqkTg4WXYkekGoOc1_SVDsI6QI084Ut4eBKPG_XtHP2ruTR_Y6WLbmQEFMkSPTB-TULHWZ8elwuGMWdAAV60oGQgvid4FHHwJyYXJLyb2NC3Q4XSb_7sS_cZIEWgO6hRUb9VYQq1tof0NT6WegUGbzhbSTfEOOEGJ3-3bquAoxskvOXTeVB7nzCw6e8KBnZS1PYtoiCR_9fp_Ag_7xukcgrfibn9k-BlN1w";
        let result = introspect(token);
        match result {
            IntrospectionResult::JWTBearer { header, iss, aud } => {
                assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
                assert_eq!(iss.len(), 1);
                assert!(iss.contains("http://localhost:30080/realms/iceberg"));
                assert_eq!(aud.len(), 2);
                assert!(aud.contains("account"));
                assert!(aud.contains("lakekeeper"));
            }
            _ => panic!("Unexpected result: {result:?}"),
        }
    }

    #[test]
    #[traced_test]
    fn test_long_lived_kube_token() {
        let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ill1aDZXRGtoUk9mcnUzb3lfekFSQXBBMklQYjdwaFdVN3F3Qkp4SURyOVEifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6Imxha2VrZWVwZXItc2EtdG9rZW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoibXktbGFrZWtlZXBlciIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImI4ZTZlZTc1LTgzNDEtNGEzMC04YjNkLWU1YTIwZjRiOTFkYyIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0Om15LWxha2VrZWVwZXIifQ.bwP_X8aBIkoDPyhmpyd1gBGIxreblgHZem1BHjhoyN3fSvMFdwg34muZAs7m3VlFphPQxQPdyvY6sqoKigCydbK1AS3-DdpdVG2jge2AKJlL27HEnWhDZwO8iD8orUlgPCNFd7qinK0FBEHOJKAAB3XSwGSt0nWL6cFcGoggbhE6IorbfPrpHHJMca7aTIu1Wo3QA4AHDekwqivWdO-CfRC7clVMjDogbd55qnxSMZnPkRQzJ7Loy9YRqzizoMo2yuaUEQ1Kfz-gDsMYBdhtzMLR25c-uVMSGNPombxImmza5YpNNbQNBA9JkQSydfGRVqGnCQcVhIZ4M8e9dc0Trw";
        let token = dbg!(introspect(token));
        if let IntrospectionResult::JWTBearer { iss, .. } = token {
            assert_eq!(
                iss,
                HashSet::from(["kubernetes/serviceaccount".to_string()])
            );
        } else {
            panic!("Unexpected result: {:?}", token);
        }
    }
}
