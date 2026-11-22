use jsonwebtoken::Header;
use serde::Deserialize;
use std::collections::HashSet;

/// What a token says about itself, read without verifying it.
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum IntrospectionResult {
    /// The token is a JWT Bearer token according to RFC 7523.
    #[non_exhaustive]
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

/// Introspect a token to determine its type and issuer. Does not verify the token.
pub(crate) fn introspect(token: &str) -> IntrospectionResult {
    match jsonwebtoken::dangerous::insecure_decode::<RoutingClaims>(token) {
        Ok(token_data) => IntrospectionResult::JWTBearer {
            header: token_data.header,
            iss: token_data.claims.iss.into_set(),
            aud: token_data.claims.aud.into_set(),
        },
        Err(e) => {
            tracing::trace!("Token is not a JWT Bearer token: {e}");
            IntrospectionResult::Unknown
        }
    }
}

#[derive(Deserialize)]
struct RoutingClaims {
    // Only `iss` and `aud` are needed to classify and route a token. `sub` is intentionally
    // not required here so introspection does not reject otherwise-valid tokens (e.g. those
    // relying on a `subject_claim` override such as `oid`); the subject is resolved later
    // during full authentication.
    iss: OneOrMany,
    #[serde(default)]
    aud: OneOrMany,
}

/// A claim that holds one string or an array of strings, such as `iss` and `aud`.
#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(HashSet<String>),
}

impl Default for OneOrMany {
    fn default() -> Self {
        Self::Many(HashSet::new())
    }
}

impl OneOrMany {
    fn into_set(self) -> HashSet<String> {
        match self {
            Self::One(value) => HashSet::from([value]),
            Self::Many(values) => values,
        }
    }
}

/// Parse the `aud` claim from a JSON value into a `HashSet<String>`.
/// Handles both single-string (`"aud": "app"`) and array (`"aud": ["app1", "app2"]`) forms.
pub(crate) fn parse_aud(value: Option<&serde_json::Value>) -> HashSet<String> {
    value
        .and_then(|v| OneOrMany::deserialize(v).ok())
        .map(OneOrMany::into_set)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use tracing_test::traced_test;

    fn unsigned_token(header: &str, payload: &str) -> String {
        format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        )
    }

    #[test]
    fn test_introspect_decodes_escaped_strings() {
        let token = unsigned_token(
            r#"{"alg":"RS256","kid":"k1"}"#,
            r#"{"iss":"https:\/\/idp.example","aud":["a\u0062c","abc"]}"#,
        );
        assert_eq!(
            introspect(&token),
            IntrospectionResult::JWTBearer {
                header: jsonwebtoken::decode_header(&token).unwrap(),
                iss: HashSet::from(["https://idp.example".to_string()]),
                aud: HashSet::from(["abc".to_string()]),
            }
        );
    }

    #[test]
    fn test_introspect_header_is_the_header_jsonwebtoken_decodes() {
        let token = unsigned_token(
            r#"{"alg":"ES256","kid":"k1","typ":"at+jwt","x5t":"thumb","extra":1}"#,
            r#"{"iss":"https://idp.example"}"#,
        );
        let IntrospectionResult::JWTBearer { header, .. } = introspect(&token) else {
            panic!("expected a JWT bearer token");
        };
        assert_eq!(header, jsonwebtoken::decode_header(&token).unwrap());
    }

    #[test]
    fn test_introspect_unknown_formats() {
        let jwt = unsigned_token(r#"{"alg":"RS256"}"#, r#"{"iss":"i"}"#);
        for token in [
            String::new(),
            "not-a-jwt".to_string(),
            "a.b".to_string(),
            // Four parts: the header part holds a `.`, which is not base64.
            format!("x.{jwt}"),
            unsigned_token(r#"{"alg":"RS256"}"#, r#"{"aud":"a"}"#),
            unsigned_token(r#"{"alg":"RS256"}"#, r#"{"iss":1}"#),
            unsigned_token(r#"{"alg":"RS256"}"#, r#"{"iss":"i","aud":null}"#),
            unsigned_token(r#"{"alg":"none!"}"#, r#"{"iss":"i"}"#),
        ] {
            assert_eq!(introspect(&token), IntrospectionResult::Unknown, "{token}");
        }
        assert!(matches!(
            introspect(&jwt),
            IntrospectionResult::JWTBearer { .. }
        ));
    }

    #[test]
    fn test_parse_aud_single_string() {
        let aud = serde_json::json!("my-app");
        let parsed = parse_aud(Some(&aud));
        assert_eq!(parsed, HashSet::from(["my-app".to_string()]));
    }

    #[test]
    fn test_parse_aud_array() {
        let aud = serde_json::json!(["my-app", "other-app"]);
        let parsed = parse_aud(Some(&aud));
        assert_eq!(
            parsed,
            HashSet::from(["my-app".to_string(), "other-app".to_string()])
        );
    }

    #[test]
    fn test_parse_aud_none() {
        let parsed = parse_aud(None);
        assert_eq!(parsed, HashSet::new());
    }

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
            IntrospectionResult::Unknown => panic!("Unexpected result: {result:?}"),
        }
    }

    #[test]
    #[traced_test]
    fn test_long_lived_kube_token() {
        let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ill1aDZXRGtoUk9mcnUzb3lfekFSQXBBMklQYjdwaFdVN3F3Qkp4SURyOVEifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6Imxha2VrZWVwZXItc2EtdG9rZW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoibXktbGFrZWtlZXBlciIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6ImI4ZTZlZTc1LTgzNDEtNGEzMC04YjNkLWU1YTIwZjRiOTFkYyIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0Om15LWxha2VrZWVwZXIifQ.bwP_X8aBIkoDPyhmpyd1gBGIxreblgHZem1BHjhoyN3fSvMFdwg34muZAs7m3VlFphPQxQPdyvY6sqoKigCydbK1AS3-DdpdVG2jge2AKJlL27HEnWhDZwO8iD8orUlgPCNFd7qinK0FBEHOJKAAB3XSwGSt0nWL6cFcGoggbhE6IorbfPrpHHJMca7aTIu1Wo3QA4AHDekwqivWdO-CfRC7clVMjDogbd55qnxSMZnPkRQzJ7Loy9YRqzizoMo2yuaUEQ1Kfz-gDsMYBdhtzMLR25c-uVMSGNPombxImmza5YpNNbQNBA9JkQSydfGRVqGnCQcVhIZ4M8e9dc0Trw";
        let introspection_result = introspect(token);
        if let IntrospectionResult::JWTBearer { iss, .. } = introspection_result {
            assert_eq!(
                iss,
                HashSet::from(["kubernetes/serviceaccount".to_string()])
            );
        } else {
            panic!("Unexpected result: {introspection_result:?}");
        }
    }

    #[test]
    fn test_introspect_without_sub_claim() {
        // A token carrying `iss`/`aud` but no `sub` must still classify as a JWT bearer so
        // that authenticators relying on a `subject_claim` override (e.g. `oid`) keep working.
        let claims = serde_json::json!({
            "iss": "https://example.com",
            "aud": "my-app",
        });
        let token = jsonwebtoken::encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"secret").unwrap(),
        )
        .unwrap();

        match introspect(&token) {
            IntrospectionResult::JWTBearer { iss, aud, .. } => {
                assert!(iss.contains("https://example.com"));
                assert!(aud.contains("my-app"));
            }
            IntrospectionResult::Unknown => panic!("expected JWTBearer for sub-less token"),
        }
    }
}
