//! The keys of a JWKS document, prepared to verify token signatures.

use std::{collections::HashMap, sync::Arc};

use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, KeyOperations, PublicKeyUse},
};

/// A key of the JWKS, ready to verify signatures.
pub(super) struct VerificationKey {
    pub(super) decoding_key: DecodingKey,
    /// The algorithm the JWKS names for the key. Some identity providers, like Entra ID,
    /// name none; then the token's header decides.
    pub(super) algorithm: Option<Algorithm>,
}

impl std::fmt::Debug for VerificationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// A JWKS document as the identity provider serves it. Its keys are read one by one.
#[derive(serde::Deserialize)]
pub(super) struct JwksDocument {
    keys: Vec<serde_json::Value>,
}

/// The usable keys of a JWKS document, by key id.
#[derive(Default)]
pub(super) struct KeySet(HashMap<String, Arc<VerificationKey>>);

impl KeySet {
    /// Prepares the keys of a JWKS document one by one. A key that cannot verify
    /// signatures is skipped and does not affect the others. If two usable keys share a
    /// `kid`, the first one is used.
    pub(super) fn parse(jwks: JwksDocument) -> Self {
        let mut keys = HashMap::new();
        for value in jwks.keys {
            if let Some((kid, key)) = prepare_key(value) {
                keys.entry(kid).or_insert_with(|| Arc::new(key));
            }
        }
        Self(keys)
    }

    pub(super) fn get(&self, kid: &str) -> Option<Arc<VerificationKey>> {
        self.0.get(kid).cloned()
    }
}

/// Prepares one key of a JWKS, or returns `None` if it cannot verify token signatures.
pub(super) fn prepare_key(value: serde_json::Value) -> Option<(String, VerificationKey)> {
    // Tokens select their key by `kid`, so a key without one is never selected.
    let Some(kid) = value.get("kid").and_then(serde_json::Value::as_str) else {
        tracing::debug!("Skipping a JWKS key without `kid`.");
        return None;
    };
    let kid = kid.to_string();
    let jwk: Jwk = match serde_json::from_value(value) {
        Ok(jwk) => jwk,
        Err(e) => {
            tracing::debug!(kid, "Skipping a JWKS key that is not a valid JWK: {e}");
            return None;
        }
    };
    if jwk.common.public_key_use == Some(PublicKeyUse::Encryption)
        || jwk
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
    {
        tracing::debug!(kid, "Skipping a JWKS key that is not for signatures.");
        return None;
    }
    // A JWKS is public, so anyone could sign tokens with a symmetric key published in it.
    if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
        tracing::debug!(kid, "Skipping a symmetric key (`kty` `oct`) in the JWKS.");
        return None;
    }
    let Ok(algorithm) = jwk
        .common
        .key_algorithm
        .map(Algorithm::try_from)
        .transpose()
    else {
        tracing::debug!(
            kid,
            algorithm = ?jwk.common.key_algorithm,
            "Skipping a JWKS key whose algorithm cannot verify signatures."
        );
        return None;
    };
    if algorithm.is_some_and(|algorithm| !fits(algorithm, &jwk.algorithm)) {
        tracing::debug!(
            kid,
            ?algorithm,
            "Skipping a JWKS key whose algorithm does not fit its key type or curve."
        );
        return None;
    }
    match DecodingKey::from_jwk(&jwk) {
        Ok(decoding_key) => Some((
            kid,
            VerificationKey {
                decoding_key,
                algorithm,
            },
        )),
        Err(e) => {
            tracing::debug!(kid, "Skipping a JWKS key that cannot be used: {e}");
            None
        }
    }
}

/// Whether `algorithm` verifies signatures with a key of these parameters. Each ECDSA
/// algorithm takes keys of one curve (RFC 7518, section 3.4).
fn fits(algorithm: Algorithm, parameters: &AlgorithmParameters) -> bool {
    match parameters {
        AlgorithmParameters::RSA(_) => algorithm.family() == AlgorithmFamily::Rsa,
        AlgorithmParameters::EllipticCurve(key) => matches!(
            (algorithm, &key.curve),
            (Algorithm::ES256, EllipticCurve::P256) | (Algorithm::ES384, EllipticCurve::P384)
        ),
        AlgorithmParameters::OctetKeyPair(key) => {
            algorithm == Algorithm::EdDSA && key.curve == EllipticCurve::Ed25519
        }
        _ => false,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, Validation};
    use pretty_assertions::assert_eq;

    fn ed25519_pair(kid: &str) -> (EncodingKey, serde_json::Value) {
        use base64::Engine as _;
        let key_pair = aws_lc_rs::signature::Ed25519KeyPair::generate().unwrap();
        let encoding_key = EncodingKey::from_ed_der(key_pair.to_pkcs8().unwrap().as_ref());
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(aws_lc_rs::signature::KeyPair::public_key(&key_pair).as_ref());
        let jwk = serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": kid, "x": x });
        (encoding_key, jwk)
    }

    fn ed25519_jwk(kid: &str) -> serde_json::Value {
        ed25519_pair(kid).1
    }

    /// The JWK of a new ECDSA key on `crv`, `P-256` or `P-384`.
    fn ec_jwk(kid: &str, crv: &str, alg: &str) -> serde_json::Value {
        use aws_lc_rs::signature::{
            ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair,
            KeyPair as _,
        };
        use base64::Engine as _;
        let curve = match crv {
            "P-256" => &ECDSA_P256_SHA256_FIXED_SIGNING,
            "P-384" => &ECDSA_P384_SHA384_FIXED_SIGNING,
            _ => panic!("unsupported curve {crv}"),
        };
        let key_pair = EcdsaKeyPair::generate(curve).unwrap();
        // An uncompressed point: 0x04, then x and y of equal length.
        let point = &key_pair.public_key().as_ref()[1..];
        let (x, y) = point.split_at(point.len() / 2);
        let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        serde_json::json!({ "kty": "EC", "crv": crv, "alg": alg, "kid": kid, "x": encode(x), "y": encode(y) })
    }

    fn kids(keys: &KeySet) -> Vec<&str> {
        let mut kids: Vec<&str> = keys.0.keys().map(String::as_str).collect();
        kids.sort_unstable();
        kids
    }

    fn verifies(key: &VerificationKey, signer: &EncodingKey) -> bool {
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::EdDSA),
            &serde_json::json!({ "sub": "u" }),
            signer,
        )
        .unwrap();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        jsonwebtoken::decode::<serde_json::Value>(&token, &key.decoding_key, &validation).is_ok()
    }

    #[test]
    fn test_parse_skips_keys_that_cannot_verify_signatures() {
        let mut no_kid = ed25519_jwk("unused");
        no_kid.as_object_mut().unwrap().remove("kid");
        let mut encryption = ed25519_jwk("encryption");
        encryption["use"] = serde_json::json!("enc");
        let mut operations = ed25519_jwk("operations");
        operations["key_ops"] = serde_json::json!(["encrypt"]);
        let mut verify_operation = ed25519_jwk("verify-operation");
        verify_operation["key_ops"] = serde_json::json!(["verify"]);
        let mut unknown_algorithm = ed25519_jwk("unknown-algorithm");
        unknown_algorithm["alg"] = serde_json::json!("XYZ");
        let mut broken = ed25519_jwk("broken");
        broken["x"] = serde_json::json!("not base64!");
        let mut other_family = ed25519_jwk("other-family");
        other_family["alg"] = serde_json::json!("RS256");
        let jwks = JwksDocument {
            keys: vec![
                ed25519_jwk("k1"),
                no_kid,
                encryption,
                operations,
                verify_operation,
                unknown_algorithm,
                broken,
                other_family,
                ec_jwk("es256", "P-256", "ES256"),
                ec_jwk("es384", "P-384", "ES384"),
                ec_jwk("other-curve", "P-384", "ES256"),
                serde_json::json!({ "kty": "oct", "kid": "symmetric", "alg": "HS256", "k": "c2VjcmV0" }),
                serde_json::json!({ "kty": "RSA", "kid": "rs256", "alg": "RS256", "n": "AQAB", "e": "AQAB" }),
                serde_json::json!({ "kty": "RSA", "kid": "oaep", "alg": "RSA-OAEP", "n": "AQAB", "e": "AQAB" }),
                serde_json::json!({ "kty": "unknown", "kid": "unknown-type" }),
                serde_json::json!("not an object"),
            ],
        };
        let keys = KeySet::parse(jwks);
        assert_eq!(
            kids(&keys),
            ["es256", "es384", "k1", "rs256", "verify-operation"]
        );
    }

    #[test]
    fn test_parse_keeps_the_algorithm_of_the_jwks() {
        let mut without_algorithm = ed25519_jwk("without-algorithm");
        without_algorithm.as_object_mut().unwrap().remove("alg");
        let keys = KeySet::parse(JwksDocument {
            keys: vec![ed25519_jwk("k1"), without_algorithm],
        });
        assert_eq!(keys.get("k1").unwrap().algorithm, Some(Algorithm::EdDSA));
        assert_eq!(keys.get("without-algorithm").unwrap().algorithm, None);
    }

    #[test]
    fn test_parse_uses_the_first_usable_key_of_a_kid() {
        let mut encryption = ed25519_jwk("shared");
        encryption["use"] = serde_json::json!("enc");
        let mut other_family = ed25519_jwk("shared");
        other_family["alg"] = serde_json::json!("ES256");
        let (first, first_jwk) = ed25519_pair("shared");
        let (second, second_jwk) = ed25519_pair("shared");
        let keys = KeySet::parse(JwksDocument {
            keys: vec![encryption, other_family, first_jwk, second_jwk],
        });
        let key = keys.get("shared").unwrap();
        assert!(verifies(&key, &first));
        assert!(!verifies(&key, &second));
    }
}
