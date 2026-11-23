# Upgrading limes

This page lists the changes that need updates in your code, by release.

## From 0.7 to 0.8

| 0.7 | 0.8 |
|---|---|
| `full_name()`, `email()`, `principal_type()` on `Authentication`, `PrincipalType` | Derive them from `identity()`. Each `VerifiedClaims` accessor reads one claim. 0.7 fell back across claims: the name to `given_name` or `first_name` and `family_name` or `last_name`, then `app_displayname`, then `preferred_username`; the email to `upn`, then `preferred_username`, if they contain `@`; the type came from `idtyp`, else human if a name claim was present, else application if `app_displayname` or `client_id` was. A Kubernetes identity had its `username()` as the name, the type application and no email. |
| `roles()`, `with_role_claim(s)` | Read the roles claim with `VerifiedClaims::claim(path)`. 0.7 took the strings of an array, or a single string. |
| `with_display_name_template`, `jwks::DisplayNameTemplate`, `jwks::DisplayNameTemplateError` | Removed. |
| `format_subject`, `parse_subject`, `Error::InvalidSubject` | Removed. Choose a string form of `Subject` in your application. |
| `claims(key)`, `all_claims()` | For `Identity::Claims(claims)`: `claims.as_json().get(key)` and `claims.as_json()`; `claims.claim(path)` reads nested claims. For `Identity::Kubernetes(user)`: `user.extra()`. To test a claim rule, `satisfies(rule)`. |
| `issuer()`, `scopes()`, `expires_at()`, `issued_at()`, `not_before()` | The same methods on `VerifiedClaims`. `Authentication::valid_until()` gives the expiry as a `SystemTime`, also for Kubernetes tokens. |
| `token_header()` | The `header` of `Token::new(token).introspection()`, for a JWT. |
| `Authentication::idp_id()` | `subject().idp_id()`. `Subject::idp_id()` and `Authenticator::idp_id()` return `Option<&str>`. |
| `Authentication::builder()` with `token_header`, `claims`, `name`, `email`, `principal_type`, `roles` | `.subject(..)` and `.identity(..)` with `VerifiedClaims::new(map)`, `VerifiedClaims::try_from(value)` or a `KubernetesUser`; `audiences` is optional. |
| `Error::RefreshOpenIDWellKnownConfigError` | `Error::FetchJwksError`. `Error::kind()` tells 401, 503 and 500 apart. |
| `none_of` with a `Separator::Literal` made of whitespace | Refused with `ClaimRuleError::WhitespaceLiteralOnDeny`. Use `Separator::Whitespace`. |
| `Authenticator::authenticate(token, introspection)` and `can_handle_token(token, introspection)` | `authenticate(&Token)` and `can_handle_token(&Token)`. `Token::as_str()` is the token, `Token::introspection()` reads it on first use. |
| `introspect::introspect(token)` | `Token::new(token).introspection().clone()`. |
| Exhaustive `match` on `IntrospectionResult`, `AuthenticatorEnum`, `KubernetesSubjectSource` | Add a wildcard arm. Patterns of `IntrospectionResult::JWTBearer` need `..`. |
| serde_json's `preserve_order` feature, turned on by limes for your whole build | limes leaves it off, so JSON objects sort their keys. If your code needs objects in insertion order, turn the feature on in your own `Cargo.toml`. |
| `default-features = false` with JWT verification by aws-lc-rs | Add the feature `aws-lc-rs`, or `rust-crypto` for the RustCrypto crates. Without one, `JWKSWebAuthenticator::new` returns `Error::NoJwtCryptoProvider` and the `cache` feature does not build. |

limes 0.8 also moves to jsonwebtoken 12, kube 5.1 and k8s-openapi 0.29.
