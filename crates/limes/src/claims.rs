//! Rules over verified token claims.
//!
//! A [`ClaimRule`] is evaluated against the decoded claims of a token whose signature,
//! issuer and audience have already been verified. Rules are validated at construction
//! and matched with [`ClaimRule::matches`].

use std::{borrow::Cow, collections::HashSet};

/// How a string claim is split into values before set operators are applied.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Separator {
    /// Split on any Unicode whitespace (the OAuth `scope` convention).
    Whitespace,
    /// Split on an exact, non-empty literal.
    Literal(String),
}

/// The single operator of a [`ClaimRule`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimOperator {
    /// At least one claim value is in the set.
    AnyOf(HashSet<String>),
    /// Every value of the set is a claim value.
    AllOf(HashSet<String>),
    /// No claim value is in the set. A missing claim fails.
    NoneOf(HashSet<String>),
    /// `true`: the claim is present and not `null`; `false`: absent or `null`.
    Exists(bool),
}

/// A structurally invalid rule, rejected at construction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimRuleError {
    #[error("claim path must not be empty or contain empty segments")]
    InvalidClaimPath,
    #[error("{operator} must not be empty")]
    EmptyValueList { operator: &'static str },
    #[error("{operator} must not contain empty strings")]
    EmptyValue { operator: &'static str },
    #[error("separator must not be empty")]
    EmptySeparator,
    /// A value the separator would split can never equal a split piece, so the rule could
    /// never match it — and a `none_of` rule would never deny it.
    #[error("{operator} value `{value}` contains the separator")]
    ValueContainsSeparator {
        operator: &'static str,
        value: String,
    },
}

/// A validated rule over one claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRule {
    claims: Vec<String>,
    separator: Option<Separator>,
    operator: ClaimOperator,
}

impl ClaimRule {
    /// Build a rule for `claim`, a claim name or a dotted path such as `realm_access.roles`.
    /// A name containing dots (e.g. `https://example.com/roles`) is looked up as a whole key
    /// first; only if no such key exists is it walked as a path.
    ///
    /// # Errors
    /// See [`ClaimRuleError`].
    pub fn new(
        claim: impl Into<String>,
        separator: Option<Separator>,
        operator: ClaimOperator,
    ) -> Result<Self, ClaimRuleError> {
        let claim = validate_path(claim.into())?;
        if matches!(&separator, Some(Separator::Literal(literal)) if literal.is_empty()) {
            return Err(ClaimRuleError::EmptySeparator);
        }
        let (name, values) = match &operator {
            ClaimOperator::AnyOf(v) => ("any_of", Some(v)),
            ClaimOperator::AllOf(v) => ("all_of", Some(v)),
            ClaimOperator::NoneOf(v) => ("none_of", Some(v)),
            ClaimOperator::Exists(_) => ("exists", None),
        };
        if let Some(values) = values {
            if values.is_empty() {
                return Err(ClaimRuleError::EmptyValueList { operator: name });
            }
            if values.iter().any(String::is_empty) {
                return Err(ClaimRuleError::EmptyValue { operator: name });
            }
            let split_by_separator = |v: &str| match &separator {
                Some(Separator::Whitespace) => v.contains(char::is_whitespace),
                Some(Separator::Literal(sep)) => v.contains(sep.as_str()),
                None => false,
            };
            if let Some(value) = values.iter().find(|v| split_by_separator(v)) {
                return Err(ClaimRuleError::ValueContainsSeparator {
                    operator: name,
                    value: value.clone(),
                });
            }
        }
        Ok(Self {
            claims: vec![claim],
            separator,
            operator,
        })
    }

    /// Add a fallback claim path, consulted only when every earlier path is absent or `null`.
    ///
    /// The first present path decides the rule alone: with `none_of`, a banned value that
    /// appears only in a fallback path is not seen when the primary path is present.
    ///
    /// # Errors
    /// [`ClaimRuleError::InvalidClaimPath`] if the path is empty or has empty segments.
    pub fn or_claim(mut self, claim: impl Into<String>) -> Result<Self, ClaimRuleError> {
        self.claims.push(validate_path(claim.into())?);
        Ok(self)
    }

    /// The claim paths in lookup order.
    #[must_use]
    pub fn claims(&self) -> &[String] {
        &self.claims
    }

    /// The operator.
    #[must_use]
    pub fn operator(&self) -> &ClaimOperator {
        &self.operator
    }

    /// Evaluate the rule against decoded claims.
    ///
    /// The claim is the first path that is present and not `null`; if there is none it is
    /// *missing*. A present claim is a set of values: a scalar is its canonical string, an
    /// array of scalars is its elements, and strings are split by the separator. Objects and
    /// arrays holding non-scalars are *malformed*: they exist but match no value.
    #[must_use]
    pub fn matches(&self, claims: &serde_json::Value) -> bool {
        let value = self
            .claims
            .iter()
            .filter_map(|path| navigate(claims, path))
            .find(|v| !v.is_null());
        let items = value.and_then(scalars);
        let separator = self.separator.as_ref();
        let values = || items.map(|items| ClaimValues::new(items, separator));
        match &self.operator {
            ClaimOperator::Exists(expected) => value.is_some() == *expected,
            ClaimOperator::AnyOf(set) => values().is_some_and(|mut v| v.any(|x| set.contains(&*x))),
            ClaimOperator::NoneOf(set) => {
                values().is_some_and(|mut v| !v.any(|x| set.contains(&*x)))
            }
            ClaimOperator::AllOf(set) => items.is_some_and(|items| {
                set.iter()
                    .all(|needle| ClaimValues::new(items, separator).any(|x| *x == **needle))
            }),
        }
    }
}

/// The scalar items of a claim value: the value itself, or the elements of an array of
/// scalars. `None` for objects and arrays holding non-scalars.
pub(crate) fn scalars(value: &serde_json::Value) -> Option<&[serde_json::Value]> {
    match value {
        serde_json::Value::Array(items) if items.iter().all(is_scalar) => Some(items),
        v if is_scalar(v) => Some(std::slice::from_ref(v)),
        _ => None,
    }
}

fn is_scalar(value: &serde_json::Value) -> bool {
    value.is_string() || value.is_number() || value.is_boolean()
}

fn validate_path(path: String) -> Result<String, ClaimRuleError> {
    if path.is_empty() || path.split('.').any(str::is_empty) {
        return Err(ClaimRuleError::InvalidClaimPath);
    }
    Ok(path)
}

/// Streams the comparable values of scalar items without collecting: strings are borrowed
/// (and split by the separator, empty pieces dropped), numbers and booleans are formatted.
pub(crate) struct ClaimValues<'a> {
    items: std::slice::Iter<'a, serde_json::Value>,
    separator: Option<&'a Separator>,
    pending: Option<Pieces<'a>>,
}

enum Pieces<'a> {
    Whitespace(std::str::SplitWhitespace<'a>),
    Literal(std::str::Split<'a, &'a str>),
}

impl<'a> ClaimValues<'a> {
    pub(crate) fn new(items: &'a [serde_json::Value], separator: Option<&'a Separator>) -> Self {
        Self {
            items: items.iter(),
            separator,
            pending: None,
        }
    }
}

impl<'a> Iterator for ClaimValues<'a> {
    type Item = Cow<'a, str>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(pieces) = &mut self.pending {
                let piece = match pieces {
                    Pieces::Whitespace(it) => it.next(),
                    Pieces::Literal(it) => it.find(|p| !p.is_empty()),
                };
                match piece {
                    Some(p) => return Some(Cow::Borrowed(p)),
                    None => self.pending = None,
                }
            }
            let item = self.items.next()?;
            match (item, self.separator) {
                (serde_json::Value::String(s), None) => return Some(Cow::Borrowed(s)),
                (serde_json::Value::String(s), Some(Separator::Whitespace)) => {
                    self.pending = Some(Pieces::Whitespace(s.split_whitespace()));
                }
                (serde_json::Value::String(s), Some(Separator::Literal(sep))) => {
                    self.pending = Some(Pieces::Literal(s.split(sep.as_str())));
                }
                (other, _) => return Some(Cow::Owned(other.to_string())),
            }
        }
    }
}

/// Look up a claim by its whole name, or navigate nested claims using dot-notation
/// (e.g. `resource_access.account.roles`) if no key of that name exists. Returns `None` if
/// the path is absent.
pub(crate) fn navigate<'a>(
    claims: &'a serde_json::Value,
    dot_path: &str,
) -> Option<&'a serde_json::Value> {
    if let Some(whole) = claims.get(dot_path) {
        return Some(whole);
    }
    let mut current = claims;
    for part in dot_path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::{Value, json};

    fn set(values: &[&str]) -> HashSet<String> {
        values.iter().map(ToString::to_string).collect()
    }

    fn rule(claim: &str, operator: ClaimOperator) -> ClaimRule {
        ClaimRule::new(claim, None, operator).unwrap()
    }

    fn rule_sep(claim: &str, separator: Separator, operator: ClaimOperator) -> ClaimRule {
        ClaimRule::new(claim, Some(separator), operator).unwrap()
    }

    fn any_of(values: &[&str]) -> ClaimOperator {
        ClaimOperator::AnyOf(set(values))
    }
    fn all_of(values: &[&str]) -> ClaimOperator {
        ClaimOperator::AllOf(set(values))
    }
    fn none_of(values: &[&str]) -> ClaimOperator {
        ClaimOperator::NoneOf(set(values))
    }

    // ---- construction ----

    #[test]
    fn new_rejects_empty_claim_path() {
        assert_eq!(
            ClaimRule::new("", None, any_of(&["a"])).unwrap_err(),
            ClaimRuleError::InvalidClaimPath
        );
    }

    #[test]
    fn new_rejects_empty_path_segments() {
        for path in ["a..b", ".a", "a.", "."] {
            assert_eq!(
                ClaimRule::new(path, None, any_of(&["a"])).unwrap_err(),
                ClaimRuleError::InvalidClaimPath,
                "path {path:?}"
            );
        }
    }

    #[test]
    fn new_rejects_empty_value_lists() {
        for (operator, name) in [
            (ClaimOperator::AnyOf(HashSet::new()), "any_of"),
            (ClaimOperator::AllOf(HashSet::new()), "all_of"),
            (ClaimOperator::NoneOf(HashSet::new()), "none_of"),
        ] {
            assert_eq!(
                ClaimRule::new("c", None, operator).unwrap_err(),
                ClaimRuleError::EmptyValueList { operator: name }
            );
        }
    }

    #[test]
    fn new_rejects_empty_string_values() {
        assert_eq!(
            ClaimRule::new("c", None, any_of(&["a", ""])).unwrap_err(),
            ClaimRuleError::EmptyValue { operator: "any_of" }
        );
    }

    #[test]
    fn new_rejects_values_the_separator_would_split() {
        assert_eq!(
            ClaimRule::new(
                "groups",
                Some(Separator::Whitespace),
                none_of(&["Domain Admins"])
            )
            .unwrap_err(),
            ClaimRuleError::ValueContainsSeparator {
                operator: "none_of",
                value: "Domain Admins".to_string(),
            }
        );
        assert_eq!(
            ClaimRule::new("c", Some(Separator::Literal(",".into())), any_of(&["a,b"]))
                .unwrap_err(),
            ClaimRuleError::ValueContainsSeparator {
                operator: "any_of",
                value: "a,b".to_string(),
            }
        );
        // Without a separator a value may contain anything.
        assert!(ClaimRule::new("c", None, none_of(&["Domain Admins"])).is_ok());
    }

    #[test]
    fn new_rejects_empty_literal_separator() {
        assert_eq!(
            ClaimRule::new("c", Some(Separator::Literal(String::new())), any_of(&["a"]))
                .unwrap_err(),
            ClaimRuleError::EmptySeparator
        );
    }

    #[test]
    fn new_accepts_exists_without_values() {
        let r = rule("c", ClaimOperator::Exists(true));
        assert_eq!(r.claims(), &["c".to_string()]);
        assert_eq!(r.operator(), &ClaimOperator::Exists(true));
    }

    #[test]
    fn or_claim_appends_fallback_and_validates() {
        let r = rule("scope", all_of(&["x"])).or_claim("scp").unwrap();
        assert_eq!(r.claims(), &["scope".to_string(), "scp".to_string()]);
        assert_eq!(
            rule("scope", all_of(&["x"])).or_claim("a..b").unwrap_err(),
            ClaimRuleError::InvalidClaimPath
        );
    }

    // ---- value shapes ----

    fn claims_with(value: &Value) -> Value {
        json!({ "sub": "u", "c": value })
    }

    #[test]
    fn string_claim_is_a_single_value() {
        let claims = claims_with(&json!("admin"));
        assert!(rule("c", any_of(&["admin", "x"])).matches(&claims));
        assert!(rule("c", all_of(&["admin"])).matches(&claims));
        assert!(!rule("c", all_of(&["admin", "x"])).matches(&claims));
        assert!(rule("c", none_of(&["x"])).matches(&claims));
        assert!(!rule("c", none_of(&["admin"])).matches(&claims));
    }

    #[test]
    fn string_claim_is_not_split_without_separator() {
        let claims = claims_with(&json!("openid email"));
        assert!(!rule("c", any_of(&["openid"])).matches(&claims));
        assert!(rule("c", any_of(&["openid email"])).matches(&claims));
    }

    #[test]
    fn number_and_bool_claims_compare_by_canonical_string() {
        assert!(rule("c", any_of(&["42"])).matches(&claims_with(&json!(42))));
        assert!(!rule("c", any_of(&["42"])).matches(&claims_with(&json!(42.0))));
        assert!(rule("c", any_of(&["1.5"])).matches(&claims_with(&json!(1.5))));
        assert!(rule("c", any_of(&["true"])).matches(&claims_with(&json!(true))));
        assert!(!rule("c", any_of(&["True"])).matches(&claims_with(&json!(true))));
    }

    #[test]
    fn whitespace_only_string_with_separator_has_no_values() {
        let claims = claims_with(&json!("   "));
        let r = |op| rule_sep("c", Separator::Whitespace, op);
        assert!(!r(any_of(&["a"])).matches(&claims));
        assert!(!r(all_of(&["a"])).matches(&claims));
        // Like an empty array: present, nothing to deny.
        assert!(r(none_of(&["a"])).matches(&claims));
        assert!(r(ClaimOperator::Exists(true)).matches(&claims));
    }

    #[test]
    fn array_claim_has_set_semantics() {
        let claims = claims_with(&json!(["a", "b", 3]));
        assert!(rule("c", any_of(&["b"])).matches(&claims));
        assert!(rule("c", any_of(&["3"])).matches(&claims));
        assert!(rule("c", all_of(&["a", "b"])).matches(&claims));
        assert!(!rule("c", all_of(&["a", "z"])).matches(&claims));
        assert!(rule("c", none_of(&["z"])).matches(&claims));
        assert!(!rule("c", none_of(&["a"])).matches(&claims));
    }

    #[test]
    fn empty_array_matches_nothing_but_exists() {
        let claims = claims_with(&json!([]));
        assert!(!rule("c", any_of(&["a"])).matches(&claims));
        assert!(!rule("c", all_of(&["a"])).matches(&claims));
        assert!(rule("c", none_of(&["a"])).matches(&claims));
        assert!(rule("c", ClaimOperator::Exists(true)).matches(&claims));
        assert!(!rule("c", ClaimOperator::Exists(false)).matches(&claims));
    }

    #[test]
    fn object_claim_fails_every_operator_except_exists_true() {
        let claims = claims_with(&json!({"a": "b"}));
        assert!(!rule("c", any_of(&["a"])).matches(&claims));
        assert!(!rule("c", all_of(&["a"])).matches(&claims));
        assert!(!rule("c", none_of(&["zzz"])).matches(&claims));
        assert!(rule("c", ClaimOperator::Exists(true)).matches(&claims));
        assert!(!rule("c", ClaimOperator::Exists(false)).matches(&claims));
    }

    #[test]
    fn array_with_non_scalar_element_fails_every_operator_except_exists_true() {
        for value in [
            json!(["a", ["b"]]),
            json!(["a", {"k": "v"}]),
            json!(["a", null]),
        ] {
            let claims = claims_with(&value);
            assert!(!rule("c", any_of(&["a"])).matches(&claims));
            assert!(!rule("c", none_of(&["zzz"])).matches(&claims));
            assert!(rule("c", ClaimOperator::Exists(true)).matches(&claims));
        }
    }

    #[test]
    fn missing_claim_fails_every_operator_except_exists_false() {
        let claims = json!({ "sub": "u" });
        assert!(!rule("c", any_of(&["a"])).matches(&claims));
        assert!(!rule("c", all_of(&["a"])).matches(&claims));
        assert!(!rule("c", none_of(&["a"])).matches(&claims));
        assert!(!rule("c", ClaimOperator::Exists(true)).matches(&claims));
        assert!(rule("c", ClaimOperator::Exists(false)).matches(&claims));
    }

    #[test]
    fn null_claim_behaves_like_missing() {
        let claims = claims_with(&Value::Null);
        assert!(!rule("c", any_of(&["a"])).matches(&claims));
        assert!(!rule("c", none_of(&["a"])).matches(&claims));
        assert!(!rule("c", ClaimOperator::Exists(true)).matches(&claims));
        assert!(rule("c", ClaimOperator::Exists(false)).matches(&claims));
    }

    #[test]
    fn empty_string_claim_exists() {
        let claims = claims_with(&json!(""));
        assert!(rule("c", ClaimOperator::Exists(true)).matches(&claims));
        assert!(!rule("c", any_of(&["a"])).matches(&claims));
    }

    #[test]
    fn matching_is_case_sensitive() {
        let claims = claims_with(&json!("Admin"));
        assert!(!rule("c", any_of(&["admin"])).matches(&claims));
        assert!(rule("c", any_of(&["Admin"])).matches(&claims));
    }

    #[test]
    fn values_may_contain_commas_and_spaces() {
        let claims = claims_with(&json!(["a,b", "c d"]));
        assert!(rule("c", all_of(&["a,b", "c d"])).matches(&claims));
    }

    // ---- separators ----

    #[test]
    fn whitespace_separator_splits_string_claim() {
        let claims = claims_with(&json!("openid  email\tprofile"));
        let r = |op| rule_sep("c", Separator::Whitespace, op);
        assert!(r(all_of(&["openid", "email", "profile"])).matches(&claims));
        assert!(!r(any_of(&["open"])).matches(&claims));
        // The double space yields no empty value.
        assert!(!r(ClaimOperator::Exists(false)).matches(&claims));
        assert!(r(none_of(&["x"])).matches(&claims));
    }

    #[test]
    fn literal_separator_splits_string_claim_and_drops_empty_pieces() {
        let claims = claims_with(&json!("a,,b,"));
        let r = rule_sep("c", Separator::Literal(",".into()), all_of(&["a", "b"]));
        assert!(r.matches(&claims));
        // Exactly the two pieces: nothing else to deny.
        let r = rule_sep("c", Separator::Literal(",".into()), none_of(&["c"]));
        assert!(r.matches(&claims));
        let r = rule_sep("c", Separator::Literal(",".into()), none_of(&["b"]));
        assert!(!r.matches(&claims));
    }

    #[test]
    fn literal_separator_is_exact_not_whitespace() {
        let claims = claims_with(&json!("a b\tc"));
        let r = rule_sep("c", Separator::Literal(" ".into()), all_of(&["a", "b\tc"]));
        assert!(r.matches(&claims));
    }

    #[test]
    fn separator_applies_to_each_string_array_element() {
        let claims = claims_with(&json!(["openid email", "profile"]));
        let r = rule_sep(
            "c",
            Separator::Whitespace,
            all_of(&["openid", "email", "profile"]),
        );
        assert!(r.matches(&claims));
    }

    #[test]
    fn separator_does_not_apply_to_numbers() {
        let claims = claims_with(&json!(1.5));
        let r = rule_sep("c", Separator::Literal(",".into()), any_of(&["1.5"]));
        assert!(r.matches(&claims));
    }

    // ---- paths ----

    #[test]
    fn dotted_path_resolves_nested_claims() {
        let claims = json!({ "realm_access": { "roles": ["admin"] } });
        assert!(rule("realm_access.roles", any_of(&["admin"])).matches(&claims));
        assert!(!rule("realm_access.missing", ClaimOperator::Exists(true)).matches(&claims));
    }

    #[test]
    fn claim_name_containing_dots_is_matched_as_a_whole_key_first() {
        let claims = json!({ "https://example.com/roles": ["admin"], "a": { "b": "nested" } });
        assert!(rule("https://example.com/roles", any_of(&["admin"])).matches(&claims));
        assert!(rule("a.b", any_of(&["nested"])).matches(&claims));
        // A whole key wins over a path of the same spelling.
        let both = json!({ "a.b": "whole", "a": { "b": "nested" } });
        assert!(rule("a.b", any_of(&["whole"])).matches(&both));
        assert!(!rule("a.b", any_of(&["nested"])).matches(&both));
    }

    #[test]
    fn fallback_is_not_consulted_when_primary_is_present_but_malformed() {
        let r = rule("scope", any_of(&["x"])).or_claim("scp").unwrap();
        assert!(!r.matches(&json!({ "scope": {"k": "v"}, "scp": ["x"] })));
    }

    #[test]
    fn dotted_path_does_not_index_arrays() {
        let claims = json!({ "arr": ["x"] });
        assert!(!rule("arr.0", ClaimOperator::Exists(true)).matches(&claims));
    }

    #[test]
    fn fallback_claim_is_used_when_primary_is_absent_or_null() {
        let r = rule("scope", any_of(&["x"])).or_claim("scp").unwrap();
        assert!(r.matches(&json!({ "scp": ["x"] })));
        assert!(r.matches(&json!({ "scope": null, "scp": ["x"] })));
        // Primary present: fallback is NOT consulted.
        assert!(!r.matches(&json!({ "scope": "y", "scp": ["x"] })));
    }

    /// Pins the documented footgun: the first present path decides alone, so a banned
    /// value in the fallback path is not seen.
    #[test]
    fn fallback_is_not_consulted_for_none_of_when_primary_is_present() {
        let r = rule("scope", none_of(&["banned"])).or_claim("scp").unwrap();
        assert!(r.matches(&json!({ "scope": "ok", "scp": ["banned"] })));
        assert!(!r.matches(&json!({ "scp": ["banned"] })));
    }

    #[test]
    fn fallback_exists_false_requires_all_paths_absent() {
        let r = rule("scope", ClaimOperator::Exists(false))
            .or_claim("scp")
            .unwrap();
        assert!(r.matches(&json!({})));
        assert!(!r.matches(&json!({ "scp": "x" })));
    }

    #[test]
    fn navigate_walks_dotted_paths() {
        let claims = json!({ "a": { "b": 1 } });
        assert_eq!(navigate(&claims, "a.b"), Some(&json!(1)));
        assert_eq!(navigate(&claims, "a.c"), None);
        assert_eq!(navigate(&claims, "a"), Some(&json!({ "b": 1 })));
    }
}
