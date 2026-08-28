//! Rules over verified token claims.
//!
//! A [`ClaimRule`] is evaluated against the decoded claims of a token whose signature,
//! issuer and audience have already been verified. Rules are validated at construction
//! and matched with [`ClaimRule::matches`].

use std::{borrow::Cow, collections::HashSet};

/// How a lone string claim is split into values before set operators are applied. Array
/// elements are not split by `any_of`/`all_of`/`exists`; `none_of` additionally considers the
/// split reading so that a deny cannot be evaded by embedding a banned value in an element.
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
    ///
    /// A value is the *whole* string unless a separator is configured: without one,
    /// `none_of ["admin"]` does NOT fire on `"scope": "openid admin"` — that claim's single
    /// value is `"openid admin"`. Configure the separator that matches the claim's format
    /// when denying values inside delimited strings.
    ///
    /// With a separator, a deny fires if *any* reading of the claim yields a banned value:
    /// the values as written and the pieces they split into, array elements included. A grant
    /// never splits array elements, so the two directions are deliberately asymmetric — each
    /// errs towards refusing access.
    NoneOf(HashSet<String>),
    /// `true`: the claim is populated — present, not `null`, and carrying at least one
    /// non-empty value or, for an object, at least one member. `false`: absent or `null`.
    ///
    /// These are not opposites: a claim that is present but empty (`[]`, `""`, `{}`)
    /// satisfies neither.
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
    /// At least one of `values` must be a value of `claim`.
    ///
    /// `claim` is a dotted path such as `realm_access.roles`, which nests on every dot, or —
    /// when it contains `/` or `:` — the whole name of one claim, as identity providers use
    /// for namespaced custom claims (`https://example.com/roles`). The same applies to all
    /// constructors.
    ///
    /// # Errors
    /// See [`ClaimRuleError`].
    pub fn any_of<I: IntoIterator<Item = S>, S: Into<String>>(
        claim: impl Into<String>,
        values: I,
    ) -> Result<Self, ClaimRuleError> {
        Self::new(claim, None, ClaimOperator::AnyOf(collect(values)))
    }

    /// Every one of `values` must be a value of `claim`.
    ///
    /// # Errors
    /// See [`ClaimRuleError`].
    pub fn all_of<I: IntoIterator<Item = S>, S: Into<String>>(
        claim: impl Into<String>,
        values: I,
    ) -> Result<Self, ClaimRuleError> {
        Self::new(claim, None, ClaimOperator::AllOf(collect(values)))
    }

    /// None of `values` may be a value of `claim`; a missing claim fails.
    ///
    /// # Errors
    /// See [`ClaimRuleError`].
    pub fn none_of<I: IntoIterator<Item = S>, S: Into<String>>(
        claim: impl Into<String>,
        values: I,
    ) -> Result<Self, ClaimRuleError> {
        Self::new(claim, None, ClaimOperator::NoneOf(collect(values)))
    }

    /// `claim` must be populated (`true`) — present, not `null`, and carrying a non-empty
    /// value or, for an object or an array of objects, at least one member — or absent or
    /// `null` (`false`). A claim that is present but empty satisfies neither.
    ///
    /// # Errors
    /// See [`ClaimRuleError`].
    pub fn exists(claim: impl Into<String>, expected: bool) -> Result<Self, ClaimRuleError> {
        Self::new(claim, None, ClaimOperator::Exists(expected))
    }

    /// Split a lone string claim on `separator` before matching. Array elements are not
    /// split by a grant, since an array already states one value per element; `none_of` also
    /// denies on the split reading so a deny cannot be evaded.
    ///
    /// # Errors
    /// [`ClaimRuleError::EmptySeparator`], or [`ClaimRuleError::ValueContainsSeparator`] if a
    /// listed value contains the separator (it could never match a split piece).
    pub fn with_separator(self, separator: Separator) -> Result<Self, ClaimRuleError> {
        Self::new_with_claims(self.claims, Some(separator), self.operator)
    }

    pub(crate) fn new(
        claim: impl Into<String>,
        separator: Option<Separator>,
        operator: ClaimOperator,
    ) -> Result<Self, ClaimRuleError> {
        Self::new_with_claims(vec![validate_path(claim.into())?], separator, operator)
    }

    fn new_with_claims(
        claims: Vec<String>,
        separator: Option<Separator>,
        operator: ClaimOperator,
    ) -> Result<Self, ClaimRuleError> {
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
            claims,
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
    /// [`ClaimRuleError::InvalidClaimPath`] if the path is empty, or nests on a dot with an
    /// empty segment.
    pub fn or_claim(mut self, claim: impl Into<String>) -> Result<Self, ClaimRuleError> {
        self.claims.push(validate_path(claim.into())?);
        Ok(self)
    }

    /// The claim paths in lookup order.
    #[must_use]
    pub(crate) fn claims(&self) -> &[String] {
        &self.claims
    }

    /// The operator.
    #[cfg(test)]
    pub(crate) fn operator(&self) -> &ClaimOperator {
        &self.operator
    }

    /// Evaluate the rule against decoded claims.
    ///
    /// The claim is the first path that is present and not `null`; if there is none it is
    /// *missing*. A present claim is a set of values: a scalar is its canonical string, an
    /// array of scalars is its elements, and strings are split by the separator. Objects and
    /// arrays holding non-scalars are *malformed*: they exist but carry no value.
    ///
    /// `exists: true` holds when the claim is *populated*: it carries at least one non-empty
    /// value, or — being malformed and so carrying none — holds at least one member or
    /// element. A claim that is present but empty (`[]`, `""`, `{}`) satisfies it no more
    /// than a missing one. `exists: false` keeps its narrow meaning of absent or `null`, so
    /// the two are not complements: an empty claim fails both.
    #[must_use]
    pub fn matches(&self, claims: &serde_json::Value) -> bool {
        let value = self
            .claims
            .iter()
            .filter_map(|path| navigate(claims, path))
            .find(|v| !v.is_null());
        let items = value.and_then(scalars);
        let separator = self.separator.as_ref();
        let values = || items.map(|(items, split)| ClaimValues::new(items, separator, split));
        match &self.operator {
            ClaimOperator::Exists(true) => match value {
                None => false,
                // An object or an array of objects carries no comparable value, but it is
                // still content: `exists` asks whether the claim is populated.
                Some(serde_json::Value::Object(map)) => !map.is_empty(),
                Some(serde_json::Value::Array(arr)) if items.is_none() => !arr.is_empty(),
                Some(_) => values().is_some_and(|mut v| v.any(|x| !x.is_empty())),
            },
            ClaimOperator::Exists(false) => value.is_none(),
            ClaimOperator::AnyOf(set) => values().is_some_and(|mut v| v.any(|x| set.contains(&*x))),
            // A deny holds only if no reading of the claim yields a banned value: both the
            // values as the issuer wrote them and, when a separator is configured, the pieces
            // it splits into — including inside array elements, which a grant never splits.
            ClaimOperator::NoneOf(set) => items.is_some_and(|(items, _)| {
                let banned = |separator, split| {
                    ClaimValues::new(items, separator, split).any(|x| set.contains(&*x))
                };
                !(banned(None, false) || (separator.is_some() && banned(separator, true)))
            }),
            // Splitting is the expensive part, so a multi-value `all_of` over a split string
            // splits once instead of once per needle.
            ClaimOperator::AllOf(set) if separator.is_some() && set.len() > 1 => values()
                .is_some_and(|v| {
                    let values: Vec<_> = v.collect();
                    set.iter()
                        .all(|needle| values.iter().any(|x| **x == **needle))
                }),
            ClaimOperator::AllOf(set) => items.is_some_and(|(items, split)| {
                set.iter()
                    .all(|needle| ClaimValues::new(items, separator, split).any(|x| *x == **needle))
            }),
        }
    }
}

/// The scalar items of a claim value: the value itself, or the elements of an array of
/// scalars. `None` for objects and arrays holding non-scalars.
///
/// The flag reports whether the claim was a lone scalar rather than an array, which is the
/// only case a separator may split.
pub(crate) fn scalars(value: &serde_json::Value) -> Option<(&[serde_json::Value], bool)> {
    match value {
        serde_json::Value::Array(items) if items.iter().all(is_scalar) => Some((items, false)),
        v if is_scalar(v) => Some((std::slice::from_ref(v), true)),
        _ => None,
    }
}

/// Like [`scalars`], but only a string or an array of strings qualifies; numbers and booleans
/// make the claim malformed. Used for scopes, which are strings by definition.
pub(crate) fn strings(value: &serde_json::Value) -> Option<(&[serde_json::Value], bool)> {
    match value {
        serde_json::Value::Array(items) if items.iter().all(serde_json::Value::is_string) => {
            Some((items, false))
        }
        serde_json::Value::String(_) => Some((std::slice::from_ref(value), true)),
        _ => None,
    }
}

fn is_scalar(value: &serde_json::Value) -> bool {
    value.is_string() || value.is_number() || value.is_boolean()
}

fn collect<I: IntoIterator<Item = S>, S: Into<String>>(values: I) -> HashSet<String> {
    values.into_iter().map(Into::into).collect()
}

fn validate_path(path: String) -> Result<String, ClaimRuleError> {
    if path.is_empty() || (!is_claim_name(&path) && path.split('.').any(str::is_empty)) {
        return Err(ClaimRuleError::InvalidClaimPath);
    }
    Ok(path)
}

/// Whether a path names one claim outright rather than describing a nesting.
///
/// Identity providers namespace custom claims as URIs (`https://example.com/roles`,
/// `kubernetes.io/serviceaccount/namespace`). A nesting never contains `/` or `:`, so those
/// characters distinguish the two without ambiguity.
fn is_claim_name(path: &str) -> bool {
    path.contains(['/', ':'])
}

/// Streams the comparable values of scalar items without collecting: strings are borrowed
/// (and split by the separator, empty pieces dropped), numbers and booleans are formatted.
///
/// The separator applies only when the claim is a lone string. An array already states one
/// value per element, so splitting its elements would manufacture values the issuer never
/// put in the token — `["x,admin"]` must not satisfy a rule for `admin`.
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
    /// `separator` is applied only if `items` is a lone string claim, not array elements.
    pub(crate) fn new(
        items: &'a [serde_json::Value],
        separator: Option<&'a Separator>,
        split: bool,
    ) -> Self {
        Self {
            items: items.iter(),
            separator: if split { separator } else { None },
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

/// Resolve a claim path.
///
/// A path containing `/` or `:` names a single claim and is looked up whole — that is how
/// identity providers namespace custom claims (`https://example.com/roles`). Any other path
/// nests on every dot, so a flat claim spelled like a nesting can never shadow the nested
/// claim a rule targets. Returns `None` if the path is absent.
pub(crate) fn navigate<'a>(
    claims: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    if is_claim_name(path) {
        return claims.get(path);
    }
    let mut current = claims;
    for part in path.split('.') {
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
    fn named_constructors_build_the_same_rules_as_new() {
        assert_eq!(
            ClaimRule::any_of("c", ["a", "b"]).unwrap(),
            rule("c", any_of(&["a", "b"]))
        );
        assert_eq!(
            ClaimRule::all_of("c", ["a"]).unwrap(),
            rule("c", all_of(&["a"]))
        );
        assert_eq!(
            ClaimRule::none_of("c", ["a"]).unwrap(),
            rule("c", none_of(&["a"]))
        );
        assert_eq!(
            ClaimRule::exists("c", true).unwrap(),
            rule("c", ClaimOperator::Exists(true))
        );
        assert_eq!(
            ClaimRule::any_of("c", ["a"])
                .unwrap()
                .with_separator(Separator::Whitespace)
                .unwrap(),
            rule_sep("c", Separator::Whitespace, any_of(&["a"]))
        );
        // `with_separator` revalidates values against the separator.
        assert_eq!(
            ClaimRule::none_of("groups", ["Domain Admins"])
                .unwrap()
                .with_separator(Separator::Whitespace)
                .unwrap_err(),
            ClaimRuleError::ValueContainsSeparator {
                operator: "none_of",
                value: "Domain Admins".to_string(),
            }
        );
        // The separator survives `or_claim`.
        assert_eq!(
            ClaimRule::all_of("scope", ["x"])
                .unwrap()
                .with_separator(Separator::Whitespace)
                .unwrap()
                .or_claim("scp")
                .unwrap(),
            ClaimRule::new("scope", Some(Separator::Whitespace), all_of(&["x"]))
                .unwrap()
                .or_claim("scp")
                .unwrap()
        );
    }

    #[test]
    fn new_rejects_empty_claim_path() {
        assert_eq!(
            ClaimRule::new("", None, any_of(&["a"])).unwrap_err(),
            ClaimRuleError::InvalidClaimPath
        );
    }

    /// Identity providers namespace custom claims as URIs. Such a name is looked up whole,
    /// so the rule works and `exists: false` cannot be satisfied by a path that could never
    /// resolve.
    #[test]
    fn uri_shaped_claim_names_are_looked_up_whole() {
        let claims = json!({
            "https://myapp.example.com/org": ["tenant-a"],
            "kubernetes.io/serviceaccount/namespace": "prod",
        });
        assert!(
            ClaimRule::any_of("https://myapp.example.com/org", ["tenant-a"])
                .unwrap()
                .matches(&claims)
        );
        assert!(
            ClaimRule::any_of("kubernetes.io/serviceaccount/namespace", ["prod"])
                .unwrap()
                .matches(&claims)
        );
        assert!(
            ClaimRule::exists("https://myapp.example.com/org", true)
                .unwrap()
                .matches(&claims)
        );
        assert!(
            !ClaimRule::exists("https://myapp.example.com/org", false)
                .unwrap()
                .matches(&claims)
        );
        // Empty segments are only meaningful for a nesting, so a URI keeps its `//`.
        assert!(
            ClaimRule::exists("https://other.example.com/x", false)
                .unwrap()
                .matches(&claims)
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
        assert!(!r(ClaimOperator::Exists(true)).matches(&claims));
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

    /// `exists: true` asks whether the claim carries a value, so the wire form of
    /// "belongs to nothing" — an empty array or an empty string — does not satisfy it.
    /// `exists: false` keeps its narrow meaning (absent or `null`), so the two are not
    /// complements: both reject a claim that is present but carries nothing.
    #[test]
    fn empty_array_matches_no_operator() {
        let claims = claims_with(&json!([]));
        assert!(!rule("c", any_of(&["a"])).matches(&claims));
        assert!(!rule("c", all_of(&["a"])).matches(&claims));
        assert!(rule("c", none_of(&["a"])).matches(&claims));
        assert!(!rule("c", ClaimOperator::Exists(true)).matches(&claims));
        assert!(!rule("c", ClaimOperator::Exists(false)).matches(&claims));
    }

    #[test]
    fn exists_true_requires_a_non_empty_value() {
        for empty in [json!([]), json!(""), json!({}), json!(["", ""])] {
            let claims = claims_with(&empty);
            assert!(
                !rule("c", ClaimOperator::Exists(true)).matches(&claims),
                "{empty} must not satisfy exists=true"
            );
            assert!(
                !rule("c", ClaimOperator::Exists(false)).matches(&claims),
                "{empty} is present, so exists=false must not hold either"
            );
        }
        for present in [json!("a"), json!(0), json!(false), json!(["a"])] {
            let claims = claims_with(&present);
            assert!(
                rule("c", ClaimOperator::Exists(true)).matches(&claims),
                "{present} must satisfy exists=true"
            );
        }
    }

    /// An object carries no comparable value, so no set operator can hold. `exists` asks a
    /// different question — whether the claim is populated — and a populated object is.
    #[test]
    fn object_claim_matches_no_set_operator_but_is_populated() {
        let claims = claims_with(&json!({"a": "b"}));
        assert!(!rule("c", any_of(&["a"])).matches(&claims));
        assert!(!rule("c", all_of(&["a"])).matches(&claims));
        assert!(!rule("c", none_of(&["zzz"])).matches(&claims));
        assert!(rule("c", ClaimOperator::Exists(true)).matches(&claims));
        assert!(!rule("c", ClaimOperator::Exists(false)).matches(&claims));

        // A Keycloak-shaped nested claim is reachable both ways.
        let keycloak = json!({ "realm_access": { "roles": ["admin"] } });
        assert!(
            ClaimRule::exists("realm_access", true)
                .unwrap()
                .matches(&keycloak)
        );
        assert!(
            ClaimRule::any_of("realm_access.roles", ["admin"])
                .unwrap()
                .matches(&keycloak)
        );

        // An empty object is present but not populated.
        let empty = claims_with(&json!({}));
        assert!(!rule("c", ClaimOperator::Exists(true)).matches(&empty));
        assert!(!rule("c", ClaimOperator::Exists(false)).matches(&empty));
    }

    #[test]
    fn array_with_non_scalar_element_matches_no_set_operator() {
        for value in [
            json!(["a", ["b"]]),
            json!(["a", {"k": "v"}]),
            json!(["a", null]),
        ] {
            let claims = claims_with(&value);
            assert!(!rule("c", any_of(&["a"])).matches(&claims));
            assert!(!rule("c", all_of(&["a"])).matches(&claims));
            assert!(!rule("c", none_of(&["zzz"])).matches(&claims));
            // Not comparable, but populated.
            assert!(rule("c", ClaimOperator::Exists(true)).matches(&claims));
            assert!(!rule("c", ClaimOperator::Exists(false)).matches(&claims));
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
    fn empty_string_claim_carries_no_value() {
        let claims = claims_with(&json!(""));
        assert!(!rule("c", ClaimOperator::Exists(true)).matches(&claims));
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

    /// An array states one value per element. Splitting elements would manufacture values
    /// the issuer never put in the token, so a rule for `admin` must not match
    /// `["x,admin"]`.
    #[test]
    fn separator_does_not_split_array_elements() {
        let claims = claims_with(&json!(["openid email", "profile"]));
        let r = rule_sep(
            "c",
            Separator::Whitespace,
            all_of(&["openid", "email", "profile"]),
        );
        assert!(!r.matches(&claims));
        // Unsplit, each element is one value — matched by a rule without a separator.
        assert!(rule("c", all_of(&["openid email", "profile"])).matches(&claims));

        let smuggled = claims_with(&json!(["x,platform-admins"]));
        let r = rule_sep(
            "c",
            Separator::Literal(",".into()),
            any_of(&["platform-admins"]),
        );
        assert!(!r.matches(&smuggled));
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

    /// Every dot nests. A flat key spelled like the path is a *different*, unaddressable
    /// claim — it can never shadow the nested claim a rule targets, so a token cannot
    /// smuggle a flat `realm_access.roles` key past a deny rule.
    #[test]
    fn dots_always_nest_and_flat_keys_never_shadow() {
        let both = json!({ "a.b": "flat", "a": { "b": "nested" } });
        assert!(rule("a.b", any_of(&["nested"])).matches(&both));
        assert!(!rule("a.b", any_of(&["flat"])).matches(&both));

        let attack = json!({
            "realm_access.roles": ["ok"],
            "realm_access": { "roles": ["banned"] },
        });
        assert!(!rule("realm_access.roles", none_of(&["banned"])).matches(&attack));

        // A flat key spelled like the nesting, even a `null` one, cannot hide it.
        let null_flat = json!({ "a.b": null, "a": { "b": "real" } });
        assert!(rule("a.b", ClaimOperator::Exists(true)).matches(&null_flat));
        assert!(!rule("a.b", ClaimOperator::Exists(false)).matches(&null_flat));

        // Consequence: a URI-shaped claim name is not addressable; such a path is rejected
        // at construction (see `new_rejects_uri_shaped_claim_paths`).
    }

    /// Pins the documented `none_of` semantics: without a separator the whole string is one
    /// value, so denies inside delimited strings need the matching separator.
    #[test]
    fn none_of_without_separator_treats_the_whole_string_as_one_value() {
        let claims = claims_with(&json!("openid admin"));
        assert!(rule("c", none_of(&["admin"])).matches(&claims));
        assert!(!rule_sep("c", Separator::Whitespace, none_of(&["admin"])).matches(&claims));
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

    /// A multi-value `all_of` takes the split-once path; it must agree with the general one.
    #[test]
    fn all_of_over_a_split_string_matches_every_value() {
        let claims = claims_with(&json!("a b c"));
        let r = |v: &[&str]| rule_sep("c", Separator::Whitespace, all_of(v));
        assert!(r(&["a", "b"]).matches(&claims));
        assert!(r(&["a", "b", "c"]).matches(&claims));
        assert!(!r(&["a", "z"]).matches(&claims));
        assert!(!r(&["a", "b", "c", "d"]).matches(&claims));
        assert!(r(&["a"]).matches(&claims));
    }

    /// A deny must not be evadable by embedding the banned value in an array element, even
    /// though a grant deliberately refuses to split those elements.
    #[test]
    fn none_of_denies_a_banned_value_inside_an_array_element() {
        let smuggled = claims_with(&json!(["x,admin"]));
        let deny = rule_sep("c", Separator::Literal(",".into()), none_of(&["admin"]));
        assert!(!deny.matches(&smuggled));
        // The same claim as a lone string is denied too.
        assert!(!deny.matches(&claims_with(&json!("x,admin"))));
        // ...while the grant direction still refuses to manufacture the value.
        let grant = rule_sep("c", Separator::Literal(",".into()), any_of(&["admin"]));
        assert!(!grant.matches(&smuggled));

        // Values the issuer wrote are denied regardless of the separator.
        assert!(!deny.matches(&claims_with(&json!(["admin"]))));
        // An unrelated claim still passes the deny.
        assert!(deny.matches(&claims_with(&json!(["users"]))));
    }

    #[test]
    fn navigate_walks_dotted_paths() {
        let claims = json!({ "a": { "b": 1 } });
        assert_eq!(navigate(&claims, "a.b"), Some(&json!(1)));
        assert_eq!(navigate(&claims, "a.c"), None);
        assert_eq!(navigate(&claims, "a"), Some(&json!({ "b": 1 })));
    }
}
