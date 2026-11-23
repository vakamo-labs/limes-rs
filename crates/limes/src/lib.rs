#![warn(
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    clippy::pedantic
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::large_enum_variant,
    clippy::doc_markdown
)]
#![forbid(unsafe_code)]
#![cfg_attr(not(doctest), doc = include_str!("../README.md"))]

mod authenticator;
#[cfg(feature = "cache")]
pub mod cache;
mod chain;
pub mod claims;
pub mod error;
mod identity;
pub mod introspect;
#[cfg(feature = "jwks")]
pub mod jwks;
mod subject;
mod token;
pub mod tower;

#[cfg(feature = "kubernetes")]
pub mod kubernetes;

pub use authenticator::{Authentication, Authenticator};
pub use chain::{AuthenticatorChain, AuthenticatorChainBuilder, AuthenticatorEnum};
pub use claims::{ClaimOperator, ClaimRule, ClaimRuleError, Separator};
pub use error::RejectionReason;
pub use identity::{Identity, KubernetesUser, VerifiedClaims};
pub use subject::Subject;
pub use token::Token;

#[cfg(feature = "axum")]
pub mod axum;

/// The README examples need the `jwks`, `kubernetes` and `cache` features, so they run as
/// doctests only with all three.
#[cfg(all(doctest, feature = "jwks", feature = "kubernetes", feature = "cache"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
