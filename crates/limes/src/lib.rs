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
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]

mod authenticator;
mod chain;
pub mod error;
pub mod introspect;
#[cfg(feature = "jwks")]
pub mod jwks;
mod subject;

#[cfg(feature = "kubernetes")]
pub mod kubernetes;

pub use authenticator::{Authentication, Authenticator, PrincipalType};
pub use chain::{AuthenticatorChain, AuthenticatorChainBuilder, AuthenticatorEnum};
pub use subject::Subject;

pub use subject::{format_subject, parse_subject};

#[cfg(feature = "axum")]
pub mod axum;
