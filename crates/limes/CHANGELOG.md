# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.2](https://github.com/vakamo-labs/limes-rs/compare/v0.4.1...v0.4.2) - 2026-07-16

### Fixed

- *(deps)* drop removed reqwest `rustls-native-certs` feature ([#73](https://github.com/vakamo-labs/limes-rs/pull/73))

## [0.4.1](https://github.com/vakamo-labs/limes-rs/compare/v0.4.0...v0.4.1) - 2026-07-15

### Added

- *(kubernetes)* make subject source configurable (uid or username) ([#71](https://github.com/vakamo-labs/limes-rs/pull/71))

## [0.4.0](https://github.com/vakamo-labs/limes-rs/compare/v0.3.3...v0.4.0) - 2026-06-30

### Added

- expose issuer, scopes, token times, and full claims on Authentication ([#69](https://github.com/vakamo-labs/limes-rs/pull/69))
- [**breaking**] introspect once per request, bump deps ([#58](https://github.com/vakamo-labs/limes-rs/pull/58)) ([#64](https://github.com/vakamo-labs/limes-rs/pull/64))

### Fixed

- harden Kubernetes token validation and trim hot-path allocations ([#68](https://github.com/vakamo-labs/limes-rs/pull/68))

### Other

- remove unused once_cell dependency ([#66](https://github.com/vakamo-labs/limes-rs/pull/66))

## [0.3.3](https://github.com/vakamo-labs/limes-rs/compare/v0.3.2...v0.3.3) - 2026-06-28

### Added

- expose token audiences on Authentication ([#59](https://github.com/vakamo-labs/limes-rs/pull/59))

## [0.3.2](https://github.com/vakamo-labs/limes-rs/compare/v0.3.1...v0.3.2) - 2026-02-23

### Added

- add idp_ids() to Authenticator trait ([#57](https://github.com/vakamo-labs/limes-rs/pull/57))
- Introduce valuable feature flag ([#55](https://github.com/vakamo-labs/limes-rs/pull/55))

## [0.3.1](https://github.com/vakamo-labs/limes-rs/compare/v0.3.0...v0.3.1) - 2026-01-26

### Added

- Extract Roles from token in `JWKSWebAuthenticator` ([#52](https://github.com/vakamo-labs/limes-rs/pull/52))

### Fixed

- Treat empty role_claim strings as None ([#53](https://github.com/vakamo-labs/limes-rs/pull/53))

### Other

- *(limes)* release v0.3.0 ([#47](https://github.com/vakamo-labs/limes-rs/pull/47))

## [0.3.0](https://github.com/vakamo-labs/limes-rs/compare/v0.2.1...v0.3.0) - 2025-08-13

### Other

- Update deps (edition 2024, jsonwebtoken 10, kube 2, MSRV 1.88) ([#46](https://github.com/vakamo-labs/limes-rs/pull/46))

## [0.2.2](https://github.com/vakamo-labs/limes-rs/compare/v0.2.1...v0.2.2) - 2025-08-13

### Fixed

- Bump jwks_client to 0.5.2 - Add support for EdDSA algorithm ([#34](https://github.com/vakamo-labs/limes-rs/pull/34))

## [0.2.1](https://github.com/vakamo-labs/limes-rs/compare/v0.2.0...v0.2.1) - 2025-04-08

### Fixed

- Activate aws-lc-rs crypto ([#28](https://github.com/vakamo-labs/limes-rs/pull/28))

## [0.2.0](https://github.com/vakamo-labs/limes-rs/compare/v0.1.4...v0.2.0) - 2025-03-25

### Added

- *(kube)* support long lived service account tokens  ([#27](https://github.com/vakamo-labs/limes-rs/pull/27))

### Other

- *(deps)* update typed-builder requirement from 0.20 to 0.21 ([#25](https://github.com/vakamo-labs/limes-rs/pull/25))
- *(deps)* update kube requirement from 0.98 to 0.99 ([#23](https://github.com/vakamo-labs/limes-rs/pull/23))

## [0.1.4](https://github.com/vakamo-labs/limes-rs/compare/v0.1.3...v0.1.4) - 2025-03-03

### Fixed

- fix double slash in wellknown config url ([#20](https://github.com/vakamo-labs/limes-rs/pull/20))

### Other

- *(tests)* Introspection test ([#19](https://github.com/vakamo-labs/limes-rs/pull/19))

## [0.1.3](https://github.com/vakamo-labs/limes-rs/compare/v0.1.2...v0.1.3) - 2025-02-25

### Fixed

- Token introspection should not validate audience (#18)

### Other

- Test Minimal Rust Version - Set to 1.81 (#16)

## [0.1.2](https://github.com/vakamo-labs/limes-rs/compare/v0.1.1...v0.1.2) - 2025-02-13

### Added

- Optionally accept multiple subject claims (#14)

### Fixed

- Expose `email` field of `Authentication` (#12)

## [0.1.1](https://github.com/vakamo-labs/limes-rs/compare/limes-v0.1.0...limes-v0.1.1) - 2025-02-08

### Added

- Initial commit (#1)

### Other

- Improve readme ([#4](https://github.com/vakamo-labs/limes-rs/pull/4))
- Release 0.1.0
- *(docs)* Badges in Readme
