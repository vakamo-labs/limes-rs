# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
