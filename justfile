set shell := ["bash", "-c"]
set export

RUST_LOG := "debug"

check-format:
	cargo fmt --all -- --check

check-clippy:
	cargo clippy --all-features --all-targets --workspace -- -D warnings
	cargo clippy --workspace -- -D warnings
	cargo clippy --workspace --no-default-features -- -D warnings
	cargo clippy --workspace --features "all aws-lc-rs" -- -D warnings
	cargo clippy -p limes --all-targets --no-default-features --features "all rust-crypto ring" -- -D warnings


check-cargo-sort:
	cargo sort -c -w

check: check-format check-clippy check-cargo-sort

fix-format:
    cargo clippy --all-targets --all-features --workspace --fix --allow-staged
    cargo fmt --all
    cargo sort -w

test: doc-test
	cargo test --all-targets --all-features --workspace
	cargo test --all-targets --workspace --no-default-features
	cargo test --all-targets --workspace --features "all aws-lc-rs"
	cargo test --all-targets -p limes --no-default-features --features "all rust-crypto ring"
	cargo test --all-targets -p limes --no-default-features --features "cache aws-lc-rs"

doc-test:
	cargo test --no-fail-fast --doc --all-features --workspace

doc: 
	RUSTFLAGS="--cfg docsrs" cargo +nightly-2025-01-25 doc --lib --no-deps --all-features --document-private-items