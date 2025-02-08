set shell := ["bash", "-c"]
set export

RUST_LOG := "debug"

check-format:
	cargo fmt --all -- --check

check-clippy:
	cargo clippy --all-features --workspace -- -D warnings
	cargo clippy --workspace -- -D warnings
	cargo clippy --workspace --no-default-features -- -D warnings
	cargo clippy --workspace --features "all" -- -D warnings


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
	cargo test --all-targets --workspace --features "all"

doc-test:
	cargo test --no-fail-fast --doc --all-features --workspace

doc: 
	RUSTFLAGS="--cfg docsrs" cargo +nightly-2025-01-25 doc --lib --no-deps --all-features --document-private-items