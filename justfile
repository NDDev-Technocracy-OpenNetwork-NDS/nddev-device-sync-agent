set shell := ["bash", "-euo", "pipefail", "-c"]

setup:
    cargo fetch --locked
    cargo fetch --locked --manifest-path tools/ci/Cargo.toml

tools-source:
    cargo fmt --manifest-path tools/ci/Cargo.toml --all -- --check
    cd tools/ci && cargo-deny --frozen check licenses sources
    cd tools/ci && cargo shear --locked --deny-warnings

check: tools-source
    cargo fmt --all -- --check
    cargo deny --frozen check licenses sources
    cargo shear --locked --deny-warnings

# Execution host or runner only. Keep compilation and real process tests together.
tools-test:
    cargo clippy --locked --manifest-path tools/ci/Cargo.toml --all-targets --jobs 4 -- -D warnings
    cargo nextest run --locked --manifest-path tools/ci/Cargo.toml --jobs 4

test: tools-test
    cargo clippy --locked --workspace --all-targets --jobs 4 -- -D warnings
    cargo nextest run --locked --workspace --jobs 4 --profile ci
    cargo test --locked --workspace --doc --jobs 4

build:
    cargo build --locked --workspace --release --jobs 4
    cargo build --locked --manifest-path tools/ci/Cargo.toml --release --jobs 4
    cargo audit --deny warnings
    cd tools/ci && cargo deny check advisories

verify: check test build

provider-prepare directory:
    command -v curl
    curl --version
    cargo metadata --locked --format-version 1 > {{ quote(directory + ".metadata.json") }}
    cargo run --locked --manifest-path tools/ci/Cargo.toml -- fetch-selected {{ quote(directory + ".metadata.json") }} sysinfo {{ quote(directory + "/sysinfo") }}

provider-check:
    python3 scripts/check-agent.py
