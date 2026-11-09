set shell := ["bash", "-euo", "pipefail", "-c"]

check:
    cargo fmt --all -- --check
    cargo deny --locked check licenses sources
    cargo shear --locked --deny-warnings

# Execution host or runner only. Keep compilation and real process tests together.
test:
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo nextest run --locked --workspace --profile ci
    cargo test --locked --workspace --doc

provider-check:
    python3 scripts/check-agent.py
