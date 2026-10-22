set shell := ["bash", "-euo", "pipefail", "-c"]

check:
    cargo fmt --all -- --check
    cargo clippy --locked --workspace --all-targets -- -D warnings
    cargo nextest run --locked --workspace --profile ci

provider-check:
    python3 scripts/check-agent.py
