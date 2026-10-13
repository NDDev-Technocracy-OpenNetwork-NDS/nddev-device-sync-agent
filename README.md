# NDDev OpenNetwork · device agent

AGPL-3.0-only native integration for NDS. [NDDev OpenNetwork](https://nddev.ai).

`crates/agent` composes the six compiled-in native adapters: sysinfo, clipboard,
cleaner, updater, GDS and RDS. Each adapter owns its manifest and provider
contract. The Flutter client calls the library to read actual native state;
configuration, untested reachability and a completed observation are distinct.
Mobile consumers share portable view types; local native tools require a
supported desktop host.

`crates/io` provides separate bounded socket and process capabilities. An
agent shares eight admission slots across its modules, uses finite deadlines
and output limits, and cancels owned work when closed. Native providers retain
their state and policy. Private paths, arguments and response content never
enter telemetry. Module operations carry real OpenTelemetry contexts through
the caller-installed shared telemetry SDK; its local logs do not imply remote
export or delivery.

Run `just check`, `cargo nextest run --locked --workspace`, `cargo deny check`
and `cargo audit`. OS transport checks exercise real sockets and child
processes. Module repositories own isolated real-provider acceptance; the
agent's Linux acceptance verifies composition against the pinned sysinfo
provider. Dependencies use immutable Git revisions.

This library has no standalone background daemon, remote-command endpoint,
maintenance mutation, backup/recovery or private estate configuration.

`nds-agent --server <origin> vault list [after_ref]` returns bounded metadata and
secret references. `vault use <ref> github|cloudflare|digitalocean` consumes the
secret natively for the official provider identity check; raw provider output
and credentials are never returned. Sign in through NDS first. The CLI uses the
same native session/device/vault stores and reconciles the server replica before
use; conflicts, revocation and incomplete catch-up deny secret consumption.

The CLI reserves stdout for one JSON operation result; the shared bounded SDK
writes redacted diagnostics to stderr. It uses the same accounts sender for
signed events and actual native spans, reporting transport acknowledgements,
operator policy and undelivered/dropped records separately. Vault list cursors
come from the native paginated read model, including tombstones/conflicts.

Linux GDS uses the bundled Rust worker and the same frozen IO source as the
native module graph. Build packaging with `cargo run --locked -p
nddev-device-sync-agent --bin nds-package-gds-worker -- --bundle <staging-dir>`.
The receipt binds the locked GDS source to the actual worker digest. Set its
`NDS_GDS_WORKER_SHA256` for the host build and place the worker beside the host
executable. The agent verifies that fixed sibling with bounded streaming reads
before each query; runtime environment, PATH and presentation input cannot
select its executable or expected hash. Verification assumes the existing
trusted installation boundary; hashing followed by execution through a path
does not provide race-free attestation. macOS/Windows GDS remains unsupported.

The Agent library has its own version; the CLI/input transport remains in its
separate binary graph. Building without a packaged worker digest leaves GDS
unconfigured instead of starting an external status provider.

Provider acceptance never extracts a working CLI account token into fixtures.
The default real GitHub check uses a generated invalid value and verifies denial
without secret/output leakage. A successful provider check requires an explicitly
supplied isolated test account credential via `NDS_TEST_ISOLATED_GITHUB_TOKEN_FILE`.
