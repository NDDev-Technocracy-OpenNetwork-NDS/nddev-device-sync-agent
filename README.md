# NDDev OpenNetwork · device agent

AGPL-3.0-only native integration for NDS. [NDDev OpenNetwork](https://nddev.ai).

`crates/agent` composes eight compiled-in native module clients: sysinfo,
clipboard, cleaner, updater, github, remote, browser-use and cache. Each module owns
its manifest and functional contract; I/O adapters remain internal boundaries. The Flutter client calls the library to read actual native state;
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

The selected Accounts client requires a compatible NDS server exposing the
original personal device context. An older server reports
`personal_context_unavailable`; it never substitutes another scope or a legacy
inventory result.

`github source` reads the encrypted account-wide GitHub choice.
`github source select <ref> <revision> [pending_id]` saves a record version from
`vault list`; `github source clear` removes the choice. Writes return their
durable local queue receipt. Other replicas receive the choice through ordinary
NDS synchronization; selecting it grants neither device permissions nor GitHub
access. Conflicted settings remain blocked.

`github repositories` lists bounded saved metadata without polling GitHub.
`github write enable` explicitly enables this device's GitHub module and its required
read/credential/network and `git_write` permissions; `github write disable`
withdraws only Git write consent and preserves existing files/settings.
`github connect <repository_id> <owner_id> <owner> <repository>` uses that grant
to connect the canonical `Developer/nddev/<owner>/<repository>` checkout on
Linux/macOS. IDs and locator are confirmed against GitHub before local work and
at publication. Existing dirty work and origins remain intact; occupied paths
and mismatched identities are reported as blocked. A connection result is not
proof of subsequent commit synchronization. This command installs no daemon and
does not activate periodic Git writes; registered intent uses ordinary NDS sync.

`sync run` keeps the existing Rust replica owner alive until Ctrl-C or a native
termination signal. It resumes queued NDS synchronization and the permitted GitHub module
catalog without a GUI. Another process observing the same local account follows
the elected owner and takes over after it exits. It installs no service; ordinary
point-of-use CLI commands remain bounded and do not start catalog polling. GitHub module
provider failures are observed separately from Vault replication. No Git clone,
commit creation or automatic Git mutation is activated by this command.

`local-use <tool>` is the bridge through which a local system tool acts as this
signed-in device (agent#161, ADR 0018). The tool spawns one child per operation:
`nds-agent --server <origin> local-use disk-controller`. The child captures the
device's local-use fence, which never leaves it, and checks the tool's admission:
fullauto admits an installed tool, manual requires its explicit enablement in this
device's module settings. It then writes one JSON frame per stdout line. `ready`
carries only `operation_id`, `module`, `user_id`, `device_id`, `space_id` and
`policy_revision`. Each `validate` line on stdin rechecks the original fence, the
current device policy and the admission, and answers `valid` or `refused` with a
fixed class (`revalidation_required`, `module_disabled`, `sign_in_required`, ...).
`close` ends the operation; EOF, a broken pipe or a termination signal cancel it,
and the last line is the operation result. The tool holds its own publication lock
from a `valid` frame through its commit and publishes nothing after any other
reply or EOF; a frame observes that moment and grants nothing beyond the process.
The child needs an enrolled device session and an unlocked Vault on the host; it
adds no daemon, listener or token. It emits the ADR 0018 records Shared emits:
`module.admission.fullauto|manual` (`accepted`/`denied` with a fixed class) for each
check and `module.action.completed|failed` when the operation's authority ends, with
device, principal and operation id, never configuration, paths or arguments.
Native acceptance (`cargo test -p nds-agent --test local_use -- --ignored`) runs
against an owned PG/SMTP fixture.

`diagnostics <command>` gives the signed-in device P2 diagnostic access (protocol
`6e82339`). Each command runs in a verified online session.
- `diagnostics policy` prints this device's one effective collection policy:
  `standard`, `debug` with its end, or `off`.
- `diagnostics search '<DiagnosticSearchRequest JSON>'` runs one scoped search and
  prints a page of fixed, redacted records. Scopes:
  - `member`: your own records;
  - `organization` with `organization_id`: you must be an active administrator;
  - `global`: needs a current grant.
- `diagnostics grant <private-key>` opens global scope for this session and device
  for fifteen minutes. It fetches a one-time challenge, has `ssh-keygen -Y sign -n
  nds-global-admin@nddev.ai -f <key>` sign exactly its bytes, and returns the
  grant's expiry and key fingerprint. The private key stays with `ssh-keygen`; the
  grant is not a token and never leaves the server.

Refusals keep their class: `forbidden_scope`, `global_grant_required`,
`diagnostics_unsupported_by_server`. Every result's `diagnostics` field also reports
the delivery's `collection` mode and `debug_until`.

The CLI reserves stdout for one JSON operation result; the shared bounded SDK
writes redacted diagnostics to stderr. It uses the same accounts sender for
signed events and actual native spans, reporting transport acknowledgements,
operator policy and undelivered/dropped records separately. Vault list cursors
come from the native paginated read model, including tombstones/conflicts.

Provider acceptance never extracts a working CLI account token into fixtures.
The default real GitHub check uses a generated invalid value and verifies denial
without secret/output leakage. A successful provider check requires an explicitly
supplied isolated test account credential via `NDS_TEST_ISOLATED_GITHUB_TOKEN_FILE`.
With a shared mutable Cargo cache, native acceptance can use
`NDS_TEST_CLI_BINARY` to select an absolute frozen CLI artifact whose source
and digest were verified before the run.

The Linux GitHub module uses the bundled Rust worker from its locked dependency and the
native module graph's IO341 process owner. Build it with
`cargo run --locked -p nddev-device-sync-agent --bin nds-package-github-worker --
--bundle <absolute-staging-directory>`. Use the receipt's actual
`NDS_GITHUB_WORKER_SHA256` for the host build and deliver the fixed worker beside
the host. Downstream Flutter packaging must also track that digest in hook
user_defines so warm caches cannot retain another worker identity.

The agent admits only that fixed sibling with bounded streaming hash checks.
Runtime PATH/environment and presentation input cannot choose its executable
or expected hash. Verification uses the existing trusted installation boundary;
hash followed by execution through a path is not race-free attestation.
Unpackaged Linux builds leave the GitHub module unconfigured. On macOS/Windows it refuses
execution until its native resource boundary is qualified; other module support
is unchanged. Provider acceptance runs only owned temporary copies and daemons.

Release journals live in [GitHub Releases](https://github.com/NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-agent/releases).
