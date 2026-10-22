//! Real native vault and official GitHub rejection; no provider-success stub.
//! A positive check requires an explicitly supplied isolated test credential.
#![cfg(target_os = "linux")]
use nddev_device_sync_accounts::{IdentityClient, SyncRequest};
use nddev_device_sync_adapter_io::ProcessRequest;
use nddev_device_sync_vault::VaultClient;
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;
fn cli_binary() -> std::path::PathBuf {
    let binary = std::env::var_os("NDS_TEST_CLI_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_nds-agent").into());
    assert!(binary.is_absolute() && binary.is_file());
    binary
}
async fn actual_cli(
    endpoint: &str,
    arguments: &[&str],
    directory: &std::path::Path,
    secret: &str,
    evidence: &str,
) -> (bool, Value) {
    let mut child = tokio::process::Command::new(cli_binary())
        .args(["--server", endpoint])
        .args(arguments)
        .env("XDG_STATE_HOME", directory)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut out = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        bytes
    });
    let mut err = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr
            .take(32 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .unwrap();
        bytes
    });
    let status = tokio::time::timeout(Duration::from_secs(60), child.wait()).await;
    if status.is_err() {
        child.start_kill().unwrap();
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap();
    }
    let stdout = tokio::time::timeout(Duration::from_secs(5), &mut out).await;
    let stderr = tokio::time::timeout(Duration::from_secs(5), &mut err).await;
    if stdout.is_err() {
        out.abort();
    }
    if stderr.is_err() {
        err.abort();
    }
    let stdout = stdout
        .expect("CLI stdout remained open after process exit")
        .unwrap();
    let logs = stderr
        .expect("CLI stderr remained open after process exit")
        .unwrap();
    assert!(stdout.len() <= 1024 * 1024);
    assert!(logs.len() <= 32 * 1024 * 1024);
    assert!(
        !logs
            .windows(secret.len())
            .any(|value| value == secret.as_bytes())
    );
    if let Ok(path) = std::env::var("NDS_TEST_CLI_EVIDENCE_FILE") {
        let path = std::path::PathBuf::from(path).with_extension(format!("{evidence}.jsonl"));
        assert!(path.is_absolute() && !path.starts_with(env!("CARGO_MANIFEST_DIR")));
        std::fs::write(path, &logs).unwrap();
    }
    let output = std::process::Output {
        status: status
            .expect("real CLI exceeded its deadline; owned diagnostics retained")
            .unwrap(),
        stdout,
        stderr: logs,
    };
    let page: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        !output
            .stdout
            .windows(secret.len())
            .any(|value| value == secret.as_bytes())
    );
    assert!(
        !output
            .stderr
            .windows(secret.len())
            .any(|value| value == secret.as_bytes())
    );
    (output.status.success(), page)
}

async fn background_handoff(
    endpoint: &str,
    root: &std::path::Path,
    secret: &str,
    vault: &VaultClient,
    identity: &Arc<IdentityClient>,
) {
    use nddev_device_sync_domain::modules::control::Configuration;
    use std::process::Stdio;
    let setting = vault.module_configuration("gds").await.unwrap();
    vault
        .set_module_configuration(
            "gds".into(),
            setting.revision,
            setting.pending_id,
            Configuration {
                enabled: true,
                permissions: nddev_device_sync_gds::catalog_runtime::required_permissions(),
            },
        )
        .await
        .unwrap();
    let view = vault.synchronize().await.unwrap();
    assert!(!view.catching_up && view.pending == 0 && view.sync_error.is_empty());
    let spawn = |label: &str| {
        let logs = root.join(format!("catalog-{label}.jsonl"));
        let child = tokio::process::Command::new(cli_binary())
            .args(["--server", endpoint, "sync", "run"])
            .env("XDG_STATE_HOME", root)
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(&logs).unwrap())
            .spawn()
            .unwrap();
        (child, logs)
    };
    async fn wait_for(path: &std::path::Path, event: &[u8], secret: &str) {
        tokio::time::timeout(Duration::from_secs(50), async {
            loop {
                let logs = std::fs::read(path).unwrap();
                assert!(logs.len() <= 32 * 1024 * 1024);
                assert!(
                    !logs
                        .windows(secret.len())
                        .any(|value| value == secret.as_bytes())
                );
                let observed = if event == b"gds.catalog.read.failed" {
                    let rows = logs
                        .split(|byte| *byte == b'\n')
                        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
                        .collect::<Vec<_>>();
                    rows.iter()
                        .filter(|row| row["event.name"] == "gds.catalog.read.failed")
                        .any(|http| {
                            rows.iter().any(|page| {
                                page["event.name"] == "gds.catalog.page.read"
                                    && page["error.type"] == "dependency_unavailable"
                                    && http["trace_id"].is_string()
                                    && page["trace_id"] == http["trace_id"]
                                    && page["producer.sequence"].as_u64()
                                        > http["producer.sequence"].as_u64()
                            })
                        })
                } else {
                    logs.windows(event.len()).any(|value| value == event)
                };
                if observed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("real elected catalog owner did not produce its provider refusal");
    }
    async fn stop(child: tokio::process::Child, signal: &str) -> Value {
        let pid = child.id().unwrap();
        assert!(
            tokio::process::Command::new("/bin/kill")
                .args([signal, &pid.to_string()])
                .status()
                .await
                .unwrap()
                .success()
        );
        let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "owned background CLI did not shut down gracefully"
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["stopped"], true);
        value
    }
    let (owner, owner_log) = spawn("owner");
    wait_for(&owner_log, b"gds.catalog.read.failed", secret).await;
    let (follower, follower_log) = spawn("follower");
    wait_for(&follower_log, b"agent.sync.started", secret).await;
    // Let the follower execute at least one actual lease/replication batch.
    wait_for(&follower_log, b"sync.replica.batch", secret).await;
    assert!(
        !std::fs::read(&follower_log)
            .unwrap()
            .windows(b"gds.catalog.read.failed".len())
            .any(|v| v == b"gds.catalog.read.failed")
    );
    let stopped = stop(owner, "-TERM").await;
    assert!(stopped["gds"]["error"].is_string());
    // A separate process can now become owner, without logging out or changing keys.
    wait_for(&follower_log, b"gds.catalog.read.failed", secret).await;
    let stopped = stop(follower, "-INT").await;
    assert!(stopped["gds"]["error"].is_string());
    // A retained resource cannot acquire a fresh local-use generation after its
    // native owner has been permanently stopped. The caller itself stays valid.
    let native = nddev_device_sync_vault::replication::native::NativeReplica::attach(
        identity,
        root.join("nddev-device-sync"),
        Some(env!("CARGO_PKG_VERSION").into()),
    )
    .await
    .unwrap();
    let catalog = native
        .catalog(nddev_device_sync_gds::catalog_runtime::CatalogRuntime::new)
        .unwrap();
    let foreground = catalog.foreground(identity.clone());
    let refusal = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match foreground.github_repository_page(false).await {
                Err(nddev_device_sync_gds::catalog_runtime::view::GithubCatalogError::Busy) => {
                    tokio::time::sleep(Duration::from_millis(100)).await
                }
                value => break value,
            }
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        refusal,
        Err(nddev_device_sync_gds::catalog_runtime::view::GithubCatalogError::Unavailable)
    ));
    assert!(catalog.observation().await.unwrap().error.is_some());
    let setting = vault.module_configuration("gds").await.unwrap();
    vault
        .set_module_configuration(
            "gds".into(),
            setting.revision,
            setting.pending_id,
            Configuration {
                enabled: false,
                permissions: setting.configuration.permissions,
            },
        )
        .await
        .unwrap();
    assert!(
        catalog.observation().await.is_none(),
        "new consent must not inherit the previous probe"
    );
    native.stop().await.unwrap();
    let settled = vault.synchronize().await.unwrap();
    assert!(!settled.catching_up && settled.pending == 0 && settled.sync_error.is_empty());
    assert!(matches!(
        foreground.saved_github_repository_page(false).await,
        Err(
            nddev_device_sync_gds::catalog_runtime::view::GithubCatalogError::AuthorizationRequired
        )
    ));
    let replacement = catalog.foreground(identity.clone());
    assert!(matches!(
        replacement.github_repository_page(false).await,
        Err(
            nddev_device_sync_gds::catalog_runtime::view::GithubCatalogError::AuthorizationRequired
        )
    ));
    let raced = nddev_device_sync_vault::replication::native::NativeReplica::attach(
        identity,
        root.join("nddev-device-sync"),
        Some(env!("CARGO_PKG_VERSION").into()),
    )
    .await
    .unwrap();
    assert!(matches!(
        raced.catalog(|owner, vault| {
            owner.cancel();
            nddev_device_sync_gds::catalog_runtime::CatalogRuntime::new(owner, vault)
        }),
        Err(nddev_device_sync_vault::Error::Locked)
    ));
    raced.stop().await.unwrap();
    nddev_device_sync_vault::replication::native::NativeReplica::shutdown()
        .await
        .unwrap();
    identity.authorize_local().await.unwrap();
    let current = vault.refresh_local().await.unwrap();
    assert!(current.pending == 0 && current.sync_error.is_empty());
    for log in [owner_log, follower_log] {
        let logs = std::fs::read(&log).unwrap();
        assert!(
            !logs
                .windows(secret.len())
                .any(|value| value == secret.as_bytes())
        );
        if let Ok(prefix) = std::env::var("NDS_TEST_CLI_EVIDENCE_FILE") {
            let evidence =
                std::path::PathBuf::from(prefix).with_extension(log.file_name().unwrap());
            std::fs::write(evidence, logs).unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires an owned --fixture-sync3 fixture and official GitHub CLI; optional isolated test credential"]
async fn actual_native_vault_reference_drives_official_github_cli() {
    let receipt = std::env::var("NDS_FIXTURE_RECEIPT").unwrap();
    let data: Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    let endpoint = data["base_url"].as_str().unwrap();
    assert!(endpoint.starts_with("http://localhost:") || endpoint.starts_with("http://127.0.0.1:"));
    let identity = Arc::new(IdentityClient::new(endpoint).unwrap());
    identity.refresh().await.unwrap();
    let mailbox = data["mailpit_url"].as_str().unwrap();
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let before: Value = http
        .get(format!("{mailbox}/api/v1/messages"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let before = before["messages"].as_array().unwrap().len();
    identity
        .request_email(data["owner_email"].as_str().unwrap().into(), "en")
        .await
        .unwrap();
    let mailbox = data["mailpit_url"].as_str().unwrap();
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let code = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let messages: Value = http
                .get(format!("{mailbox}/api/v1/messages"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if messages["messages"].as_array().unwrap().len() <= before {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            if let Some(id) = messages["messages"]
                .as_array()
                .unwrap()
                .first()
                .and_then(|message| message["ID"].as_str())
            {
                let mail: Value = http
                    .get(format!("{mailbox}/api/v1/message/{id}"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                if let Some((_, suffix)) = mail["Text"].as_str().unwrap().split_once("code: ") {
                    break suffix.chars().take(8).collect::<String>();
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    identity.verify_email(code).await.unwrap();
    identity
        .prepare_device("Owned native agent acceptance".into())
        .await
        .unwrap();
    // Create the empty server counter without negotiating a local writer.
    // The fixture operator must finish admission before this test stages data.
    assert_eq!(
        identity
            .sync_request(SyncRequest::CapabilitiesV3)
            .await
            .unwrap()
            .status,
        200
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(bytes) = std::fs::read(&receipt)
                && let Ok(state) = serde_json::from_slice::<Value>(&bytes)
                && state["new_operation_version"] == 3
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("owned fixture did not finish empty-owner admission");
    let capabilities = identity
        .sync_request(SyncRequest::CapabilitiesV3)
        .await
        .unwrap();
    assert_eq!(capabilities.status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&capabilities.body).unwrap()["new_operation_version"],
        3
    );
    // The native cache slots and their durable fence must use one installation
    // state home in every process, exactly as GUI and CLI do in production.
    let root = std::path::PathBuf::from(std::env::var_os("XDG_STATE_HOME").unwrap());
    assert!(
        root.is_absolute() && root.starts_with(std::path::Path::new(&receipt).parent().unwrap())
    );
    let vault = VaultClient::new(identity.clone(), root.as_path().join("nddev-device-sync"))
        .await
        .unwrap();
    let initial = vault.synchronize().await.unwrap();
    assert!(!initial.catching_up && initial.sync_error.is_empty() && initial.pending == 0);
    let positive = std::env::var_os("NDS_TEST_ISOLATED_GITHUB_TOKEN_FILE");
    let secret = Zeroizing::new(if let Some(path) = &positive {
        let path = std::path::PathBuf::from(path);
        assert!(path.is_absolute());
        let file = std::fs::File::open(path).unwrap();
        use std::io::Read;
        let mut value = String::new();
        file.take(16_385).read_to_string(&mut value).unwrap();
        assert!(value.len() <= 16_384);
        value.trim_end().to_owned()
    } else {
        format!("nds-invalid-acceptance-{}", std::process::id())
    });
    assert!(!secret.is_empty());
    vault
        .save_record(
            None,
            0,
            None,
            "Owned native credential consumer".into(),
            String::new(),
            secret.clone(),
        )
        .await
        .unwrap();
    // Inspect only this fixture's durable encrypted replica, including WAL.
    let files = std::fs::read_dir(root.as_path().join("nddev-device-sync/sync")).unwrap();
    let mut persisted = 0;
    for entry in files {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(path).unwrap();
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|value| value == secret.as_bytes())
            );
            persisted += bytes.len();
        }
    }
    assert!(persisted > 0);
    let committed = vault.synchronize().await.unwrap();
    assert!(!committed.catching_up && committed.sync_error.is_empty() && committed.pending == 0);
    let reference = vault
        .records(String::new())
        .await
        .unwrap()
        .items
        .into_iter()
        .find(|record| record.title == "Owned native credential consumer" && !record.conflicted)
        .unwrap()
        .id;
    let mut lists = Vec::new();
    for index in 0..2 {
        let (success, page) = actual_cli(
            endpoint,
            &["vault", "list"],
            root.as_path(),
            &secret,
            &format!("list-{index}"),
        )
        .await;
        assert!(success);
        assert_eq!(page["operation"], "vault.list");
        lists.push(page["records"].clone());
    }
    assert_eq!(
        lists[0], lists[1],
        "read-only replay must preserve committed record metadata"
    );
    assert!(
        lists[0]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["ref"] == reference)
    );
    // Each command is a fresh real process, sharing only this fixture's native
    // credentials and encrypted SQLite replica. No provider grant is inferred.
    let (success, absent) = actual_cli(
        endpoint,
        &["github", "source"],
        root.as_path(),
        &secret,
        "source-absent",
    )
    .await;
    assert!(success && absent["record_ref"].is_null());
    let record = lists[0]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["ref"] == reference)
        .unwrap();
    let revision = record["revision"].as_u64().unwrap().to_string();
    let (success, selected) = actual_cli(
        endpoint,
        &["github", "source", "select", &reference, &revision],
        root.as_path(),
        &secret,
        "source-select",
    )
    .await;
    assert!(success && selected["queued"] == true && selected["operation_id"].is_string());
    let (success, restored) = actual_cli(
        endpoint,
        &["github", "source"],
        root.as_path(),
        &secret,
        "source-restored",
    )
    .await;
    assert!(success);
    assert_eq!(restored["record_ref"], reference);
    assert_eq!(restored["record_revision"], revision);
    assert_eq!(restored["revision"], "1");
    assert!(restored["pending_id"].is_null() && restored["conflicted"] == false);
    let (success, refused) = actual_cli(
        endpoint,
        &["github", "source", "select", "absent-credential", "0"],
        root.as_path(),
        &secret,
        "source-refused",
    )
    .await;
    assert!(!success);
    assert_eq!(refused["error"], "vault_selection_changed");
    if positive.is_none() {
        background_handoff(endpoint, root.as_path(), &secret, &vault, &identity).await;
        let (success, grant) = actual_cli(
            endpoint,
            &["github", "write", "enable"],
            root.as_path(),
            &secret,
            "workspace-grant",
        )
        .await;
        assert!(success && grant["queued"] == true);
        assert!(
            grant["permissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "git_write")
        );
        let (success, cached) = actual_cli(
            endpoint,
            &["github", "repositories"],
            root.as_path(),
            &secret,
            "workspace-catalog",
        )
        .await;
        assert!(success && cached["cached"] == true);
        let (success, denied) = actual_cli(
            endpoint,
            &[
                "github",
                "connect",
                "19",
                "7",
                "generated-company",
                "generated-repository",
            ],
            root.as_path(),
            &secret,
            "workspace-provider-denied",
        )
        .await;
        assert!(!success);
        assert_eq!(denied["error"], "gds_unavailable");
        let (success, withdrawn) = actual_cli(
            endpoint,
            &["github", "write", "disable"],
            root.as_path(),
            &secret,
            "workspace-withdraw",
        )
        .await;
        assert!(success && withdrawn["enabled"] == false);
        assert!(
            !withdrawn["permissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "git_write")
        );
        let (success, denied) = actual_cli(
            endpoint,
            &[
                "github",
                "connect",
                "19",
                "7",
                "generated-company",
                "generated-repository",
            ],
            root.as_path(),
            &secret,
            "workspace-consent-denied",
        )
        .await;
        assert!(!success);
        assert_eq!(denied["error"], "module_permission_required");
    }
    let (success, cleared) = actual_cli(
        endpoint,
        &["github", "source", "clear"],
        root.as_path(),
        &secret,
        "source-clear",
    )
    .await;
    assert!(success && cleared["queued"] == true);
    let (success, empty) = actual_cli(
        endpoint,
        &["github", "source"],
        root.as_path(),
        &secret,
        "source-cleared-reopen",
    )
    .await;
    assert!(success && empty["record_ref"].is_null());
    assert_eq!(empty["revision"], "2");
    let credentials = identity.vault_credentials().unwrap();
    let command = ProcessRequest {
        executable: cli_binary(),
        arguments: ["--server", endpoint, "vault", "use", &reference, "github"]
            .into_iter()
            .map(Into::into)
            .collect(),
        directory: None,
        timeout: Duration::from_secs(60),
        max_output_bytes: 65_536,
    };
    // NativeIo preserves this test-owned XDG_STATE_HOME; spawning directly lets
    // the acceptance supply a private sandbox without changing global env.
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(command.executable)
            .args(command.arguments)
            .env("XDG_STATE_HOME", root.as_path())
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    let result: Value = serde_json::from_slice(&output.stdout)
        .expect("CLI stdout must contain exactly one JSON result");
    if let Ok(policy) = std::env::var("NDS_TEST_EXPECT_EXPORT_MODE") {
        assert!(matches!(
            policy.as_str(),
            "enabled" | "disabled" | "unknown"
        ));
        assert_eq!(result["diagnostics"]["export"], policy);
        if policy == "disabled" {
            assert_eq!(result["diagnostics"]["acknowledged_events"], 0);
            assert_eq!(result["diagnostics"]["acknowledged_spans"], 0);
            assert_eq!(result["diagnostics"]["undelivered"], 0);
            assert!(result["diagnostics"]["dropped"].as_u64().unwrap() > 0);
        }
    }
    assert_eq!(output.status.success(), positive.is_some());
    if positive.is_some() {
        assert_eq!(result["verified"], true);
    } else {
        assert_eq!(result["error"], "provider_credential_rejected");
    }
    assert!(
        !output
            .stdout
            .windows(secret.len())
            .any(|value| value == secret.as_bytes())
    );
    assert!(
        !output
            .stderr
            .windows(secret.len())
            .any(|value| value == secret.as_bytes())
    );
    if let Ok(path) = std::env::var("NDS_TEST_CLI_EVIDENCE_FILE") {
        let path = std::path::PathBuf::from(path);
        assert!(path.is_absolute() && !path.starts_with(env!("CARGO_MANIFEST_DIR")));
        let events: Vec<Value> = output
            .stderr
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        let operation = events
            .iter()
            .find(|event| {
                event["event.name"] == "agent.operation.failed"
                    || event["event.name"] == "agent.operation.completed"
            })
            .unwrap();
        let trace = operation["trace_id"].as_str().unwrap();
        let span = operation["span_id"].as_str().unwrap();
        assert!(trace.len() == 32 && span.len() == 16);
        std::fs::write(
            path,
            serde_json::to_vec(&serde_json::json!({
                "trace_id":trace,"span_id":span,"diagnostics":result["diagnostics"],
                "source_repository":operation["source.repository"],
                "source_commit":operation["source.commit"],
                "encrypted_storage_verified":true,"metadata_replay_verified":true,
                "secret_canary_absent":true,"official_provider_positive":positive.is_some(),
                "runtime_event_count":events.len()
            }))
            .unwrap(),
        )
        .unwrap();
    }
    credentials.delete().await.unwrap();
    identity.logout().await.unwrap();
}
