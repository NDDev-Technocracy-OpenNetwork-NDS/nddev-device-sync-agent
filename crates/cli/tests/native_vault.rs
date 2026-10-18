//! Real native vault and official GitHub rejection; no provider-success stub.
//! A positive check requires an explicitly supplied isolated test credential.
#![cfg(target_os = "linux")]
use nddev_device_sync_accounts::IdentityClient;
use nddev_device_sync_adapter_io::ProcessRequest;
use nddev_device_sync_vault::VaultClient;
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;
#[tokio::test]
#[ignore = "requires an owned fixture and official GitHub CLI; optional isolated test credential"]
async fn actual_native_vault_reference_drives_official_github_cli() {
    let data: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("NDS_FIXTURE_RECEIPT").unwrap()).unwrap(),
    )
    .unwrap();
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
    let root = tempfile::tempdir().unwrap();
    let vault = VaultClient::new(identity.clone(), root.path().join("nddev-device-sync"))
        .await
        .unwrap();
    vault.synchronize().await.unwrap();
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
    let files = std::fs::read_dir(root.path().join("nddev-device-sync/sync")).unwrap();
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
    vault.synchronize().await.unwrap();
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
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_nds-agent"))
            .args(["--server", endpoint, "vault", "list"])
            .env("XDG_STATE_HOME", root.path())
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
            let path = std::path::PathBuf::from(path).with_extension(format!("list-{index}.jsonl"));
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
        assert!(output.status.success());
        let page: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(page["operation"], "vault.list");
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
    let credentials = identity.vault_credentials().unwrap();
    let command = ProcessRequest {
        executable: std::path::PathBuf::from(env!("CARGO_BIN_EXE_nds-agent")),
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
            .env("XDG_STATE_HOME", root.path())
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
