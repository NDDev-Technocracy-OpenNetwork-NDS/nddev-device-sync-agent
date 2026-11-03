//! Native acceptance of the local-use bridge against an owned PG/SMTP fixture (agent#161).
//! The real binary keeps the captured authority; this test is the caller in other processes.
#![cfg(target_os = "linux")]
use nddev_device_sync_accounts::{IdentityClient, SyncRequest};
use nddev_device_sync_domain::devices::ControlMode;
use nddev_device_sync_vault::VaultClient;
use serde_json::Value;
use std::{process::Stdio, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

fn cli_binary() -> std::path::PathBuf {
    let binary = std::env::var_os("NDS_TEST_CLI_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_nds-agent").into());
    assert!(binary.is_absolute() && binary.is_file());
    binary
}

async fn sign_in(data: &Value) -> Arc<IdentityClient> {
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
    let messages = || async {
        let value: Value = http
            .get(format!("{mailbox}/api/v1/messages"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        value
    };
    let before = messages().await["messages"].as_array().unwrap().len();
    identity
        .request_email(data["owner_email"].as_str().unwrap().into(), "en")
        .await
        .unwrap();
    let code = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let list = messages().await;
            let list = list["messages"].as_array().unwrap();
            if list.len() > before
                && let Some(id) = list.first().and_then(|message| message["ID"].as_str())
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
        .prepare_device("Owned local-use acceptance".into())
        .await
        .unwrap();
    identity
}

struct Bridge {
    child: tokio::process::Child,
    stdin: Option<tokio::process::ChildStdin>,
    frames: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
}

impl Bridge {
    fn start(endpoint: &str, root: &std::path::Path) -> Self {
        let mut child = tokio::process::Command::new(cli_binary())
            .args(["--server", endpoint, "local-use", "disk-controller"])
            .env("XDG_STATE_HOME", root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let frames = BufReader::new(child.stdout.take().unwrap()).lines();
        Self {
            child,
            stdin,
            frames,
        }
    }

    async fn frame(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(30), self.frames.next_line())
            .await
            .expect("bridge frame deadline")
            .unwrap()
            .expect("bridge stdout closed");
        serde_json::from_str(&line).unwrap()
    }

    async fn validate(&mut self) -> Value {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(b"validate\n").await.unwrap();
        stdin.flush().await.unwrap();
        self.frame().await
    }
}

#[tokio::test]
#[ignore = "requires an owned --fixture-sync3 fixture (PG/SMTP) with an admitted owner vault"]
async fn the_bridge_keeps_the_original_authority_until_it_changes() {
    let receipt = std::env::var("NDS_FIXTURE_RECEIPT").unwrap();
    let data: Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    let endpoint = data["base_url"].as_str().unwrap().to_owned();
    let identity = sign_in(&data).await;
    assert_eq!(
        identity
            .sync_request(SyncRequest::CapabilitiesV3)
            .await
            .unwrap()
            .status,
        200
    );
    // The fixture operator admits current writes for this fresh, empty owner.
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
    let root = std::path::PathBuf::from(std::env::var_os("XDG_STATE_HOME").unwrap());
    assert!(
        root.is_absolute() && root.starts_with(std::path::Path::new(&receipt).parent().unwrap())
    );
    let vault = VaultClient::new(identity.clone(), root.join("nddev-device-sync"))
        .await
        .unwrap();
    let initial = vault.synchronize().await.unwrap();
    assert!(!initial.catching_up && initial.sync_error.is_empty());
    let view = identity.refresh().await.unwrap();
    let fence = identity.local_use_fence().await.unwrap();
    let policy = identity.device_policy(&fence).await.unwrap();
    assert_eq!(
        policy.mode(),
        ControlMode::Fullauto,
        "an enrolled device starts fullauto"
    );

    // ready → valid under fullauto without any module checklist.
    let mut bridge = Bridge::start(&endpoint, &root);
    let ready = bridge.frame().await;
    assert_eq!(ready["frame"], "ready", "{ready}");
    assert_eq!(ready["user_id"], view.user_id.as_str());
    assert_eq!(ready["device_id"], view.current_device_id.as_str());
    assert_eq!(ready["policy_revision"], policy.revision().to_string());
    let operation = ready["operation_id"].as_str().unwrap().to_owned();
    let valid = bridge.validate().await;
    assert_eq!(valid["frame"], "valid", "{valid}");

    // A termination signal cancels an operation whose caller still holds stdin open;
    // the child must not wait for the uncancellable blocking stdin read.
    let mut signalled = Bridge::start(&endpoint, &root);
    assert_eq!(signalled.frame().await["frame"], "ready");
    let pid = signalled.child.id().unwrap().to_string();
    assert!(
        std::process::Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    let last = signalled.frame().await;
    assert_eq!(last["ended"], "cancelled", "{last}");
    let status = tokio::time::timeout(Duration::from_secs(10), signalled.child.wait())
        .await
        .expect("a signalled bridge must exit while its stdin stays open")
        .unwrap();
    assert!(status.success());
    drop(signalled);

    // Narrowing this device to manual in another process disables the tool.
    identity
        .replace_device_policy(
            &fence,
            policy.revision(),
            ControlMode::Manual,
            policy.purposes().clone(),
        )
        .await
        .unwrap();
    let refused = bridge.validate().await;
    assert_eq!(
        (refused["frame"].as_str(), refused["error"].as_str()),
        (Some("refused"), Some("module_disabled"))
    );

    // A sign-out in another process ends the captured authority; nothing is valid afterwards.
    identity.logout().await.unwrap();
    for _ in 0..2 {
        let refused = bridge.validate().await;
        assert_eq!(refused["frame"], "refused");
        assert_eq!(refused["error"], "revalidation_required");
        assert_eq!(refused["operation_id"], operation.as_str());
    }

    // EOF cancels the operation; the final report names it and carries no private data.
    drop(bridge.stdin.take());
    let last = bridge.frame().await;
    assert_eq!(
        (last["operation"].as_str(), last["ended"].as_str()),
        (Some("local_use"), Some("cancelled"))
    );
    assert_eq!(last["validated"], 1);
    let status = tokio::time::timeout(Duration::from_secs(30), bridge.child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
    let mut logs = Vec::new();
    bridge
        .child
        .stderr
        .take()
        .unwrap()
        .take(32 * 1024 * 1024)
        .read_to_end(&mut logs)
        .await
        .unwrap();
    let logs = String::from_utf8_lossy(&logs);
    let email = data["owner_email"].as_str().unwrap();
    assert!(!logs.contains(email) && !logs.contains(root.to_str().unwrap()));
    // The same ADR 0018 records Shared emits, correlated by this operation and device.
    for name in [
        "module.admission.fullauto",
        "module.admission.manual",
        "module.action.failed",
    ] {
        assert!(logs.contains(name), "{name} was not emitted");
    }
    assert!(logs.contains(&operation) && logs.contains(view.current_device_id.as_str()));
    if let Ok(path) = std::env::var("NDS_TEST_CLI_EVIDENCE_FILE") {
        let path = std::path::PathBuf::from(path).with_extension("local-use.jsonl");
        assert!(path.is_absolute() && !path.starts_with(env!("CARGO_MANIFEST_DIR")));
        std::fs::write(path, logs.as_bytes()).unwrap();
    }
}
