//! `nds-agent --server <origin> local-use <tool>`: one child process per operation that keeps
//! the signed-in device's captured local-use authority for a system tool (agent#161, ADR 0018).
//!
//! The opaque `LocalUseFence` never leaves this process. The caller reads one JSON frame per
//! stdout line and writes `validate` or `close` lines to stdin:
//!
//! - `ready` carries only non-secret context: user, device, space, operation and policy revision;
//! - `validate` rechecks the original fence, the device control policy and the tool's admission
//!   and answers `valid` or `refused` with a fixed class;
//! - `close` ends the operation; EOF, a broken pipe or a termination signal cancel it.
//!
//! The caller holds its own publication lock from a `valid` reply through its commit and publishes
//! nothing after any other reply or EOF. A `ready` or `valid` frame is an observation at that
//! moment, not a grant that outlives this process.
use nddev_device_sync_accounts::{IdentityClient, LocalUseFence};
use nddev_device_sync_domain::{
    ModuleKind, Permission,
    devices::ControlMode,
    modules::control::{Configuration, Readiness},
};
use nddev_device_sync_vault::VaultClient;
use serde_json::{Value, json};
use std::{collections::BTreeSet, io::Write, sync::Arc};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

/// System tools admitted through this bridge. Each is a `Tool` under ADR 0018: fullauto admits it
/// once installed; manual requires its explicit enablement in this device's module settings.
pub const TOOLS: &[&str] = &["disk-controller"];
const MAX_LINE: usize = 64;

pub fn requested(arguments: &[String]) -> bool {
    matches!(arguments, [flag, _, scope, ..] if flag == "--server" && scope == "local-use")
}

/// The captured basis of one operation.
struct Basis {
    identity: Arc<IdentityClient>,
    vault: Arc<VaultClient>,
    fence: LocalUseFence,
    tool: &'static str,
}

fn client_class(error: nddev_device_sync_accounts::view::ClientError) -> &'static str {
    use nddev_device_sync_accounts::view::ClientError as E;
    match error {
        E::Transport | E::Timeout | E::Busy | E::CredentialStore => "identity_unavailable",
        E::Cancelled => "operation_cancelled",
        _ => "revalidation_required",
    }
}

fn vault_class(error: nddev_device_sync_vault::Error) -> &'static str {
    use nddev_device_sync_vault::Error as E;
    match error {
        E::Locked | E::Authentication | E::RegistrationRequired => "sign_in_required",
        E::Busy => "vault_busy",
        _ => "vault_unavailable",
    }
}

/// Admission of `tool` under the device's control `mode` (ADR 0018). The tool is supported and
/// installed by construction: its own process is the caller.
fn admit(configuration: &Configuration, mode: ControlMode) -> Result<(), &'static str> {
    let required = BTreeSet::<Permission>::new();
    configuration
        .admit_in(mode, ModuleKind::Tool, true, true, &required)
        .map_err(|readiness| match readiness {
            Readiness::Disabled => "module_disabled",
            Readiness::PermissionRequired => "module_permission_required",
            _ => "module_unavailable",
        })
}

impl Basis {
    /// Rechecks the original fence, the current device policy and the tool's admission.
    /// Returns the policy revision the answer was decided under.
    async fn check(&self) -> Result<u64, &'static str> {
        self.identity
            .validate_local_use(&self.fence)
            .await
            .map_err(client_class)?;
        let policy = self
            .identity
            .device_policy(&self.fence)
            .await
            .map_err(client_class)?;
        let setting = self
            .vault
            .module_configuration(self.tool)
            .await
            .map_err(vault_class)?;
        if setting.conflicted {
            return Err("module_configuration_conflict");
        }
        admit(&setting.configuration, policy.mode())?;
        // The answer must not outlive a sign-out or replacement during these reads.
        self.identity
            .validate_local_use(&self.fence)
            .await
            .map_err(client_class)?;
        Ok(policy.revision())
    }
}

fn frame(value: &Value) -> Result<(), &'static str> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{value}")
        .and_then(|()| out.flush())
        .map_err(|_| "caller_disconnected")
}

/// Reads one bounded line; `None` at EOF. Longer lines are a protocol error.
async fn next_line(
    reader: &mut (impl AsyncBufRead + Unpin),
) -> Result<Option<String>, &'static str> {
    let mut bytes = Vec::new();
    let read = (&mut *reader)
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(|_| "caller_disconnected")?;
    if read == 0 {
        return Ok(None);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    } else if bytes.len() > MAX_LINE {
        return Err("invalid_frame");
    }
    String::from_utf8(bytes)
        .map(|line| Some(line.trim_end_matches('\r').to_owned()))
        .map_err(|_| "invalid_frame")
}

pub async fn run(
    arguments: &[String],
    export_identity: &mut Option<Arc<IdentityClient>>,
    data_directory: impl FnOnce() -> Result<std::path::PathBuf, &'static str>,
) -> Result<Value, &'static str> {
    let [_, endpoint, _, tool] = arguments else {
        return Err("invalid_arguments");
    };
    if endpoint.len() > 2048 {
        return Err("invalid_arguments");
    }
    let tool = *TOOLS
        .iter()
        .find(|known| **known == tool.as_str())
        .ok_or("unsupported_operation")?;
    let identity = Arc::new(IdentityClient::new(endpoint).map_err(|_| "invalid_server")?);
    let view = identity
        .refresh()
        .await
        .map_err(|_| "identity_unavailable")?;
    if !view.authenticated || !(view.session_verified || view.offline_authorized) {
        return Err("sign_in_required");
    }
    *export_identity = Some(identity.clone());
    let fence = identity.local_use_fence().await.map_err(client_class)?;
    let vault = Arc::new(
        VaultClient::new(identity.clone(), data_directory()?)
            .await
            .map_err(vault_class)?,
    );
    let basis = Basis {
        identity,
        vault,
        fence,
        tool,
    };
    let operation_id = uuid::Uuid::new_v4().to_string();
    let admitted = basis.check().await;
    match &admitted {
        Ok(_) => {
            tracing::info!(event.name = "module.admission.admitted", module = tool, operation.id = %operation_id, outcome = "ok")
        }
        Err(class) => {
            tracing::warn!(event.name = "module.admission.refused", module = tool, operation.id = %operation_id, error.type = *class, outcome = "rejected")
        }
    }
    let revision = admitted?;
    frame(&json!({
        "frame": "ready",
        "operation_id": operation_id,
        "module": tool,
        "user_id": view.user_id,
        "device_id": view.current_device_id,
        "space_id": view.tenant_id,
        "policy_revision": revision.to_string(),
    }))?;
    let mut input = tokio::io::BufReader::new(tokio::io::stdin());
    let stop = super::stop_signal();
    tokio::pin!(stop);
    let mut validated = 0u64;
    let ended = loop {
        let line = tokio::select! {
            biased;
            _ = &mut stop => break "cancelled",
            line = next_line(&mut input) => line,
        };
        match line {
            Ok(None) => break "cancelled",
            Ok(Some(line)) if line == "close" => break "closed",
            Ok(Some(line)) if line == "validate" => {
                let checked = basis.check().await;
                let reply = match checked {
                    Ok(revision) => {
                        validated += 1;
                        tracing::info!(event.name = "module.action.validated", module = tool, operation.id = %operation_id, outcome = "ok");
                        json!({"frame": "valid", "operation_id": operation_id, "policy_revision": revision.to_string()})
                    }
                    Err(class) => {
                        tracing::warn!(event.name = "module.action.refused", module = tool, operation.id = %operation_id, error.type = class, outcome = "rejected");
                        json!({"frame": "refused", "operation_id": operation_id, "error": class})
                    }
                };
                frame(&reply)?;
            }
            Ok(Some(_)) | Err("invalid_frame") => {
                frame(
                    &json!({"frame": "refused", "operation_id": operation_id, "error": "invalid_frame"}),
                )?;
                break "invalid_frame";
            }
            Err(error) => return Err(error),
        }
    };
    tracing::info!(event.name = "module.action.ended", module = tool, operation.id = %operation_id, outcome = if ended == "closed" { "ok" } else { "stopped" });
    Ok(json!({
        "operation": "local_use",
        "operation_id": operation_id,
        "module": tool,
        "validated": validated,
        "ended": ended,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_bridge_form_is_requested() {
        let args = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        assert!(requested(&args(&[
            "--server",
            "https://x",
            "local-use",
            "disk-controller"
        ])));
        assert!(!requested(&args(&[
            "--server",
            "https://x",
            "vault",
            "list"
        ])));
        assert!(!requested(&args(&["local-use"])));
    }

    #[test]
    fn fullauto_admits_the_tool_and_manual_requires_enablement() {
        let disabled = Configuration::default();
        assert_eq!(admit(&disabled, ControlMode::Fullauto), Ok(()));
        assert_eq!(
            admit(&disabled, ControlMode::Manual),
            Err("module_disabled")
        );
        let enabled = Configuration {
            enabled: true,
            permissions: BTreeSet::new(),
        };
        assert_eq!(admit(&enabled, ControlMode::Manual), Ok(()));
    }

    #[tokio::test]
    async fn frames_are_bounded_lines() {
        let mut input: &[u8] = b"validate\nclose\r\n";
        assert_eq!(next_line(&mut input).await, Ok(Some("validate".into())));
        assert_eq!(next_line(&mut input).await, Ok(Some("close".into())));
        assert_eq!(next_line(&mut input).await, Ok(None));
        let long = vec![b'x'; MAX_LINE + 2];
        let mut input: &[u8] = &long;
        assert_eq!(next_line(&mut input).await, Err("invalid_frame"));
        let mut input: &[u8] = b"\xff\n";
        assert_eq!(next_line(&mut input).await, Err("invalid_frame"));
    }
}
