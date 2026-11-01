//! `nds-agent --server <origin> diagnostics <command>`: P2 diagnostic access for the signed-in
//! device.
//!
//! - `policy` prints this device's one effective collection policy (standard, finite debug, off).
//! - `search <request-json>` runs one scoped search (`DiagnosticSearchRequest`). The server
//!   decides the caller's rights from the signed request; the reply is a page of fixed,
//!   redacted records.
//! - `grant <private-key>` opens global scope for this session and device. It asks for a one-time
//!   challenge, signs exactly its bytes with `ssh-keygen -Y sign` in the
//!   `nds-global-admin@nddev.ai` namespace and returns the grant (expiry and key fingerprint).
//!   The private key stays with `ssh-keygen`; this process only sees the signature.
use nddev_device_sync_accounts::{IdentityClient, SyncRequest, view::ClientError};
use serde_json::{Value, json};
use std::{io::Write, process::Stdio, sync::Arc, time::Duration};

pub const NAMESPACE: &str = "nds-global-admin@nddev.ai";

pub fn requested(arguments: &[String]) -> bool {
    matches!(arguments, [flag, _, scope, ..] if flag == "--server" && scope == "diagnostics")
}

fn class(error: ClientError) -> &'static str {
    match error {
        ClientError::Server(code) => match code.as_str() {
            "forbidden_scope" => "forbidden_scope",
            "global_grant_required" => "global_grant_required",
            "invalid_request" => "invalid_arguments",
            "collection_policy_unavailable" => "diagnostics_unsupported_by_server",
            "authorization_denied" => "forbidden_scope",
            _ => "diagnostics_rejected",
        },
        ClientError::InvalidInput => "invalid_arguments",
        ClientError::DeviceRevoked => "device_revoked",
        ClientError::RevalidationRequired | ClientError::Expired => "revalidation_required",
        ClientError::OnlineVerificationRequired => "online_verification_required",
        _ => "diagnostics_unavailable",
    }
}

fn reply(body: &[u8]) -> Result<Value, &'static str> {
    serde_json::from_slice(body).map_err(|_| "diagnostics_invalid_response")
}

/// Signs `challenge` with `ssh-keygen -Y sign`; the challenge is the only input on stdin.
fn sign(key: &str, challenge: &str) -> Result<String, &'static str> {
    if !challenge
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        || challenge.len() != 43
    {
        return Err("diagnostics_invalid_response");
    }
    let program = crate::executable("ssh-keygen").map_err(|_| "ssh_keygen_unavailable")?;
    let key = std::fs::canonicalize(key).map_err(|_| "global_key_unavailable")?;
    let mut child = std::process::Command::new(program)
        .args(["-Y", "sign", "-n", NAMESPACE, "-f"])
        .arg(&key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .spawn()
        .map_err(|_| "ssh_keygen_unavailable")?;
    child
        .stdin
        .take()
        .ok_or("ssh_keygen_unavailable")?
        .write_all(challenge.as_bytes())
        .map_err(|_| "ssh_keygen_unavailable")?;
    let output = child
        .wait_with_output()
        .map_err(|_| "ssh_keygen_unavailable")?;
    let signature = String::from_utf8(output.stdout).map_err(|_| "global_signature_failed")?;
    if !output.status.success()
        || !signature.starts_with("-----BEGIN SSH SIGNATURE-----\n")
        || signature.len() > 2048
    {
        return Err("global_signature_failed");
    }
    Ok(signature)
}

pub async fn run(
    arguments: &[String],
    export_identity: &mut Option<Arc<IdentityClient>>,
) -> Result<Value, &'static str> {
    let (endpoint, command, argument) = match arguments {
        [_, endpoint, _, command] => (endpoint, command.as_str(), None),
        [_, endpoint, _, command, argument] => (endpoint, command.as_str(), Some(argument)),
        _ => return Err("invalid_arguments"),
    };
    if arguments.iter().any(|value| value.len() > 4096)
        || !matches!(
            (command, argument.is_some()),
            ("policy", false) | ("search", true) | ("grant", true)
        )
    {
        return Err("invalid_arguments");
    }
    let identity = Arc::new(IdentityClient::new(endpoint).map_err(|_| "invalid_server")?);
    let view = identity
        .refresh()
        .await
        .map_err(|_| "identity_unavailable")?;
    if !view.authenticated || !view.session_verified {
        return Err("sign_in_required");
    }
    identity
        .prepare_device("NDS agent".into())
        .await
        .map_err(|_| "device_unavailable")?;
    *export_identity = Some(identity.clone());
    match (command, argument) {
        ("policy", None) => {
            let policy = identity
                .sync_request(SyncRequest::CollectionPolicy)
                .await
                .map_err(class)?;
            Ok(json!({"operation":"diagnostics.policy","policy":reply(&policy.body)?}))
        }
        ("search", Some(request)) => {
            // Only a JSON object is forwarded; the server validates the closed request.
            let value: Value = serde_json::from_str(request).map_err(|_| "invalid_arguments")?;
            if !value.is_object() {
                return Err("invalid_arguments");
            }
            let body = serde_json::to_vec(&value).map_err(|_| "invalid_arguments")?;
            let page = identity
                .sync_request(SyncRequest::DiagnosticSearch(body))
                .await
                .map_err(class)?;
            Ok(json!({"operation":"diagnostics.search","page":reply(&page.body)?}))
        }
        ("grant", Some(key)) => {
            let issued = identity
                .sync_request(SyncRequest::GlobalDiagnosticChallenge)
                .await
                .map_err(class)?;
            let issued = reply(&issued.body)?;
            let challenge = issued["challenge"]
                .as_str()
                .ok_or("diagnostics_invalid_response")?
                .to_owned();
            if issued["namespace"] != NAMESPACE {
                return Err("diagnostics_invalid_response");
            }
            let key = key.clone();
            let signature = tokio::time::timeout(
                Duration::from_secs(60),
                tokio::task::spawn_blocking(move || sign(&key, &challenge).map(|s| (challenge, s))),
            )
            .await
            .map_err(|_| "global_signature_failed")?
            .map_err(|_| "global_signature_failed")??;
            let body =
                serde_json::to_vec(&json!({"challenge":signature.0,"signature":signature.1}))
                    .map_err(|_| "invalid_arguments")?;
            let grant = identity
                .sync_request(SyncRequest::GlobalDiagnosticGrant(body))
                .await
                .map_err(class)?;
            Ok(json!({"operation":"diagnostics.grant","grant":reply(&grant.body)?}))
        }
        _ => Err("invalid_arguments"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_three_diagnostic_commands_are_requested() {
        let args = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        assert!(requested(&args(&[
            "--server",
            "https://nds.example",
            "diagnostics",
            "policy"
        ])));
        assert!(!requested(&args(&[
            "--server",
            "https://nds.example",
            "vault",
            "list"
        ])));
        assert!(!requested(&args(&["diagnostics", "policy"])));
    }

    #[test]
    fn refusals_keep_their_class() {
        assert_eq!(
            class(ClientError::Server("forbidden_scope".into())),
            "forbidden_scope"
        );
        assert_eq!(
            class(ClientError::Server("global_grant_required".into())),
            "global_grant_required"
        );
        assert_eq!(
            class(ClientError::Server("collection_policy_unavailable".into())),
            "diagnostics_unsupported_by_server"
        );
        assert_eq!(class(ClientError::Transport), "diagnostics_unavailable");
    }

    #[test]
    fn only_a_well_formed_challenge_is_ever_signed() {
        assert_eq!(
            sign("/nonexistent", "short"),
            Err("diagnostics_invalid_response")
        );
        assert_eq!(
            sign(
                "/nonexistent",
                &"A".repeat(42).chars().chain(['/']).collect::<String>()
            ),
            Err("diagnostics_invalid_response")
        );
    }
}
