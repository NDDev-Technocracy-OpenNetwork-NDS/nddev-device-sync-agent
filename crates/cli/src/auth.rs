//! Email sign-in reads its secret code from one bounded stdin line, never an argument.
//! `nds-agent --server <origin> auth <command>`: headless sign-in for an agent host.
//!
//! - `status` prints the session state of this host's NDS identity: whether it is
//!   authenticated and verified, the principal and device ids, and the expiry. It never
//!   prints credentials.
//! - `github <pending-file>` starts the GitHub sign-in. It writes the authorization URL and
//!   the 8-digit verification code (0600) to `<pending-file>` for whoever completes the
//!   browser approval, then polls until the server approves, the flow expires or 11 minutes
//!   pass. Afterwards it enrolls or reuses this host's device. The session lives in the OS
//!   credential store like the app's, lasts seven days and renews through the device.
//! - `logout` ends this host's session.
use nddev_device_sync_accounts::{IdentityClient, View};
use serde_json::{Value, json};
use std::{io::Write, path::Path, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use zeroize::Zeroizing;

pub fn requested(arguments: &[String]) -> bool {
    matches!(arguments, [flag, _, scope, ..] if flag == "--server" && scope == "auth")
}

fn state(view: &View) -> Value {
    json!({
        "authenticated": view.authenticated,
        "session_verified": view.session_verified,
        "offline_authorized": view.offline_authorized,
        "credential_store_ready": view.credential_store_ready,
        "auth_method": view.auth_method,
        "user_id": view.user_id,
        "tenant_id": view.tenant_id,
        "device_id": view.current_device_id,
        "expires_at": view.expires_at,
        "server_version": view.server_version,
    })
}

/// Writes the pending approval for the browser step; the file is private and replaced
/// atomically.
fn pending(path: &Path, view: &View) -> Result<(), &'static str> {
    let body = json!({
        "authorization_url": view.authorization_url,
        "verification_code": view.verification_code,
        "expires_in_seconds": view.expires_in_seconds,
    });
    let directory = path.parent().ok_or("invalid_arguments")?;
    let temporary = directory.join(format!(".nds-auth-{}.tmp", std::process::id()));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| "pending_file_unavailable")?;
        file.write_all(body.to_string().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| "pending_file_unavailable")?;
    }
    std::fs::rename(&temporary, path).map_err(|_| "pending_file_unavailable")
}

async fn github(identity: &IdentityClient, file: &str) -> Result<Value, &'static str> {
    let path = Path::new(file);
    if !path.is_absolute() || path.file_name().is_none() {
        return Err("invalid_arguments");
    }
    let view = identity
        .start_github("en")
        .await
        .map_err(|_| "github_sign_in_unavailable")?;
    if view.authorization_url.is_empty() || view.verification_code.len() != 8 {
        return Err("github_sign_in_unavailable");
    }
    pending(path, &view)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(660);
    let result = loop {
        if tokio::time::Instant::now() >= deadline {
            break Err("github_sign_in_timeout");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        match identity.poll_github().await {
            Ok(view) if view.authenticated => break Ok(()),
            Ok(_) => {}
            Err(nddev_device_sync_accounts::view::ClientError::Expired) => {
                break Err("github_sign_in_expired");
            }
            Err(nddev_device_sync_accounts::view::ClientError::Server(code))
                if code == "authorization_denied" || code == "access_denied" =>
            {
                break Err("github_sign_in_denied");
            }
            Err(_) => {}
        }
    };
    let _ = std::fs::remove_file(path);
    result?;
    let view = identity
        .prepare_device("NDS agent".into())
        .await
        .map_err(|_| "device_unavailable")?;
    Ok(json!({"operation":"auth.github","session":state(&view)}))
}

fn code_line(bytes: &[u8]) -> Result<&str, &'static str> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    if bytes.len() != 8 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err("invalid_email_code");
    }
    std::str::from_utf8(bytes).map_err(|_| "invalid_email_code")
}

async fn email(identity: &IdentityClient, address: &str) -> Result<Value, &'static str> {
    identity
        .request_email(address.to_owned(), "en")
        .await
        .map_err(|_| "email_sign_in_unavailable")?;
    tracing::info!(target: "nds_agent",
        event.name = "agent.auth.email.waiting", auth_method = "email_otp", outcome = "pending");
    let receive = async {
        // One eight-digit line, optional CR/LF. A large or unterminated input
        // is bounded before allocation; never format the bytes or the address.
        let mut bytes = Zeroizing::new(Vec::with_capacity(11));
        let mut input = tokio::io::BufReader::with_capacity(11, tokio::io::stdin()).take(11);
        input
            .read_until(b'\n', &mut bytes)
            .await
            .map_err(|_| "email_code_unavailable")?;
        Ok::<_, &'static str>(code_line(&bytes)?.to_owned())
    };
    let code = tokio::time::timeout(Duration::from_secs(600), receive)
        .await
        .map_err(|_| "email_sign_in_timeout")??;
    identity
        .verify_email(code)
        .await
        .map_err(|_| "email_sign_in_failed")?;
    let view = identity
        .prepare_device("NDS agent".into())
        .await
        .map_err(|_| "device_unavailable")?;
    Ok(json!({"operation":"auth.email","session":state(&view)}))
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
    if arguments.iter().any(|value| value.len() > 4096) {
        return Err("invalid_arguments");
    }
    let identity = Arc::new(IdentityClient::new(endpoint).map_err(|_| "invalid_server")?);
    let view = identity
        .refresh()
        .await
        .map_err(|_| "identity_unavailable")?;
    match (command, argument) {
        ("status", None) => Ok(json!({"operation":"auth.status","session":state(&view)})),
        ("github", Some(file)) => {
            let result = github(&identity, file).await;
            if result.is_ok() {
                *export_identity = Some(identity.clone());
            }
            result
        }
        ("email", Some(address)) => {
            let result = email(&identity, address).await;
            if result.is_ok() {
                *export_identity = Some(identity.clone());
            }
            result
        }
        ("logout", None) => {
            let view = identity
                .logout()
                .await
                .map_err(|_| "identity_unavailable")?;
            Ok(json!({"operation":"auth.logout","session":state(&view)}))
        }
        _ => Err("invalid_arguments"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_code_input_is_one_bounded_secret_line() {
        for value in [b"12345678".as_slice(), b"12345678\n", b"12345678\r\n"] {
            assert_eq!(code_line(value).map(str::len), Ok(8));
        }
        for value in [
            b"".as_slice(),
            b"1234567",
            b"123456789",
            b"1234abcd",
            b" 12345678",
            b"12345678\n\n",
            b"\xff1234567",
        ] {
            assert!(code_line(value).is_err());
        }
    }

    #[test]
    fn only_auth_commands_are_requested() {
        let args = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        assert!(requested(&args(&[
            "--server",
            "https://nds.example",
            "auth",
            "status"
        ])));
        assert!(!requested(&args(&[
            "--server",
            "https://nds.example",
            "diagnostics",
            "policy"
        ])));
        assert!(!requested(&args(&["auth", "status"])));
    }

    #[test]
    fn the_pending_approval_is_private_and_replaced_atomically() {
        let directory = std::env::temp_dir().join(format!("nds-auth-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("pending.json");
        let view = View {
            authorization_url: "https://nds.example/v2/auth/github/authorize".into(),
            verification_code: "12345678".into(),
            expires_in_seconds: 600,
            ..Default::default()
        };
        pending(&path, &view).unwrap();
        let written: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(written["verification_code"], "12345678");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
