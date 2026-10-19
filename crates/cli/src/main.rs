//! Agent point-of-use interface. Session, vault keys and provider credentials stay
//! native; child output is discarded and never forwarded to chat or telemetry.
use nddev_device_sync_accounts::{IdentityClient, telemetry::Delivery};
use nddev_device_sync_adapter_io::{
    CancellationToken, CredentialEnvironment, NativeIo, ProcessInput, ProcessRequest,
};
use nddev_device_sync_telemetry::client_traces::ClientTraces;
use nddev_device_sync_vault::{VaultClient, replication::native::NativeReplica};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tracing::Instrument;
use zeroize::Zeroizing;

fn data_directory() -> Result<PathBuf, &'static str> {
    nddev_device_sync_accounts::private_data_directory().map_err(|_| "native_directory_unavailable")
}

fn executable(name: &str) -> Result<PathBuf, &'static str> {
    let paths = std::env::var_os("PATH").ok_or("provider_unavailable")?;
    #[cfg(target_os = "windows")]
    let name = format!("{name}.exe");
    #[cfg(target_os = "windows")]
    let name = name.as_str();
    for directory in std::env::split_paths(&paths)
        .take(64)
        .filter(|directory| directory.is_absolute())
    {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return std::fs::canonicalize(candidate).map_err(|_| "provider_unavailable");
        }
    }
    Err("provider_unavailable")
}
async fn operation(
    args: &[String],
    export_identity: &mut Option<Arc<IdentityClient>>,
) -> Result<Value, &'static str> {
    let [flag, endpoint, scope, command, remaining @ ..] = args else {
        return Err("invalid_arguments");
    };
    if flag != "--server"
        || scope != "vault"
        || args.len() > 6
        || args.iter().any(|value| value.len() > 2048)
    {
        return Err("invalid_arguments");
    }
    if command != "list" && command != "use" {
        return Err("unsupported_operation");
    }
    let identity = Arc::new(IdentityClient::new(endpoint).map_err(|_| "invalid_server")?);
    let view = identity
        .refresh()
        .await
        .map_err(|_| "identity_unavailable")?;
    if !view.authenticated || !(view.session_verified || view.offline_authorized) {
        return Err("sign_in_required");
    }
    if view.session_verified {
        identity
            .prepare_device("NDS agent".into())
            .await
            .map_err(|_| "device_unavailable")?;
    }
    *export_identity = Some(identity.clone());
    let vault = Arc::new(
        VaultClient::new(identity.clone(), data_directory()?)
            .await
            .map_err(|_| "vault_unavailable")?,
    );
    let offline = view.offline_authorized;
    if !offline {
        let replica = NativeReplica::attach(&identity, data_directory()?, None)
            .await
            .map_err(|_| "vault_unavailable")?;
        let mut updates = replica.updates().map_err(|_| "vault_unavailable")?;
        let current = async {
            loop {
                updates.changed().await.map_err(|_| "vault_unavailable")?;
                let result = updates.borrow_and_update().clone();
                tracing::info!(
                    event.name = "agent.replica.observed",
                    module = "vault",
                    outcome = match &result {
                        Some(Ok(view)) if !view.sync_error.is_empty() => "error",
                        Some(Ok(view)) if !view.catching_up => "ok",
                        Some(Err(_)) => "error",
                        _ => "pending",
                    }
                );
                match result {
                    Some(Ok(view)) if !view.sync_error.is_empty() => {
                        return Err(match view.sync_error.as_str() {
                            "sync_basis_expired" => "sync_basis_expired",
                            "sync_legacy_outcome_unknown" => "sync_legacy_outcome_unknown",
                            _ => "vault_unavailable",
                        });
                    }
                    Some(Ok(view)) if !view.catching_up => return Ok(()),
                    Some(Ok(_)) | Some(Err(nddev_device_sync_vault::Error::Busy)) | None => {}
                    Some(Err(nddev_device_sync_vault::Error::CapacityExhausted)) => {
                        return Err("sync_capacity_exhausted");
                    }
                    Some(Err(_)) => return Err("vault_unavailable"),
                }
            }
        }
        .await;
        // The CLI detaches its bounded process owner before point-of-use I/O.
        // A GUI in another process keeps its own elected owner running.
        NativeReplica::shutdown()
            .await
            .map_err(|_| "vault_unavailable")?;
        vault
            .refresh_local()
            .await
            .map_err(|_| "vault_unavailable")?;
        current?;
    }
    match (command.as_str(), remaining) {
        ("list", [] | [_]) => {
            let after = remaining.first().map_or("", String::as_str);
            let page = vault
                .records(after.to_owned())
                .await
                .map_err(|_| "vault_unavailable")?;
            Ok(
                json!({"operation":"vault.list","offline":offline,"last_sync_at":vault.snapshot().last_sync_at,"pending":vault.snapshot().pending,"records":page.items.iter().map(|record|json!({"ref":record.id,"title":record.title,"revision":record.revision,"observed_seq":record.observed_seq,"deleted":record.deleted,"conflicted":record.conflicted,"pending":record.pending_id.is_some()})).collect::<Vec<_>>(),"next_ref":if page.has_more {page.next_after} else {String::new()}}),
            )
        }
        ("use", [record, provider]) => {
            let (name, arguments, environment) = match provider.as_str() {
                "github" => (
                    "gh",
                    vec!["api", "user", "--hostname", "github.com"],
                    CredentialEnvironment::GitHub,
                ),
                "cloudflare" => (
                    "wrangler",
                    vec!["whoami", "--json"],
                    CredentialEnvironment::Cloudflare,
                ),
                "digitalocean" => (
                    "doctl",
                    vec!["account", "get", "--output", "json"],
                    CredentialEnvironment::DigitalOcean,
                ),
                _ => return Err("unsupported_provider"),
            };
            let token = vault
                .native_secret(record.clone())
                .await
                .map_err(|_| "secret_reference_unavailable")?;
            let output = NativeIo::new(1)
                .map_err(|_| "native_io_unavailable")?
                .process_handle()
                .process_input(
                    ProcessRequest {
                        executable: executable(name)?,
                        arguments: arguments.into_iter().map(Into::into).collect(),
                        directory: None,
                        timeout: Duration::from_secs(20),
                        max_output_bytes: 65_536,
                    },
                    ProcessInput {
                        stdin: Zeroizing::new(Vec::new()),
                        credential: Some((environment, token)),
                    },
                    CancellationToken::new(),
                )
                .await
                .map_err(|_| "provider_unavailable")?;
            let success = output.status.success();
            let _stdout = Zeroizing::new(output.stdout);
            let _stderr = Zeroizing::new(output.stderr);
            if !success {
                return Err("provider_credential_rejected");
            }
            Ok(
                json!({"operation":"vault.use","provider":provider,"verified":true,"replica_offline":offline}),
            )
        }
        _ => Err("invalid_arguments"),
    }
}
#[tokio::main]
async fn main() {
    let config = nddev_device_sync_telemetry::Config {
        service: "nddev-device-sync-agent".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        repository: "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-agent".into(),
        commit: option_env!("NDS_SOURCE_COMMIT").unwrap_or("unknown").into(),
        channel: "alpha".into(),
        standards: "unreleased".into(),
        environment: "client".into(),
        target_prefixes: vec![
            "nds_agent".into(),
            "nds_accounts".into(),
            "nddev_device_sync_vault".into(),
            "nddev_device_sync_adapter_io".into(),
        ],
        default_module: "agent".into(),
        debug: None,
    };
    let traces = ClientTraces::new(&config).ok();
    let mut logger = traces.as_ref().and_then(|traces| {
        nddev_device_sync_telemetry::install_client_with_tracer_to(
            config,
            traces.tracer(),
            nddev_device_sync_telemetry::LocalOutput::Stderr,
        )
        .ok()
    });
    let mut feeds = logger
        .as_ref()
        .zip(traces.as_ref())
        .and_then(|(logger, traces)| {
            Some((logger.control.subscribe().ok()?, traces.subscribe().ok()?))
        });
    if feeds.is_none() {
        println!("{}", json!({"error":"telemetry_unavailable"}));
        std::process::exit(2);
    }
    let mut export_identity = None;
    let arguments = std::env::args_os()
        .skip(1)
        .take(8)
        .map(|value| value.into_string().map_err(|_| "invalid_arguments"))
        .collect::<Result<Vec<_>, _>>();
    let span = nddev_device_sync_telemetry::operation_span("agent", "process")
        .expect("static agent scope");
    let mut result = match arguments {
        Ok(arguments) => tokio::time::timeout(
            Duration::from_secs(120),
            operation(&arguments, &mut export_identity).instrument(span.clone()),
        )
        .await
        .unwrap_or(Err("operation_timeout")),
        Err(error) => Err(error),
    };
    // Also terminate/drain the retained owner after operation timeout or early
    // error; the process exporter starts only after this foreground lifetime.
    if NativeReplica::shutdown().await.is_err() {
        result = Err("vault_unavailable");
    }
    span.in_scope(|| match &result {
        Ok(_) => tracing::info!(event.name = "agent.operation.completed", outcome = "ok"),
        Err(error) => tracing::warn!(event.name = "agent.operation.failed", error.type = *error, outcome = "error"),
    });
    drop(span);
    // Flush after the foreground capability completes. Background telemetry
    // must not compete with its native credential-store admission budget.
    let delivery = export_identity
        .zip(feeds.take())
        .map(|(identity, (events, traces))| Delivery::start(identity, events, traces, true));
    let observed = match &delivery {
        Some(delivery) => Some(delivery.flush().await),
        None => None,
    };
    let success = result.is_ok();
    let mut output = result.unwrap_or_else(|error| json!({"error":error}));
    output["diagnostics"] = observed.map_or_else(|| json!({"export":"unavailable"}), |state| json!({
        "export":match state.policy {nddev_device_sync_accounts::telemetry::ExportPolicy::Unknown=>"unknown",nddev_device_sync_accounts::telemetry::ExportPolicy::Enabled=>"enabled",nddev_device_sync_accounts::telemetry::ExportPolicy::Disabled=>"disabled"},
        "acknowledged_events":state.delivered,"acknowledged_spans":state.spans_delivered,
        "undelivered":state.pending+state.spans_pending,"dropped":state.dropped+state.spans_dropped
    }));
    drop(delivery);
    if let Some(traces) = traces {
        traces.shutdown();
    }
    if let Some(logger) = &mut logger {
        logger.shutdown();
    }
    println!("{output}");
    if !success {
        std::process::exit(2);
    }
}
