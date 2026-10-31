//! Agent point-of-use interface. Session, vault keys and provider credentials stay
//! native; child output is discarded and never forwarded to chat or telemetry.
use nddev_device_sync_accounts::{IdentityClient, telemetry::Delivery};
use nddev_device_sync_adapter_io::{
    CancellationToken, CredentialEnvironment, NativeIo, ProcessInput, ProcessRequest,
};
use nddev_device_sync_domain::repositories::catalog::CredentialSelection;
use nddev_device_sync_telemetry::client_traces::ClientTraces;
use nddev_device_sync_vault::{VaultClient, replication::native::NativeReplica};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tracing::Instrument;
use zeroize::Zeroizing;

mod local_use;

struct CommandReply {
    value: Value,
    durable: bool,
}
fn catalog_error(
    error: nddev_device_sync_github::catalog_runtime::view::GithubCatalogError,
) -> &'static str {
    use nddev_device_sync_github::catalog_runtime::view::GithubCatalogError as E;
    match error {
        E::InvalidInput => "invalid_arguments",
        E::AuthorizationRequired => "sign_in_required",
        E::CredentialChanged => "github_source_changed",
        E::Busy => "github_busy",
        E::Cancelled => "github_cancelled",
        E::Timeout => "github_timeout",
        E::Unavailable => "github_unavailable",
        E::ProviderFailed => "github_provider_failed",
        E::InvalidResponse => "github_invalid_response",
        E::CapacityExhausted => "sync_capacity_exhausted",
        E::ModuleDisabled => "module_disabled",
        E::ModulePermissionRequired => "module_permission_required",
        E::ModuleConfigurationConflict => "module_configuration_conflict",
        E::AccountIgnored => "account_ignored",
        E::IgnoreListInvalid => "ignore_list_invalid",
    }
}
impl From<Value> for CommandReply {
    fn from(value: Value) -> Self {
        Self {
            value,
            durable: false,
        }
    }
}
fn source_error(error: nddev_device_sync_vault::Error) -> &'static str {
    match error {
        nddev_device_sync_vault::Error::Busy => "vault_busy",
        nddev_device_sync_vault::Error::SelectionChanged => "vault_selection_changed",
        nddev_device_sync_vault::Error::Cancelled => "vault_cancelled",
        _ => "vault_unavailable",
    }
}
fn shutdown_error(result: &mut Result<CommandReply, &'static str>) {
    if let Ok(reply) = result
        && reply.durable
    {
        // Shutdown cannot erase an already committed local transaction receipt.
        reply.value["shutdown_error"] = json!("vault_unavailable");
    } else {
        *result = Err("vault_unavailable");
    }
}

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
    replica_owner: &mut Option<Arc<NativeReplica>>,
    feeds: &mut Option<(
        nddev_device_sync_telemetry::ExportFeed,
        nddev_device_sync_telemetry::ExportFeed,
    )>,
) -> Result<CommandReply, &'static str> {
    let [flag, endpoint, scope, command, remaining @ ..] = args else {
        return Err("invalid_arguments");
    };
    if flag != "--server" || args.len() > 8 || args.iter().any(|value| value.len() > 2048) {
        return Err("invalid_arguments");
    }
    if !matches!(
        (scope.as_str(), command.as_str()),
        ("vault", "list" | "use")
            | ("github", "source" | "write" | "connect" | "repositories")
            | ("sync", "run")
    ) {
        return Err("unsupported_operation");
    }
    if scope == "sync" && !remaining.is_empty() {
        return Err("invalid_arguments");
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
    let mut catalog_client = None;
    if !offline || (scope == "sync" && command == "run") {
        let replica = NativeReplica::attach(
            &identity,
            data_directory()?,
            (scope == "sync" && command == "run").then(|| env!("CARGO_PKG_VERSION").into()),
        )
        .await
        .map_err(|_| "vault_unavailable")?;
        *replica_owner = Some(replica.clone());
        replica.ensure_delivery(|identity| {
            feeds
                .take()
                .map(|(events, traces)| Delivery::start(identity, events, traces, true))
        });
        if scope == "sync" && command == "run" {
            replica
                .catalog(nddev_device_sync_github::catalog_runtime::CatalogRuntime::new)
                .map_err(|_| "vault_unavailable")?;
            if !remaining.is_empty() {
                return Err("invalid_arguments");
            }
            return Ok(
                json!({"operation":"sync.run","started_offline":offline,"stopped":false}).into(),
            );
        }
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
                            "sync_capacity_exhausted" => "sync_capacity_exhausted",
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
        // Drain this process's data work before point-of-use I/O. Its existing
        // sender retains the independent owner identity until final flushing.
        replica
            .stop_replication()
            .await
            .map_err(|_| "vault_unavailable")?;
        vault
            .refresh_local()
            .await
            .map_err(|_| "vault_unavailable")?;
        current?;
    }
    if catalog_client.is_none()
        && scope == "github"
        && matches!(command.as_str(), "connect" | "repositories")
    {
        // Bounded point use starts no collector task, including cache listing.
        // The same concrete Rust composition owns its original caller; the
        // existing NativeReplica remains responsible for background sync only.
        let catalog = nddev_device_sync_github::catalog_runtime::CatalogRuntime::new(
            identity.clone(),
            vault.clone(),
        );
        catalog_client = Some(catalog.foreground(identity.clone()));
    }
    match (scope.as_str(), command.as_str(), remaining) {
        ("github", "write", [action]) if matches!(action.as_str(), "enable" | "disable") => {
            use nddev_device_sync_domain::{
                Permission, modules::control::Configuration,
                repositories::workspace::write_permissions,
            };
            if !nddev_device_sync_github::catalog_runtime::workspace_supported() {
                return Err("unsupported_platform");
            }
            let setting = vault
                .module_configuration("github")
                .await
                .map_err(source_error)?;
            if setting.conflicted {
                return Err("module_configuration_conflict");
            }
            let mut permissions = setting.configuration.permissions;
            let enabled = action == "enable" || setting.configuration.enabled;
            if action == "enable" {
                permissions.extend(write_permissions());
            } else {
                permissions.remove(&Permission::GitWrite);
            }
            let tags = permissions
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "invalid_arguments")?;
            let receipt = vault
                .set_module_configuration_attempt(
                    "github".into(),
                    setting.revision,
                    setting.pending_id,
                    Configuration {
                        enabled,
                        permissions,
                    },
                )
                .await
                .map_err(source_error)?;
            Ok(CommandReply {
                value: json!({"operation":"github.write","enabled":action=="enable","permissions":tags,"queued":true,"operation_id":receipt.operation_id,"local_revision":receipt.local_revision.to_string(),"offline":offline}),
                durable: true,
            })
        }
        ("github", "connect", [repository_id, owner_id, owner, name]) => {
            use nddev_device_sync_domain::repositories::{
                catalog::{GithubAccountId, RepositoryId},
                workspace::CheckoutLocation,
            };
            let parse = |value: &str| {
                let number = value.parse::<u64>().map_err(|_| "invalid_arguments")?;
                if number.to_string() != value {
                    return Err("invalid_arguments");
                }
                Ok(number)
            };
            let location = CheckoutLocation::new(
                RepositoryId::new(parse(repository_id)?).map_err(|_| "invalid_arguments")?,
                GithubAccountId::new(parse(owner_id)?).map_err(|_| "invalid_arguments")?,
                owner.clone(),
                name.clone(),
            )
            .map_err(|_| "invalid_arguments")?;
            let result = catalog_client
                .as_ref()
                .ok_or("online_verification_required")?
                .connect_repository(location)
                .await
                .map_err(catalog_error)?;
            let durable = matches!(
                result.outcome.as_str(),
                "connected" | "registration_pending"
            );
            Ok(CommandReply {
                value: json!({"operation":"github.connect","outcome":result.outcome,"reason":result.reason,"relative_path":result.relative_path,"intent_queued":result.intent_queued}),
                durable,
            })
        }
        ("github", "repositories", []) => {
            let client = catalog_client
                .as_ref()
                .ok_or("online_verification_required")?;
            let mut repositories = Vec::new();
            let mut next = false;
            for _ in 0..=(nddev_device_sync_domain::sync::MAX_ENTITY_COUNT / 25) {
                let page = client
                    .saved_github_repository_page(next)
                    .await
                    .map_err(catalog_error)?;
                for group in page.groups {
                    for item in group.repositories {
                        repositories.push(json!({"id":item.repository.id,"owner_id":group.owner_id,"owner":group.owner.as_ref().map(|value|value.owner.login.as_str()),"ignored":group.ignored,"name":item.repository.name,"conflicted":item.observation.conflicted,"pending":item.observation.pending,"observed_at_ms":item.observation.observed_at_ms,"synchronization":item.synchronization.map(|value|json!({"outcome":value.outcome,"reason":value.reason,"observed_at_ms":value.observed_at_ms}))}));
                    }
                }
                if !page.has_more {
                    return Ok(json!({"operation":"github.repositories","cached":true,"repositories":repositories}).into());
                }
                next = true;
            }
            Err("github_capacity_exhausted")
        }
        ("github", "source", []) => {
            let source = vault.github_source().await.map_err(source_error)?;
            Ok(json!({"operation":"github.source","offline":offline,
                "record_ref":source.selection.as_ref().map(CredentialSelection::record_ref),
                "record_revision":source.selection.as_ref().map(|value|value.revision().to_string()),
                "record_pending_id":source.selection.as_ref().and_then(CredentialSelection::pending_id),
                "revision":source.revision.to_string(),"pending_id":source.pending_id,
                "local_revision":source.local_revision.to_string(),"conflicted":source.conflicted}).into())
        }
        ("github", "source", [action, rest @ ..]) => {
            let selection = match (action.as_str(), rest) {
                ("clear", []) => None,
                ("select", [record, revision, pending @ ..]) if pending.len() <= 1 => {
                    let value = revision.parse::<u64>().map_err(|_| "invalid_arguments")?;
                    if value.to_string() != *revision {
                        return Err("invalid_arguments");
                    }
                    Some(
                        CredentialSelection::new(record.clone(), value, pending.first().cloned())
                            .map_err(|_| "invalid_arguments")?,
                    )
                }
                _ => return Err("invalid_arguments"),
            };
            let source = vault.github_source().await.map_err(source_error)?;
            if source.conflicted {
                return Err("github_source_conflict");
            }
            let receipt = vault
                .set_github_source(selection, source.revision, source.pending_id)
                .await
                .map_err(source_error)?;
            Ok(CommandReply {
                value: json!({"operation":"github.source.write","queued":true,"operation_id":receipt.operation_id,"local_revision":receipt.local_revision.to_string(),"offline":offline}),
                durable: true,
            })
        }
        ("vault", "list", [] | [_]) => {
            let after = remaining.first().map_or("", String::as_str);
            let page = vault
                .records(after.to_owned())
                .await
                .map_err(|_| "vault_unavailable")?;
            Ok(
                json!({"operation":"vault.list","offline":offline,"last_sync_at":vault.snapshot().last_sync_at,"pending":vault.snapshot().pending,"records":page.items.iter().map(|record|json!({"ref":record.id,"title":record.title,"revision":record.revision,"observed_seq":record.observed_seq,"deleted":record.deleted,"conflicted":record.conflicted,"pending":record.pending_id.is_some(),"pending_id":record.pending_id})).collect::<Vec<_>>(),"next_ref":if page.has_more {page.next_after} else {String::new()}}).into(),
            )
        }
        ("vault", "use", [record, provider]) => {
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
                json!({"operation":"vault.use","provider":provider,"verified":true,"replica_offline":offline}).into(),
            )
        }
        _ => Err("invalid_arguments"),
    }
}
async fn stop_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result, _ = term.recv() => Ok(()) }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

/// Observes the existing owner; this is not another replication scheduler.
async fn run_owner(owner: &Arc<NativeReplica>) -> Result<Value, &'static str> {
    let catalog = owner
        .catalog(nddev_device_sync_github::catalog_runtime::CatalogRuntime::new)
        .map_err(|_| "vault_unavailable")?;
    let mut updates = owner.updates().map_err(|_| "vault_unavailable")?;
    let stop = stop_signal();
    tokio::pin!(stop);
    tracing::info!(
        event.name = "agent.sync.started",
        module = "github",
        outcome = "ok"
    );
    loop {
        tokio::select! {
            signal = &mut stop => {
                signal.map_err(|_| "shutdown_unavailable")?;
                let observed = catalog.observation().await;
                return Ok(observed.map_or(Value::Null, |value| json!({
                    "observed_at_ms":value.observed_at_ms,
                    "error":value.error.map(|error|error.to_string()),
                })));
            }
            changed = updates.changed() => {
                changed.map_err(|_| "vault_unavailable")?;
                if matches!(&*updates.borrow_and_update(), Some(Err(
                    nddev_device_sync_vault::Error::Locked
                    | nddev_device_sync_vault::Error::Authentication
                    | nddev_device_sync_vault::Error::RegistrationRequired))) {
                    return Err("sign_in_required");
                }
            }
        }
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
            "nddev_device_sync_github".into(),
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
    let mut replica_owner = None;
    let arguments = std::env::args_os()
        .skip(1)
        .take(10)
        .map(|value| value.into_string().map_err(|_| "invalid_arguments"))
        .collect::<Result<Vec<_>, _>>();
    let span = nddev_device_sync_telemetry::operation_span("agent", "process")
        .expect("static agent scope");
    let mut result = match arguments {
        // One operation's lifetime belongs to its caller, not the point-use deadline.
        Ok(arguments) if local_use::requested(&arguments) => {
            local_use::run(&arguments, &mut export_identity, data_directory)
                .instrument(span.clone())
                .await
                .map(CommandReply::from)
        }
        Ok(arguments) => tokio::time::timeout(
            Duration::from_secs(120),
            operation(
                &arguments,
                &mut export_identity,
                &mut replica_owner,
                &mut feeds,
            )
            .instrument(span.clone()),
        )
        .await
        .unwrap_or(Err("operation_timeout")),
        Err(error) => Err(error),
    };
    if let Ok(reply) = &mut result
        && reply.value.get("operation").and_then(Value::as_str) == Some("sync.run")
    {
        if let Some(owner) = &replica_owner {
            match run_owner(owner).await {
                Ok(observation) => {
                    reply.value["stopped"] = json!(true);
                    reply.value["github"] = observation;
                }
                Err(error) => result = Err(error),
            }
        } else {
            result = Err("vault_unavailable");
        }
    }
    // Timeout and early error also drain real data work before terminal signals.
    // The one retained sender can still authenticate this process's final batch.
    if let Some(owner) = &replica_owner
        && owner.stop_replication().await.is_err()
    {
        shutdown_error(&mut result);
    }
    span.in_scope(|| match &result {
        Ok(_) => tracing::info!(event.name = "agent.operation.completed", outcome = "ok"),
        Err(error) => tracing::warn!(event.name = "agent.operation.failed", error.type = *error, outcome = "error"),
    });
    drop(span);
    let delivery = replica_owner
        .as_ref()
        .and_then(|owner| owner.delivery_handle())
        .or_else(|| {
            export_identity
                .zip(feeds.take())
                .map(|(identity, (events, traces))| {
                    Arc::new(Delivery::start(identity, events, traces, true))
                })
        });
    let observed = match &delivery {
        Some(delivery) => Some(delivery.flush().await),
        None => None,
    };
    drop(delivery);
    if NativeReplica::shutdown().await.is_err() {
        shutdown_error(&mut result);
    }
    let success = result.is_ok();
    let mut output = result
        .map(|reply| reply.value)
        .unwrap_or_else(|error| json!({"error":error}));
    output["diagnostics"] = observed.map_or_else(|| json!({"export":"unavailable"}), |state| json!({
        "export":match state.policy {nddev_device_sync_accounts::telemetry::ExportPolicy::Unknown=>"unknown",nddev_device_sync_accounts::telemetry::ExportPolicy::Enabled=>"enabled",nddev_device_sync_accounts::telemetry::ExportPolicy::Disabled=>"disabled"},
        "acknowledged_events":state.delivered,"acknowledged_spans":state.spans_delivered,
        "undelivered":state.pending+state.spans_pending,"dropped":state.dropped+state.spans_dropped
    }));
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
