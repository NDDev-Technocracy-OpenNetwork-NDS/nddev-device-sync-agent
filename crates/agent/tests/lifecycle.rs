#![cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use nddev_device_sync_domain::{DeviceId, state::Snapshot, sync::EntityKind};
use nddev_device_sync_telemetry::{Config, ExportFeed, client_traces::ClientTraces};
use opentelemetry_proto::tonic::{
    collector::trace::v1::ExportTraceServiceRequest, common::v1::any_value,
};
use prost::Message;
use tracing::instrument::WithSubscriber;

use nddev_device_sync_agent::{
    NativeAgent,
    view::{AgentError, Reachability},
};

#[tokio::test]
async fn discovery_never_claims_observation_and_closed_hosts_refuse_work() {
    let agent = NativeAgent::discover().unwrap();
    let modules = agent.modules();
    assert_eq!(modules.len(), 8);
    assert!(
        modules.iter().all(|module| module.observed_at_ms.is_none()
            && module.reachability == Reachability::NotChecked)
    );
    agent.close();
    assert!(matches!(
        agent.system_info().await,
        Err(AgentError::Cancelled)
    ));
    assert!(matches!(
        agent.remote_sessions().await,
        Err(AgentError::Cancelled)
    ));
    assert!(
        agent
            .modules()
            .iter()
            .all(|module| module.observed_at_ms.is_none())
    );
}

#[tokio::test]
#[ignore = "requires scripts/check-agent.py with its paused native provider"]
async fn closing_an_in_flight_query_preserves_unobserved_state() {
    use std::time::Duration;
    assert_eq!(std::env::var("NDS_PAUSED_PROVIDER").as_deref(), Ok("1"));
    let agent = NativeAgent::discover().unwrap();
    let (traces, feed, dispatch) = telemetry();
    let query = agent.system_info().with_subscriber(dispatch);
    tokio::pin!(query);
    tokio::select! {
        _ = &mut query => panic!("paused native provider completed before cancellation"),
        _ = tokio::time::sleep(Duration::from_millis(100)) => {}
    }
    agent.close();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(7), query)
            .await
            .unwrap(),
        Err(AgentError::Cancelled)
    ));
    let state = agent
        .modules()
        .into_iter()
        .find(|module| module.id == "sysinfo")
        .unwrap();
    assert!(state.configured);
    assert!(state.reachability == Reachability::NotChecked);
    assert!(state.observed_at_ms.is_none() && state.error.is_none());
    assert_query_span(&feed, "sysinfo", 0);
    traces.shutdown();
}

#[tokio::test]
#[ignore = "requires scripts/check-agent.py with an empty child PATH"]
async fn cached_missing_provider_is_not_a_fresh_native_observation() {
    assert_eq!(std::env::var("PATH").as_deref(), Ok(""));
    let agent = NativeAgent::discover().unwrap();
    let (traces, feed, dispatch) = telemetry();
    assert!(matches!(
        agent.remote_sessions().with_subscriber(dispatch).await,
        Err(AgentError::Unavailable)
    ));
    let state = agent
        .modules()
        .into_iter()
        .find(|module| module.id == "rds")
        .unwrap();
    assert!(!state.configured);
    assert!(state.reachability == Reachability::NotChecked);
    assert!(state.observed_at_ms.is_none() && state.error.is_none());
    assert_query_span(&feed, "rds", 2);
    traces.shutdown();
}

#[tokio::test]
#[ignore = "requires scripts/check-agent.py with its paused native provider"]
async fn invalidating_a_module_cancels_its_actual_query_without_refreshing_health() {
    use std::time::Duration;
    assert_eq!(std::env::var("NDS_PAUSED_PROVIDER").as_deref(), Ok("1"));
    let agent = NativeAgent::discover().unwrap();
    let (traces, feed, dispatch) = telemetry();
    let query = agent.system_info().with_subscriber(dispatch);
    tokio::pin!(query);
    tokio::select! {
        _ = &mut query => panic!("paused provider completed before module invalidation"),
        _ = tokio::time::sleep(Duration::from_millis(100)) => {}
    }
    agent.invalidate_module("sysinfo").unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(7), query)
            .await
            .unwrap(),
        Err(AgentError::Cancelled)
    ));
    assert!(
        agent
            .modules()
            .iter()
            .all(|module| module.observed_at_ms.is_none()
                && module.reachability == Reachability::NotChecked)
    );
    assert_query_span(&feed, "sysinfo", 0);
    traces.shutdown();
}

#[tokio::test]
#[ignore = "requires scripts/check-agent.py with the real isolated sysinfo provider"]
async fn native_query_updates_only_its_own_observation() {
    assert_eq!(std::env::var("NDS_ISOLATED_PROVIDER").as_deref(), Ok("1"));
    let agent = NativeAgent::discover().unwrap();
    let (traces, feed, dispatch) = telemetry();
    agent
        .system_info()
        .with_subscriber(dispatch.clone())
        .await
        .unwrap();
    assert_query_span(&feed, "sysinfo", 0);
    for module in agent.modules() {
        if module.id == "sysinfo" {
            assert!(module.reachability == Reachability::Reachable);
            assert!(module.observed_at_ms.is_some() && module.error.is_none());
        } else {
            assert!(module.reachability == Reachability::NotChecked);
        }
    }
    let observed = agent
        .modules()
        .into_iter()
        .find(|module| module.id == "sysinfo")
        .unwrap()
        .observed_at_ms;
    agent.close();
    assert!(matches!(
        agent.system_info().with_subscriber(dispatch).await,
        Err(AgentError::Cancelled)
    ));
    let latest = agent
        .modules()
        .into_iter()
        .find(|module| module.id == "sysinfo")
        .unwrap();
    assert!(latest.reachability == Reachability::Reachable);
    assert_eq!(latest.observed_at_ms, observed);
    assert_query_span(&feed, "sysinfo", 0);
    traces.shutdown();
}

fn telemetry() -> (ClientTraces, ExportFeed, tracing::Dispatch) {
    let config = Config {
        service: "nddev-device-sync-agent".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        repository: "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-agent".into(),
        commit: "unknown".into(),
        channel: "alpha".into(),
        standards: "unreleased".into(),
        environment: "test".into(),
        default_module: "agent".into(),
        debug: None,
        target_prefixes: vec![
            "nddev_device_sync_agent".into(),
            "nddev_device_sync_adapter_io".into(),
            "nddev_device_sync_sysinfo".into(),
        ],
    };
    let traces = ClientTraces::new(&config).unwrap();
    let feed = traces.subscribe().unwrap();
    let (subscriber, _) =
        nddev_device_sync_telemetry::subscriber(config, std::io::sink(), traces.tracer()).unwrap();
    (traces, feed, tracing::Dispatch::new(subscriber))
}
fn assert_query_span(feed: &ExportFeed, module: &str, status: i32) {
    let batch = feed.take_batch().unwrap();
    assert_eq!(batch.count(), 1);
    let request = ExportTraceServiceRequest::decode(batch.bytes()).unwrap();
    let span = &request.resource_spans[0].scope_spans[0].spans[0];
    assert_eq!(span.name, "module.operation");
    let result = span.status.as_ref().unwrap();
    assert_eq!(result.code, status);
    assert!(result.message.is_empty());
    assert!(span.attributes.iter().any(|field| field.key == "module"
        && field.value.as_ref().and_then(|v| v.value.as_ref())
            == Some(&any_value::Value::StringValue(module.into()))));
    batch.acknowledge();
    assert_eq!(feed.health().pending, 0);
    assert_eq!(feed.health().dropped, 0);
}

#[tokio::test]
#[ignore = "requires scripts/check-agent.py with its paused native provider"]
async fn native_timeout_uses_core_failure_observation_and_error_span() {
    assert_eq!(std::env::var("NDS_PAUSED_PROVIDER").as_deref(), Ok("1"));
    let agent = NativeAgent::discover().unwrap();
    let (traces, feed, dispatch) = telemetry();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        agent.system_info().with_subscriber(dispatch),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(AgentError::Timeout)));
    let state = agent
        .modules()
        .into_iter()
        .find(|module| module.id == "sysinfo")
        .unwrap();
    assert!(state.configured && state.reachability == Reachability::Failed);
    assert!(state.observed_at_ms.is_some() && state.error == Some(AgentError::Timeout));
    assert_query_span(&feed, "sysinfo", 2);
    traces.shutdown();
}

#[tokio::test]
#[ignore = "requires scripts/check-agent.py with the verified packaged Rust worker and owned Git repository"]
async fn native_gds_query_uses_core_observation_and_projection() {
    let repository = std::path::PathBuf::from(std::env::var("NDS_AGENT_TEST_REPOSITORY").unwrap());
    assert!(repository.is_absolute());
    let agent = NativeAgent::discover().unwrap();
    let (traces, feed, dispatch) = telemetry();
    let result = agent
        .repository_status(&repository)
        .with_subscriber(dispatch)
        .await
        .unwrap();
    assert_eq!(result.status.unwrap().remote_freshness, "unknown");
    let state = agent
        .modules()
        .into_iter()
        .find(|module| module.id == "gds")
        .unwrap();
    assert!(
        state.configured && state.reachability == Reachability::Reachable && state.error.is_none()
    );
    let snapshot = Snapshot {
        schema_version: 1,
        observed_at_ms: state.observed_at_ms.unwrap(),
        data: state.state(),
    };
    snapshot
        .validate(
            &DeviceId::new("fixture-device").unwrap(),
            EntityKind::ModuleState,
            "fixture-device:gds",
        )
        .unwrap();
    assert_query_span(&feed, "gds", 0);
    traces.shutdown();
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
#[tokio::test]
async fn unqualified_gds_platform_is_unconfigured_and_refuses_queries() {
    let agent = NativeAgent::discover().unwrap();
    let state = agent
        .modules()
        .into_iter()
        .find(|module| module.id == "gds")
        .unwrap();
    assert!(!state.configured && state.observed_at_ms.is_none());
    assert!(matches!(
        agent
            .repository_status(std::path::Path::new("C:\\owned-test"))
            .await,
        Err(AgentError::UnsupportedPlatform)
    ));
}

#[tokio::test]
#[ignore = "requires scripts/check-agent.py with invalid owned worker copies"]
async fn gds_worker_admission_has_no_path_fallback() {
    let case = std::env::var("NDS_INVALID_WORKER").unwrap();
    let marker = std::path::PathBuf::from(std::env::var("NDS_GDS_EXECUTION_MARKER").unwrap());
    match case.as_str() {
        "missing" | "wrong-sibling" => {
            let agent = NativeAgent::discover().unwrap();
            let state = agent
                .modules()
                .into_iter()
                .find(|state| state.id == "gds")
                .unwrap();
            assert!(!state.configured && state.observed_at_ms.is_none());
            let repository =
                std::path::PathBuf::from(std::env::var("NDS_AGENT_TEST_REPOSITORY").unwrap());
            assert!(matches!(
                agent.repository_status(&repository).await,
                Err(AgentError::Unavailable)
            ));
        }
        "corrupt" | "symlink" | "oversized" => {
            assert!(matches!(
                NativeAgent::discover(),
                Err(AgentError::InvalidContract)
            ));
        }
        _ => panic!("unexpected qualification case"),
    }
    assert!(!marker.exists());
}
