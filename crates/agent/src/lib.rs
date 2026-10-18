//! Compiled-in native module composition. Domain contracts come from NDS core;
//! concrete tools retain their own data, permissions and execution policies.
pub mod view;

/// Bound shared by artifact packaging and native worker admission.
pub const GDS_WORKER_MAX_BYTES: u64 = 128 * 1024 * 1024;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod native;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use native::NativeAgent;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod worker;

/// The same compiled-in descriptor graph is available without native I/O.
/// Browser/mobile composition must report its actual adapters separately.
pub fn module_graph() -> Result<nddev_device_sync_domain::ModuleGraph, view::AgentError> {
    let mut graph = nddev_device_sync_domain::ModuleGraph::default();
    for manifest in [
        nddev_device_sync_sysinfo::MANIFEST,
        nddev_device_sync_clipboard::MANIFEST,
        nddev_device_sync_cleaner::MANIFEST,
        nddev_device_sync_updater::MANIFEST,
        nddev_device_sync_gds::MANIFEST,
        nddev_device_sync_rds::MANIFEST,
    ] {
        graph
            .register(
                serde_json::from_str(manifest).map_err(|_| view::AgentError::InvalidContract)?,
            )
            .map_err(|_| view::AgentError::InvalidContract)?;
    }
    graph
        .validate()
        .map_err(|_| view::AgentError::InvalidContract)?;
    Ok(graph)
}
