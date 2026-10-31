//! Compiled-in native module composition. Domain contracts come from NDS core;
//! concrete tools retain their own data, permissions and execution policies.
pub mod view;

/// Bound shared by artifact packaging and native worker admission.
pub const GITHUB_WORKER_MAX_BYTES: u64 = 128 * 1024 * 1024;

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
        nddev_device_sync_github::MANIFEST,
        nddev_device_sync_remote::MANIFEST,
        nddev_device_sync_browser_use::MANIFEST,
        nddev_device_sync_cache_client::MANIFEST,
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

#[cfg(test)]
mod tests {
    #[test]
    fn graph_keeps_the_owning_browser_descriptor_with_eight_modules() {
        let graph = super::module_graph().unwrap();
        assert_eq!(graph.iter().count(), 8);
        let descriptor = graph
            .iter()
            .find(|module| module.id.as_str() == "browser-use")
            .unwrap();
        let owner: serde_json::Value =
            serde_json::from_str(nddev_device_sync_browser_use::MANIFEST).unwrap();
        assert_eq!(descriptor.version, owner["version"].as_str().unwrap());
        assert_eq!(
            owner["capabilities"],
            serde_json::json!(["control_browser"])
        );
        assert_eq!(owner["permissions"], serde_json::json!(["browser_control"]));
    }

    #[test]
    fn graph_registers_the_owning_linux_cache_descriptor_without_extra_grants() {
        use nddev_device_sync_domain::{
            ModuleCapability, Permission, Platform, modules::control::Configuration,
        };
        use std::collections::BTreeSet;
        let graph = super::module_graph().unwrap();
        let descriptor = graph
            .iter()
            .find(|value| value.id.as_str() == "cache")
            .unwrap();
        let owner: serde_json::Value =
            serde_json::from_str(nddev_device_sync_cache_client::MANIFEST).unwrap();
        assert_eq!(descriptor.version, owner["version"].as_str().unwrap());
        assert_eq!(descriptor.platforms, BTreeSet::from([Platform::Linux]));
        assert_eq!(
            owner["capabilities"],
            serde_json::json!(["read_module_health", "manage_device_state"])
        );
        assert_eq!(
            descriptor.capabilities,
            BTreeSet::from([
                ModuleCapability::ReadModuleHealth,
                ModuleCapability::ManageDeviceState,
            ])
        );
        assert_eq!(
            descriptor.permissions,
            BTreeSet::from([
                Permission::LocalNetwork,
                Permission::UserService,
                Permission::ProcessExecution,
            ])
        );
        assert_eq!(
            owner["dependencies"],
            serde_json::json!([{"id":"remote","minimum_api":1}])
        );
        let missing = Configuration {
            enabled: true,
            permissions: BTreeSet::from([Permission::ReadOnly]),
        };
        assert!(missing.admit(true, true, &descriptor.permissions).is_err());
        let explicit = Configuration {
            enabled: true,
            permissions: descriptor.permissions.clone(),
        };
        assert!(explicit.admit(true, true, &descriptor.permissions).is_ok());
        assert!(
            explicit
                .admit(false, true, &descriptor.permissions)
                .is_err()
        );
    }
}
