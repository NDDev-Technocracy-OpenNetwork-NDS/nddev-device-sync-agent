use crate::view::{AgentError, ModuleState, Reachability};
use crate::worker::bundled_git_worker;
use nddev_device_sync_adapter_io::{CancellationToken, IoError, NativeIo};
use nddev_device_sync_clipboard::{Clipboard, ReadClipboard};
use nddev_device_sync_domain::{ModuleGraph, ModuleId, Platform, modules::query_outcome};
use nddev_device_sync_sysinfo::{ReadSystemInfo, SystemInfo};
use std::{
    future::Future,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tracing::Instrument;

use nddev_device_sync_cleaner::{Cleaner, ReadCleaner};
use nddev_device_sync_gds::Gds;
use nddev_device_sync_rds::{Rds, ReadRds};
use nddev_device_sync_updater::{ReadUpdater, Updater};

struct ModuleSlot {
    state: ModuleState,
    lifetime: Arc<CancellationToken>,
}

pub struct NativeAgent {
    modules: Mutex<Vec<ModuleSlot>>,
    graph: ModuleGraph,
    platform: Platform,
    cancellation: CancellationToken,
    sysinfo: Option<SystemInfo>,
    clipboard: Option<Clipboard>,
    cleaner: Option<Cleaner>,
    updater: Option<Updater>,
    gds: Option<Gds>,
    rds: Option<Rds>,
}

impl Drop for NativeAgent {
    fn drop(&mut self) {
        self.close();
    }
}

impl NativeAgent {
    pub fn discover() -> Result<Self, AgentError> {
        let graph = crate::module_graph()?;
        let platform = current_platform();
        let supported = |id: &str| {
            graph
                .iter()
                .find(|descriptor| descriptor.id.as_str() == id)
                .is_some_and(|descriptor| descriptor.platforms.contains(&platform))
        };
        let io = NativeIo::new(8).map_err(io_error)?;
        let sysinfo = supported("sysinfo")
            .then(|| SystemInfo::for_current_user(io.local_handle()).ok())
            .flatten();
        let clipboard = supported("clipboard")
            .then(|| Clipboard::for_current_user(io.local_handle()).ok())
            .flatten();
        let cleaner = if supported("cleaner") {
            executable("rldyour-cleaner")
                .map(|path| Cleaner::new(io.process_handle(), path))
                .transpose()
                .map_err(cleaner_error)?
        } else {
            None
        };
        let updater = if supported("updater") {
            executable("rldyour-updater")
                .map(|path| Updater::new(io.process_handle(), path))
                .transpose()
                .map_err(updater_error)?
        } else {
            None
        };
        let gds = if supported("gds") {
            bundled_git_worker()?
                .map(|path| {
                    Gds::new(
                        io.process_handle(),
                        path,
                        std::time::Duration::from_secs(12),
                    )
                })
                .transpose()?
        } else {
            None
        };
        let rds = if supported("rds") {
            executable("rds")
                .map(|path| Rds::new(io.process_handle(), path, None))
                .transpose()
                .map_err(rds_error)?
        } else {
            None
        };
        let modules = graph
            .iter()
            .map(|descriptor| ModuleSlot {
                state: ModuleState {
                    id: descriptor.id.as_str().into(),
                    version: descriptor.version.clone(),
                    configured: match descriptor.id.as_str() {
                        "sysinfo" => sysinfo.is_some(),
                        "clipboard" => clipboard.is_some(),
                        "cleaner" => cleaner.is_some(),
                        "updater" => updater.is_some(),
                        "gds" => gds.is_some(),
                        "rds" => rds.is_some(),
                        _ => false,
                    },
                    reachability: Reachability::NotChecked,
                    observed_at_ms: None,
                    error: None,
                },
                lifetime: Arc::new(CancellationToken::new()),
            })
            .collect();
        Ok(Self {
            modules: Mutex::new(modules),
            graph,
            platform,
            cancellation: CancellationToken::new(),
            sysinfo,
            clipboard,
            cleaner,
            updater,
            gds,
            rds,
        })
    }

    pub fn modules(&self) -> Vec<ModuleState> {
        self.modules
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .map(|slot| slot.state.clone())
            .collect()
    }

    /// Invalidate only this module's owned requests and stale observations.
    pub fn invalidate_module(&self, module: &str) -> Result<(), AgentError> {
        let mut slots = self.modules.lock().unwrap_or_else(|e| e.into_inner());
        let slot = slots
            .iter_mut()
            .find(|slot| slot.state.id == module)
            .ok_or(AgentError::InvalidInput)?;
        slot.lifetime.cancel();
        slot.lifetime = Arc::new(CancellationToken::new());
        slot.state.reachability = Reachability::NotChecked;
        slot.state.observed_at_ms = None;
        slot.state.error = None;
        Ok(())
    }

    /// Terminal shutdown; constructing a new host is an explicit new lifetime.
    pub fn close(&self) {
        self.cancellation.cancel();
        for slot in self
            .modules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            slot.lifetime.cancel();
        }
    }

    async fn observe<T, F: Future<Output = Result<T, AgentError>>>(
        &self,
        module: &'static str,
        work: impl FnOnce(CancellationToken) -> F,
    ) -> Result<T, AgentError> {
        async {
            let started = Instant::now();
            let lifetime = self.modules.lock().unwrap_or_else(|e| e.into_inner()).iter()
                .find(|slot| slot.state.id == module).map(|slot| slot.lifetime.clone())
                .ok_or(AgentError::InvalidContract)?;
            let result = if self.cancellation.is_cancelled() {
                Err(AgentError::Cancelled)
            } else {
                match self.admitted(module) {
                    Ok(true) => {
                        let result = work(lifetime.as_ref().clone()).await;
                        if self.cancellation.is_cancelled() || lifetime.is_cancelled() {
                            Err(AgentError::Cancelled)
                        } else {
                            result
                        }
                    },
                    Ok(false) => Err(AgentError::UnsupportedPlatform),
                    Err(error) => Err(error),
                }
            };
            let observed_at_ms = SystemTime::now().duration_since(UNIX_EPOCH).ok().and_then(|value| value.as_millis().try_into().ok());
            if let Some(slot) = self.modules.lock().unwrap_or_else(|error| error.into_inner()).iter_mut().find(|slot| slot.state.id == module && Arc::ptr_eq(&slot.lifetime, &lifetime)) {
                slot.state.observe(&result, observed_at_ms);
            }
            nddev_device_sync_telemetry::finish_operation_span(
                &tracing::Span::current(), query_outcome(&result).terminal_failure(),
            );
            match &result {
                Ok(_) => tracing::info!(event.name = "module.query.completed", module, duration_ms = started.elapsed().as_millis() as u64, outcome = "ok"),
                Err(error) => tracing::warn!(event.name = "module.query.failed", module, duration_ms = started.elapsed().as_millis() as u64, error.type = %error, outcome = "error"),
            }
            result
        }.instrument(nddev_device_sync_telemetry::operation_span(module, "io").map_err(|_| AgentError::InvalidContract)?).await
    }

    fn admitted(&self, module: &str) -> Result<bool, AgentError> {
        let id = ModuleId::new(module).map_err(|_| AgentError::InvalidContract)?;
        let descriptor = self.graph.get(&id).ok_or(AgentError::InvalidContract)?;
        Ok(descriptor.platforms.contains(&self.platform))
    }

    pub async fn system_info(
        &self,
    ) -> Result<nddev_device_sync_sysinfo::view::SystemSnapshot, AgentError> {
        self.observe("sysinfo", |cancellation| async move {
            self.sysinfo
                .as_ref()
                .ok_or(AgentError::Unavailable)?
                .sample(cancellation)
                .await
                .map_err(|error| match error {
                    nddev_device_sync_sysinfo::Error::Io(error) => io_error(error),
                    nddev_device_sync_sysinfo::Error::UnsupportedPlatform => {
                        AgentError::UnsupportedPlatform
                    }
                    _ => AgentError::InvalidResponse,
                })
        })
        .await
    }

    pub async fn clipboard_entries(
        &self,
        before: Option<u64>,
    ) -> Result<nddev_device_sync_clipboard::view::Page, AgentError> {
        self.observe("clipboard", |cancellation| async move {
            self.clipboard
                .as_ref()
                .ok_or(AgentError::Unavailable)?
                .list(before, cancellation)
                .await
                .map_err(clipboard_error)
        })
        .await
    }

    pub async fn clipboard_content(&self, entry: u64, mime: String) -> Result<Vec<u8>, AgentError> {
        self.observe("clipboard", |cancellation| async move {
            self.clipboard
                .as_ref()
                .ok_or(AgentError::Unavailable)?
                .fetch(entry, mime, cancellation)
                .await
                .map_err(clipboard_error)
        })
        .await
    }

    pub async fn cleaner_diagnostics(
        &self,
    ) -> Result<nddev_device_sync_cleaner::view::Diagnostics, AgentError> {
        self.observe("cleaner", |cancellation| async move {
            self.cleaner
                .as_ref()
                .ok_or(AgentError::Unavailable)?
                .diagnose(cancellation)
                .await
                .map_err(cleaner_error)
        })
        .await
    }

    pub async fn cleaner_preview(
        &self,
    ) -> Result<nddev_device_sync_cleaner::view::CleanerRunSummary, AgentError> {
        self.observe("cleaner", |cancellation| async move {
            self.cleaner
                .as_ref()
                .ok_or(AgentError::Unavailable)?
                .preview(cancellation)
                .await
                .map_err(cleaner_error)
        })
        .await
    }

    pub async fn cleaner_last_run(
        &self,
    ) -> Result<nddev_device_sync_cleaner::view::CleanerRunSummary, AgentError> {
        self.observe("cleaner", |cancellation| async move {
            self.cleaner
                .as_ref()
                .ok_or(AgentError::Unavailable)?
                .last_run(cancellation)
                .await
                .map_err(cleaner_error)
        })
        .await
    }

    pub async fn update_plan(&self) -> Result<nddev_device_sync_updater::view::Plan, AgentError> {
        self.observe("updater", |cancellation| async move {
            self.updater
                .as_ref()
                .ok_or(AgentError::Unavailable)?
                .plan(cancellation)
                .await
                .map_err(updater_error)
        })
        .await
    }

    pub async fn update_last_run(
        &self,
    ) -> Result<nddev_device_sync_updater::view::UpdateRunSummary, AgentError> {
        self.observe("updater", |cancellation| async move {
            self.updater
                .as_ref()
                .ok_or(AgentError::Unavailable)?
                .last_run(cancellation)
                .await
                .map_err(updater_error)
        })
        .await
    }

    pub async fn repository_status(
        &self,
        path: &Path,
    ) -> Result<nddev_device_sync_gds::Status, AgentError> {
        self.observe("gds", |cancellation| async move {
            // Fixed sibling and build-embedded digest, never runtime PATH/env.
            bundled_git_worker()?.ok_or(AgentError::Unavailable)?;
            self.gds
                .as_ref()
                .ok_or(AgentError::Unavailable)?
                .status(path, cancellation)
                .await
        })
        .await
    }

    pub async fn remote_sessions(
        &self,
    ) -> Result<nddev_device_sync_rds::view::RemoteSnapshot, AgentError> {
        self.observe("rds", |cancellation| async move {
            self.rds
                .as_ref()
                .ok_or(AgentError::Unavailable)?
                .sessions(cancellation)
                .await
                .map_err(rds_error)
        })
        .await
    }
}

fn io_error(error: IoError) -> AgentError {
    match error {
        IoError::Busy => AgentError::Busy,
        IoError::Unavailable => AgentError::Unavailable,
        IoError::InvalidConfiguration => AgentError::InvalidInput,
        IoError::Timeout => AgentError::Timeout,
        IoError::Cancelled => AgentError::Cancelled,
        IoError::ProviderExit | IoError::Transport => AgentError::ProviderFailed,
        IoError::OutputLimit | IoError::InvalidFrame | IoError::InvalidResponse => {
            AgentError::InvalidResponse
        }
    }
}

fn current_platform() -> Platform {
    if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Windows
    }
}

fn clipboard_error(error: nddev_device_sync_clipboard::Error) -> AgentError {
    match error {
        nddev_device_sync_clipboard::Error::Io(error) => io_error(error),
        nddev_device_sync_clipboard::Error::Protocol => AgentError::InvalidResponse,
        nddev_device_sync_clipboard::Error::Provider => AgentError::ProviderFailed,
    }
}

fn cleaner_error(error: nddev_device_sync_cleaner::Error) -> AgentError {
    match error {
        nddev_device_sync_cleaner::Error::Io(error) => io_error(error),
        nddev_device_sync_cleaner::Error::Protocol => AgentError::InvalidResponse,
        nddev_device_sync_cleaner::Error::UnsupportedPlatform => AgentError::UnsupportedPlatform,
    }
}

fn updater_error(error: nddev_device_sync_updater::Error) -> AgentError {
    match error {
        nddev_device_sync_updater::Error::Io(error) => io_error(error),
        nddev_device_sync_updater::Error::Protocol => AgentError::InvalidResponse,
        nddev_device_sync_updater::Error::UnsupportedPlatform => AgentError::UnsupportedPlatform,
    }
}

fn rds_error(error: nddev_device_sync_rds::Error) -> AgentError {
    match error {
        nddev_device_sync_rds::Error::Io(error) => io_error(error),
        nddev_device_sync_rds::Error::Protocol => AgentError::InvalidResponse,
        nddev_device_sync_rds::Error::UnsupportedPlatform => AgentError::UnsupportedPlatform,
    }
}

fn executable(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path).filter(|path| path.is_absolute()) {
        let candidate = directory.join(if cfg!(windows) {
            format!("{name}.exe")
        } else {
            name.into()
        });
        let Ok(metadata) = candidate.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        return Some(candidate);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn invalidated_work_cannot_restore_observation_or_cancel_another_module() {
        let agent = NativeAgent::discover().unwrap();
        let other = agent
            .modules
            .lock()
            .unwrap()
            .iter()
            .find(|slot| slot.state.id == "clipboard")
            .unwrap()
            .lifetime
            .clone();
        let result = agent
            .observe("sysinfo", |_| async {
                agent.invalidate_module("sysinfo")?;
                Ok(())
            })
            .await;
        assert!(matches!(result, Err(AgentError::Cancelled)));
        assert!(!other.is_cancelled());
        let slots = agent.modules.lock().unwrap();
        let changed = slots
            .iter()
            .find(|slot| slot.state.id == "sysinfo")
            .unwrap();
        assert!(!changed.lifetime.is_cancelled());
        assert!(changed.state.observed_at_ms.is_none());
        assert!(changed.state.reachability == Reachability::NotChecked);
    }

    #[tokio::test]
    async fn unsupported_manifest_platform_is_refused_before_io() {
        let mut agent = NativeAgent::discover().unwrap();
        agent.platform = Platform::Windows;
        let work = std::future::poll_fn(|_| -> std::task::Poll<Result<(), AgentError>> {
            panic!("unsupported manifest platform entered adapter I/O")
        });
        assert!(matches!(
            agent.observe("gds", |_| work).await,
            Err(AgentError::UnsupportedPlatform)
        ));
        let state = agent
            .modules()
            .into_iter()
            .find(|module| module.id == "gds")
            .unwrap();
        assert!(
            state.reachability == Reachability::NotChecked
                && state.observed_at_ms.is_none()
                && state.error.is_none()
        );
    }
}
