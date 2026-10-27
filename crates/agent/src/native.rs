use crate::view::{AgentError, BrowserDocument, BrowserError, ModuleState, Reachability, browser};
use crate::worker::bundled_git_worker;
use nddev_device_sync_adapter_io::{CancellationToken, IoError, NativeIo};
use nddev_device_sync_clipboard::{Clipboard, ReadClipboard};
use nddev_device_sync_domain::{ModuleGraph, ModuleId, Platform, modules::query_outcome};
use nddev_device_sync_sysinfo::{ReadSystemInfo, SystemInfo};
use std::{
    future::Future,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::Instrument;

use nddev_device_sync_browser_use::{
    BrowserUse, BrowserUseClient, OwnedSession,
    protocol::{MAX_SESSIONS, Refusal, valid_project},
};
use nddev_device_sync_cleaner::{Cleaner, ReadCleaner};
use nddev_device_sync_gds::Gds;
use nddev_device_sync_rds::{Rds, ReadRds};
use nddev_device_sync_updater::{ReadUpdater, Updater};

struct ModuleSlot {
    state: ModuleState,
    lifetime: Arc<CancellationToken>,
}

// Private local ownership only: never a UI DTO, synced configuration or log field.
#[derive(Default)]
struct BrowserRegistry {
    entries: Vec<BrowserEntry>,
    denied: bool,
    draining: bool,
    drained: bool,
    calls: usize,
}

struct BrowserEntry {
    project: String,
    identity: Arc<()>,
    handle: Option<OwnedSession>,
    active: usize,
    needs_close: bool,
    close_running: bool,
}

#[derive(Clone, Copy)]
enum BrowserCallKind {
    Acquire,
    Use,
    Close,
}

/// The caller's owner must retain and join the future (Shared uses its existing
/// task primitive). Drop cannot recover a lost reserve/close reply or join I/O.
struct BrowserCall<'a> {
    registry: &'a Mutex<BrowserRegistry>,
    identity: Arc<()>,
    kind: BrowserCallKind,
    completed: bool,
}

impl BrowserCall<'_> {
    fn acquired(
        &mut self,
        result: Result<OwnedSession, BrowserError>,
    ) -> Result<OwnedSession, BrowserError> {
        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let position = registry
            .entries
            .iter()
            .position(|entry| Arc::ptr_eq(&entry.identity, &self.identity))
            .ok_or(BrowserError::InvalidResponse)?;
        match result {
            Ok(handle) => {
                // No await between receiving and retaining this opaque owner handle.
                registry.entries[position].handle = Some(handle.clone());
                self.kind = BrowserCallKind::Use;
                Ok(handle)
            }
            Err(error) => {
                if matches!(&error, BrowserError::Refused(_)) {
                    // Only an actual typed refusal proves that reserve was not granted.
                    registry.entries.remove(position);
                } else {
                    registry.entries[position].needs_close = true;
                }
                self.completed = true;
                Err(error)
            }
        }
    }

    fn finish<T>(mut self, result: Result<T, BrowserError>) -> Result<T, BrowserError> {
        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(position) = registry
            .entries
            .iter()
            .position(|entry| Arc::ptr_eq(&entry.identity, &self.identity))
        {
            if matches!(self.kind, BrowserCallKind::Close) && result.is_ok() {
                // SessionNotFound and a lost ACK are errors, never successful drain.
                registry.entries.remove(position);
            } else if matches!(self.kind, BrowserCallKind::Close)
                || result.as_ref().err().is_some_and(browser_requires_drain)
            {
                registry.entries[position].needs_close = true;
            }
        }
        self.completed = true;
        drop(registry);
        result
    }
}

impl Drop for BrowserCall<'_> {
    fn drop(&mut self) {
        let mut registry = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        registry.calls -= 1;
        if let Some(entry) = registry
            .entries
            .iter_mut()
            .find(|entry| Arc::ptr_eq(&entry.identity, &self.identity))
        {
            entry.active -= 1;
            if matches!(self.kind, BrowserCallKind::Close) {
                entry.close_running = false;
            }
            if !self.completed {
                entry.needs_close = true;
            }
        }
    }
}

impl BrowserRegistry {
    fn begin<'a>(
        registry: &'a Mutex<Self>,
        project: &str,
        kind: BrowserCallKind,
    ) -> Result<(BrowserCall<'a>, Option<OwnedSession>), BrowserError> {
        if !valid_project(project) {
            return Err(Refusal::InvalidProject.into());
        }
        let mut state = registry.lock().unwrap_or_else(|e| e.into_inner());
        if state.denied {
            return Err(Refusal::PermissionRequired.into());
        }
        if !matches!(kind, BrowserCallKind::Close) && state.calls >= MAX_SESSIONS {
            return Err(Refusal::Busy.into());
        }
        let position = match state
            .entries
            .iter()
            .position(|entry| entry.project == project)
        {
            Some(position) => position,
            None if matches!(kind, BrowserCallKind::Acquire) => {
                if state.entries.len() >= MAX_SESSIONS {
                    return Err(Refusal::Capacity.into());
                }
                state.entries.push(BrowserEntry {
                    project: project.into(),
                    identity: Arc::new(()),
                    handle: None,
                    active: 0,
                    needs_close: false,
                    close_running: false,
                });
                state.entries.len() - 1
            }
            None => return Err(Refusal::SessionNotFound.into()),
        };
        Self::begin_at(registry, &mut state, position, kind)
    }

    fn begin_at<'a>(
        registry: &'a Mutex<Self>,
        state: &mut Self,
        position: usize,
        kind: BrowserCallKind,
    ) -> Result<(BrowserCall<'a>, Option<OwnedSession>), BrowserError> {
        // At most one ordinary call per owned session; reserve equally bounded
        // extra capacity for closing those sessions while a caller is pending.
        let limit = if matches!(kind, BrowserCallKind::Close) {
            MAX_SESSIONS * 2
        } else {
            MAX_SESSIONS
        };
        if state.calls >= limit {
            return Err(Refusal::Busy.into());
        }
        let entry = &mut state.entries[position];
        if entry.close_running
            || (!matches!(kind, BrowserCallKind::Close) && (entry.active > 0 || entry.needs_close))
        {
            return Err(Refusal::Busy.into());
        }
        // An earlier reserve with no handle is pending or unknown. Never retry
        // it by project name, even when its original caller was dropped.
        if entry.handle.is_none()
            && (entry.needs_close || entry.active > 0 || !matches!(kind, BrowserCallKind::Acquire))
        {
            return Err(Refusal::Busy.into());
        }
        let kind = if matches!(kind, BrowserCallKind::Acquire) && entry.handle.is_some() {
            BrowserCallKind::Use
        } else {
            kind
        };
        if matches!(kind, BrowserCallKind::Close) {
            entry.needs_close = true;
            entry.close_running = true;
        }
        entry.active += 1;
        state.calls += 1;
        state.drained = false;
        Ok((
            BrowserCall {
                registry,
                identity: entry.identity.clone(),
                kind,
                completed: false,
            },
            entry.handle.clone(),
        ))
    }
}

struct BrowserDrain<'a>(&'a Mutex<BrowserRegistry>);

impl Drop for BrowserDrain<'_> {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).draining = false;
    }
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
    browser: Option<BrowserUseClient>,
    browser_registry: Mutex<BrowserRegistry>,
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
        // Construct the typed port only; discovery performs no browser RPC.
        let browser = supported("browser-use")
            .then(|| BrowserUseClient::for_current_user(io.local_handle()).ok())
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
                        "browser-use" => browser.is_some(),
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
            browser,
            // Provider discovery grants no browser attempt. Shared explicitly
            // validates configuration, drains, then resumes this composition.
            browser_registry: Mutex::new(BrowserRegistry {
                denied: true,
                ..Default::default()
            }),
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

    /// Deny new browser calls and cancel only this module. This is intent, not
    /// a drain ACK; owned handles and unknown acquisition results stay retained.
    pub fn cancel_browser(&self) {
        let mut registry = self
            .browser_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        registry.denied = true;
        registry.drained = false;
        if let Some(slot) = self
            .modules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter_mut()
            .find(|slot| slot.state.id == "browser-use")
        {
            slot.lifetime.cancel();
            slot.state.reachability = Reachability::NotChecked;
            slot.state.observed_at_ms = None;
            slot.state.error = None;
        }
    }

    /// Composition-only boundary. Shared must retain this Agent and its owned
    /// request tasks, then join their results. Pending/lost reserve replies keep
    /// drain unresolved; project names or SessionNotFound never substitute ACKs.
    /// Every captured known handle is attempted, even after an earlier failure.
    pub async fn drain_browser(&self) -> Result<(), BrowserError> {
        self.drain_browser_with(|handle| async move {
            // Cleanup is independent of the canceled normal-call token.
            match &self.browser {
                Some(browser) => {
                    browser
                        .close_owned(&handle, false, CancellationToken::new())
                        .await
                }
                None => Err(BrowserError::Io(IoError::Unavailable)),
            }
        })
        .await
    }

    async fn drain_browser_with<F, C>(&self, close: C) -> Result<(), BrowserError>
    where
        F: Future<Output = Result<(), BrowserError>>,
        C: Fn(OwnedSession) -> F,
    {
        self.cancel_browser();
        let identities = {
            let mut registry = self
                .browser_registry
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if registry.draining {
                return Err(Refusal::Busy.into());
            }
            registry.draining = true;
            registry
                .entries
                .iter()
                .map(|entry| entry.identity.clone())
                .collect::<Vec<_>>()
        };
        let _drain = BrowserDrain(&self.browser_registry);
        let mut failure = None;
        for identity in identities {
            let call = {
                let mut registry = self
                    .browser_registry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                registry
                    .entries
                    .iter()
                    .position(|entry| Arc::ptr_eq(&entry.identity, &identity))
                    .ok_or_else(|| BrowserError::from(Refusal::Busy))
                    .and_then(|position| {
                        BrowserRegistry::begin_at(
                            &self.browser_registry,
                            &mut registry,
                            position,
                            BrowserCallKind::Close,
                        )
                    })
            };
            let result = match call {
                Ok((call, Some(handle))) => call.finish(close(handle).await),
                Ok((call, None)) => call.finish(Err(Refusal::Busy.into())),
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
        }
        let mut registry = self
            .browser_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if failure.is_none() && (!registry.entries.is_empty() || registry.calls != 0) {
            failure = Some(Refusal::Busy.into());
        }
        registry.drained = failure.is_none();
        failure.map_or(Ok(()), Err)
    }

    /// Explicit new module lifetime, after Shared validates identity/Vault
    /// configuration. A successful empty drain is necessary; this is no consent
    /// grant, host restart, session adoption or automatic reopen.
    pub fn resume_browser(&self) -> Result<(), BrowserError> {
        let mut registry = self
            .browser_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.cancellation.is_cancelled() {
            return Err(BrowserError::Io(IoError::Cancelled));
        }
        if !registry.denied
            || !registry.drained
            || registry.draining
            || registry.calls != 0
            || !registry.entries.is_empty()
        {
            return Err(Refusal::Busy.into());
        }
        if self.browser.is_none() {
            return Err(BrowserError::Io(IoError::Unavailable));
        }
        let mut slots = self.modules.lock().unwrap_or_else(|e| e.into_inner());
        let slot = slots
            .iter_mut()
            .find(|slot| slot.state.id == "browser-use")
            .ok_or(BrowserError::InvalidResponse)?;
        slot.lifetime = Arc::new(CancellationToken::new());
        registry.denied = false;
        registry.drained = false;
        Ok(())
    }

    fn browser_port(&self) -> Result<&BrowserUseClient, BrowserError> {
        if self
            .browser_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .denied
        {
            return Err(Refusal::PermissionRequired.into());
        }
        self.browser
            .as_ref()
            .ok_or(BrowserError::Io(IoError::Unavailable))
    }

    async fn observe_browser<T, F: Future<Output = Result<T, BrowserError>>>(
        &self,
        work: impl FnOnce(CancellationToken) -> F,
    ) -> Result<T, BrowserError> {
        self.observe_mapped("browser-use", work, browser_gate_error, browser_observation)
            .await
    }

    pub async fn browser_status(&self) -> Result<browser::Status, BrowserError> {
        self.observe_browser(|cancellation| async move {
            self.browser_port()?.status(cancellation).await
        })
        .await
    }

    /// Per-user host metadata; this list grants no ownership of its sessions.
    pub async fn browser_sessions(&self) -> Result<Vec<browser::Session>, BrowserError> {
        self.observe_browser(|cancellation| async move {
            self.browser_port()?.sessions(cancellation).await
        })
        .await
    }

    pub async fn browser_open(&self, project: &str) -> Result<browser::Session, BrowserError> {
        self.observe_browser(|cancellation| async move {
            let browser = self.browser_port()?;
            let (mut call, handle) =
                BrowserRegistry::begin(&self.browser_registry, project, BrowserCallKind::Acquire)?;
            let handle = match handle {
                Some(handle) => handle,
                None => call.acquired(browser.create_owned(project, cancellation.clone()).await)?,
            };
            // Retention precedes this check and the next await. Revocation while
            // reserve was completing must not open the returned reservation.
            if cancellation.is_cancelled()
                || self
                    .browser_registry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .denied
            {
                return call.finish(Err(BrowserError::Io(IoError::Cancelled)));
            }
            call.finish(browser.open_owned(&handle, cancellation).await)
        })
        .await
    }

    pub async fn browser_execute(
        &self,
        project: &str,
        code: &str,
        timeout: Duration,
        expect: Option<BrowserDocument>,
    ) -> Result<browser::Outcome, BrowserError> {
        self.observe_browser(|cancellation| async move {
            let browser = self.browser_port()?;
            let (call, handle) =
                BrowserRegistry::begin(&self.browser_registry, project, BrowserCallKind::Use)?;
            let handle = handle.ok_or(BrowserError::InvalidResponse)?;
            call.finish(
                browser
                    .execute_owned(&handle, code, timeout, expect, cancellation)
                    .await,
            )
        })
        .await
    }

    pub async fn browser_close(&self, project: &str, close_tabs: bool) -> Result<(), BrowserError> {
        self.observe_browser(|cancellation| async move {
            let browser = self.browser_port()?;
            let (call, handle) =
                BrowserRegistry::begin(&self.browser_registry, project, BrowserCallKind::Close)?;
            let handle = handle.ok_or(BrowserError::InvalidResponse)?;
            call.finish(browser.close_owned(&handle, close_tabs, cancellation).await)
        })
        .await
    }

    /// Invalidate only this module's owned requests and stale observations.
    pub fn invalidate_module(&self, module: &str) -> Result<(), AgentError> {
        if module == "browser-use" {
            self.cancel_browser();
            return Ok(());
        }
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
        self.cancel_browser();
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
        self.observe_mapped(module, work, |error| error, |error| *error)
            .await
    }

    async fn observe_mapped<T, E, F: Future<Output = Result<T, E>>>(
        &self,
        module: &'static str,
        work: impl FnOnce(CancellationToken) -> F,
        from_gate: fn(AgentError) -> E,
        project: fn(&E) -> AgentError,
    ) -> Result<T, E> {
        async {
            let started = Instant::now();
            let lifetime = self.modules.lock().unwrap_or_else(|e| e.into_inner()).iter()
                .find(|slot| slot.state.id == module).map(|slot| slot.lifetime.clone())
                .ok_or_else(|| from_gate(AgentError::InvalidContract))?;
            let result = if self.cancellation.is_cancelled() {
                Err(from_gate(AgentError::Cancelled))
            } else {
                match self.admitted(module) {
                    Ok(true) => {
                        let result = work(lifetime.as_ref().clone()).await;
                        if self.cancellation.is_cancelled() || lifetime.is_cancelled() {
                            Err(from_gate(AgentError::Cancelled))
                        } else {
                            result
                        }
                    },
                    Ok(false) => Err(from_gate(AgentError::UnsupportedPlatform)),
                    Err(error) => Err(from_gate(error)),
                }
            };
            let observation = result.as_ref().map(|_| ()).map_err(project);
            let observed_at_ms = SystemTime::now().duration_since(UNIX_EPOCH).ok().and_then(|value| value.as_millis().try_into().ok());
            if let Some(slot) = self.modules.lock().unwrap_or_else(|error| error.into_inner()).iter_mut().find(|slot| slot.state.id == module && Arc::ptr_eq(&slot.lifetime, &lifetime)) {
                slot.state.observe(&observation, observed_at_ms);
            }
            nddev_device_sync_telemetry::finish_operation_span(
                &tracing::Span::current(), query_outcome(&observation).terminal_failure(),
            );
            match &observation {
                Ok(_) => tracing::info!(event.name = "module.query.completed", module, duration_ms = started.elapsed().as_millis() as u64, outcome = "ok"),
                Err(error) => tracing::warn!(event.name = "module.query.failed", module, duration_ms = started.elapsed().as_millis() as u64, error.type = %error, outcome = "error"),
            }
            result
        }.instrument(nddev_device_sync_telemetry::operation_span(module, "io").map_err(|_| from_gate(AgentError::InvalidContract))?).await
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
    io_error_ref(&error)
}

fn io_error_ref(error: &IoError) -> AgentError {
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

fn browser_gate_error(error: AgentError) -> BrowserError {
    match error {
        AgentError::UnsupportedPlatform => BrowserError::UnsupportedPlatform,
        AgentError::Unavailable => IoError::Unavailable.into(),
        AgentError::Busy => Refusal::Busy.into(),
        AgentError::InvalidInput => Refusal::InvalidRequest.into(),
        AgentError::Timeout => IoError::Timeout.into(),
        AgentError::Cancelled => IoError::Cancelled.into(),
        AgentError::ProviderFailed => IoError::Transport.into(),
        AgentError::InvalidResponse | AgentError::InvalidContract => BrowserError::InvalidResponse,
    }
}

/// Coarse observation only; the public result retains the exact owner error.
fn browser_observation(error: &BrowserError) -> AgentError {
    match error {
        BrowserError::Io(error) => io_error_ref(error),
        BrowserError::InvalidResponse => AgentError::InvalidResponse,
        BrowserError::UnsupportedPlatform => AgentError::UnsupportedPlatform,
        BrowserError::Refused(refusal) => match refusal {
            Refusal::Busy | Refusal::Capacity => AgentError::Busy,
            Refusal::ExtensionUnavailable | Refusal::ExecutorUnavailable => AgentError::Unavailable,
            Refusal::Timeout => AgentError::Timeout,
            Refusal::PayloadLimit => AgentError::InvalidResponse,
            Refusal::PermissionRequired
            | Refusal::SessionNotFound
            | Refusal::InvalidProject
            | Refusal::InvalidRequest
            | Refusal::TargetClosed
            | Refusal::StaleDocument => AgentError::InvalidInput,
        },
    }
}

fn browser_requires_drain(error: &BrowserError) -> bool {
    matches!(
        error,
        BrowserError::Io(_)
            | BrowserError::InvalidResponse
            | BrowserError::Refused(
                Refusal::Timeout
                    | Refusal::ExtensionUnavailable
                    | Refusal::ExecutorUnavailable
                    | Refusal::SessionNotFound
            )
    )
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

    fn browser_agent() -> NativeAgent {
        // An explicitly admitted synthetic composition. No discovery, provider
        // calls, browser sockets, executor or runtime tasks.
        let graph = crate::module_graph().unwrap();
        let modules = graph
            .iter()
            .map(|descriptor| ModuleSlot {
                state: ModuleState {
                    id: descriptor.id.as_str().into(),
                    version: descriptor.version.clone(),
                    configured: true,
                    reachability: Reachability::NotChecked,
                    observed_at_ms: None,
                    error: None,
                },
                lifetime: Arc::new(CancellationToken::new()),
            })
            .collect();
        NativeAgent {
            modules: Mutex::new(modules),
            graph,
            platform: current_platform(),
            cancellation: CancellationToken::new(),
            sysinfo: None,
            clipboard: None,
            cleaner: None,
            updater: None,
            gds: None,
            rds: None,
            browser: Some(
                BrowserUseClient::new(
                    NativeIo::new(1).unwrap().local_handle(),
                    std::env::temp_dir().join("unopened-agent-browser-unit.sock"),
                )
                .unwrap(),
            ),
            browser_registry: Mutex::default(),
        }
    }

    fn handle(project: &str, generation: &str) -> OwnedSession {
        // Synthetic private wire values, never used for browser I/O.
        serde_json::from_value(serde_json::json!({"project": project, "generation": generation}))
            .unwrap()
    }

    fn retain(registry: &Mutex<BrowserRegistry>, project: &str, handle: OwnedSession) {
        let (mut call, none) =
            BrowserRegistry::begin(registry, project, BrowserCallKind::Acquire).unwrap();
        assert!(none.is_none());
        assert_eq!(call.acquired(Ok(handle.clone())).unwrap(), handle);
        call.finish(Ok(())).unwrap();
    }

    #[tokio::test]
    async fn discovery_does_not_admit_a_browser_call_before_explicit_composition_resume() {
        let agent = NativeAgent::discover().unwrap();
        assert!(agent.browser_registry.lock().unwrap().denied);
        assert_eq!(
            agent.browser_status().await.err(),
            Some(Refusal::PermissionRequired.into())
        );
        assert_eq!(agent.resume_browser().err(), Some(Refusal::Busy.into()));
        let state = agent
            .modules()
            .into_iter()
            .find(|module| module.id == "browser-use")
            .unwrap();
        assert!(state.reachability == Reachability::NotChecked && state.observed_at_ms.is_none());
    }

    #[tokio::test]
    async fn browser_refusals_remain_lossless_without_manufacturing_provider_health() {
        let agent = browser_agent();
        for refusal in [
            Refusal::PermissionRequired,
            Refusal::StaleDocument,
            Refusal::TargetClosed,
            Refusal::InvalidProject,
            Refusal::InvalidRequest,
            Refusal::SessionNotFound,
            Refusal::Busy,
            Refusal::Capacity,
        ] {
            let result = agent
                .observe_browser(|_| async { Err::<(), _>(BrowserError::Refused(refusal)) })
                .await;
            assert_eq!(result.err(), Some(BrowserError::Refused(refusal)));
        }
        let state = agent
            .modules()
            .into_iter()
            .find(|module| module.id == "browser-use")
            .unwrap();
        assert!(state.observed_at_ms.is_none() && state.error.is_none());
        assert!(state.reachability == Reachability::NotChecked);
        assert_eq!(
            browser_observation(&IoError::Cancelled.into()),
            AgentError::Cancelled
        );
        assert_eq!(
            browser_observation(&Refusal::Timeout.into()),
            AgentError::Timeout
        );
    }

    #[test]
    fn acquisition_intent_survives_drop_and_only_explicit_refusal_releases_it() {
        let registry = Mutex::new(BrowserRegistry::default());
        let (call, _) =
            BrowserRegistry::begin(&registry, "lost", BrowserCallKind::Acquire).unwrap();
        drop(call);
        assert!(matches!(
            BrowserRegistry::begin(&registry, "lost", BrowserCallKind::Acquire),
            Err(BrowserError::Refused(Refusal::Busy))
        ));
        let (mut call, _) =
            BrowserRegistry::begin(&registry, "refused", BrowserCallKind::Acquire).unwrap();
        assert_eq!(
            call.acquired(Err(Refusal::PermissionRequired.into())).err(),
            Some(Refusal::PermissionRequired.into())
        );
        drop(call);
        let (mut call, _) =
            BrowserRegistry::begin(&registry, "unknown", BrowserCallKind::Acquire).unwrap();
        assert_eq!(
            call.acquired(Err(IoError::Transport.into())).err(),
            Some(IoError::Transport.into())
        );
        drop(call);
        let state = registry.lock().unwrap();
        assert_eq!(state.calls, 0);
        assert_eq!(state.entries.len(), 2);
        assert!(
            state
                .entries
                .iter()
                .all(|entry| entry.needs_close && entry.handle.is_none())
        );
    }

    #[tokio::test]
    async fn dropped_reserve_holds_drain_and_explicit_resume_without_guessing_a_session() {
        let agent = browser_agent();
        let (call, _) =
            BrowserRegistry::begin(&agent.browser_registry, "lost", BrowserCallKind::Acquire)
                .unwrap();
        drop(call);
        let called = std::sync::atomic::AtomicBool::new(false);
        assert_eq!(
            agent
                .drain_browser_with(|_| {
                    called.store(true, std::sync::atomic::Ordering::Relaxed);
                    async { Ok(()) }
                })
                .await
                .err(),
            Some(Refusal::Busy.into())
        );
        assert!(!called.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(agent.resume_browser().err(), Some(Refusal::Busy.into()));
        assert!(agent.browser_registry.lock().unwrap().denied);
    }

    #[tokio::test]
    async fn late_reserve_retains_handle_after_revoke_and_drain_attempts_every_known_owner() {
        let agent = browser_agent();
        let first = handle("first", "one");
        let later = handle("later", "two");
        let foreign = handle("foreign", "foreign");
        retain(&agent.browser_registry, "first", first.clone());
        let (mut late, _) =
            BrowserRegistry::begin(&agent.browser_registry, "later", BrowserCallKind::Acquire)
                .unwrap();
        agent.cancel_browser();
        assert_eq!(late.acquired(Ok(later.clone())).unwrap(), later);
        drop(late); // No open call: the known handle remains drainable.
        let attempts = Mutex::new(Vec::new());
        let result = agent
            .drain_browser_with(|owned| {
                attempts.lock().unwrap().push(owned.clone());
                let first = first.clone();
                async move {
                    if owned == first {
                        Err(IoError::Transport.into())
                    } else {
                        Ok(())
                    }
                }
            })
            .await;
        assert_eq!(result.err(), Some(IoError::Transport.into()));
        assert_eq!(*attempts.lock().unwrap(), [first.clone(), later]);
        assert!(!attempts.lock().unwrap().contains(&foreign));
        let state = agent.browser_registry.lock().unwrap();
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.entries[0].handle.as_ref(), Some(&first));
        assert!(state.denied && !state.drained && !state.draining);
        drop(state);
        assert_eq!(agent.resume_browser().err(), Some(Refusal::Busy.into()));
    }

    #[test]
    fn foreign_projects_and_missing_close_ack_cannot_forget_or_adopt_owned_handles() {
        let registry = Mutex::new(BrowserRegistry::default());
        let own = handle("owned", "one");
        retain(&registry, "owned", own.clone());
        for kind in [BrowserCallKind::Use, BrowserCallKind::Close] {
            assert!(matches!(
                BrowserRegistry::begin(&registry, "foreign", kind),
                Err(BrowserError::Refused(Refusal::SessionNotFound))
            ));
        }
        let (call, handle) =
            BrowserRegistry::begin(&registry, "owned", BrowserCallKind::Close).unwrap();
        assert_eq!(handle.as_ref(), Some(&own));
        assert_eq!(
            call.finish(Err::<(), _>(Refusal::SessionNotFound.into()))
                .err(),
            Some(Refusal::SessionNotFound.into())
        );
        assert_eq!(
            registry.lock().unwrap().entries[0].handle.as_ref(),
            Some(&own)
        );
        assert!(matches!(
            BrowserRegistry::begin(&registry, "owned", BrowserCallKind::Use),
            Err(BrowserError::Refused(Refusal::Busy))
        ));
        let (call, _) = BrowserRegistry::begin(&registry, "owned", BrowserCallKind::Close).unwrap();
        drop(call); // A dropped close reply remains HOLD too.
        assert_eq!(
            registry.lock().unwrap().entries[0].handle.as_ref(),
            Some(&own)
        );
        let (call, _) = BrowserRegistry::begin(&registry, "owned", BrowserCallKind::Close).unwrap();
        call.finish(Ok(())).unwrap();
        assert!(registry.lock().unwrap().entries.is_empty());
    }

    #[tokio::test]
    async fn successful_close_still_requires_caller_join_before_empty_drain_and_resume() {
        let agent = browser_agent();
        retain(&agent.browser_registry, "owned", handle("owned", "one"));
        let (pending, _) =
            BrowserRegistry::begin(&agent.browser_registry, "owned", BrowserCallKind::Use).unwrap();
        assert_eq!(
            agent.drain_browser_with(|_| async { Ok(()) }).await.err(),
            Some(Refusal::Busy.into())
        );
        assert!(agent.browser_registry.lock().unwrap().entries.is_empty());
        assert_eq!(agent.resume_browser().err(), Some(Refusal::Busy.into()));
        drop(pending);
        agent
            .drain_browser_with(|_| async { panic!("empty drain issued another close") })
            .await
            .unwrap();
        assert!(agent.browser_registry.lock().unwrap().denied);
        agent.resume_browser().unwrap();
    }

    #[tokio::test]
    async fn browser_revoke_requires_explicit_resume_and_never_reopens_a_global_close() {
        let agent = browser_agent();
        let lifetime = |id: &str| {
            agent
                .modules
                .lock()
                .unwrap()
                .iter()
                .find(|slot| slot.state.id == id)
                .unwrap()
                .lifetime
                .clone()
        };
        let old = lifetime("browser-use");
        let clipboard = lifetime("clipboard");
        agent.invalidate_module("browser-use").unwrap();
        assert!(old.is_cancelled() && !clipboard.is_cancelled());
        assert!(Arc::ptr_eq(&old, &lifetime("browser-use")));
        assert_eq!(agent.resume_browser().err(), Some(Refusal::Busy.into()));
        agent.drain_browser().await.unwrap(); // Empty registry: no I/O.
        assert!(old.is_cancelled() && agent.browser_registry.lock().unwrap().denied);
        agent.resume_browser().unwrap();
        assert!(!Arc::ptr_eq(&old, &lifetime("browser-use")));
        assert!(!lifetime("browser-use").is_cancelled() && !clipboard.is_cancelled());
        assert_eq!(agent.resume_browser().err(), Some(Refusal::Busy.into()));
        agent.close();
        agent.drain_browser().await.unwrap();
        assert_eq!(
            agent.resume_browser().err(),
            Some(IoError::Cancelled.into())
        );
    }

    #[test]
    fn registry_is_bounded_and_late_old_call_cannot_change_a_new_generation() {
        let registry = Mutex::new(BrowserRegistry::default());
        for index in 0..MAX_SESSIONS {
            let project = format!("owned-{index}");
            retain(&registry, &project, handle(&project, "one"));
        }
        assert!(matches!(
            BrowserRegistry::begin(&registry, "overflow", BrowserCallKind::Acquire),
            Err(BrowserError::Refused(Refusal::Capacity))
        ));
        let (old, _) = BrowserRegistry::begin(&registry, "owned-0", BrowserCallKind::Use).unwrap();
        let (close, _) =
            BrowserRegistry::begin(&registry, "owned-0", BrowserCallKind::Close).unwrap();
        close.finish(Ok(())).unwrap();
        let new = handle("owned-0", "replacement");
        retain(&registry, "owned-0", new.clone());
        drop(old);
        let state = registry.lock().unwrap();
        let entry = state
            .entries
            .iter()
            .find(|entry| entry.project == "owned-0")
            .unwrap();
        assert_eq!(entry.handle.as_ref(), Some(&new));
        assert!(!entry.needs_close && entry.active == 0 && state.calls == 0);
    }

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
