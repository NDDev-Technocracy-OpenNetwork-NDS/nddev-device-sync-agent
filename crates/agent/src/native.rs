use crate::view::{
    AgentError, BrowserDocument, BrowserError, CacheError, ModuleState, Reachability, browser,
    cache,
};
use crate::worker::bundled_git_worker;
use nddev_device_sync_adapter_io::{CancellationToken, IoError, NativeIo};
use nddev_device_sync_cache_client::binding::Base as CacheBase;
#[cfg(target_os = "linux")]
use nddev_device_sync_cache_client::{Client as CacheClient, NetworkCache, Scope as CacheScope};
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
use nddev_device_sync_github::Github;
use nddev_device_sync_remote::{ReadRemote, Remote};
use nddev_device_sync_updater::{ReadUpdater, Updater};

struct ModuleSlot {
    state: ModuleState,
    lifetime: Arc<CancellationToken>,
}

#[cfg(target_os = "linux")]
#[derive(Default, PartialEq, Eq)]
enum CacheMutationState {
    #[default]
    Idle,
    Running,
    Unknown,
    PublishingStatus,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct CacheMutationSlot {
    state: CacheMutationState,
    generation: Arc<()>,
}

/// An admitted mutation must be retained and joined by its composition owner.
/// Dropping LocalIo's future does not join its blocking worker: never reopen
/// this slot merely because an awaiter disappeared or a lifetime was revoked.
#[cfg(target_os = "linux")]
struct CacheMutation<'a> {
    slot: &'a Mutex<CacheMutationSlot>,
    completed: bool,
}

#[cfg(target_os = "linux")]
impl<'a> CacheMutation<'a> {
    fn begin(slot: &'a Mutex<CacheMutationSlot>) -> Result<Self, AgentError> {
        let mut state = slot.lock().unwrap_or_else(|error| error.into_inner());
        if state.state != CacheMutationState::Idle {
            return Err(AgentError::Busy);
        }
        state.generation = Arc::new(());
        state.state = CacheMutationState::Running;
        Ok(Self {
            slot,
            completed: false,
        })
    }

    fn finish(mut self, result: &Result<cache::Status, CacheError>) {
        // The concrete cache client's LocalIo maps a blocking worker JoinError
        // to Transport. Its effect is unresolved, unlike a returned Uncertain:
        // that is a known completed owner result saying files may have changed.
        self.slot
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .state = if matches!(result, Err(CacheError::Io(IoError::Transport))) {
            CacheMutationState::Unknown
        } else {
            CacheMutationState::Idle
        };
        self.completed = true;
    }
}

#[cfg(target_os = "linux")]
impl Drop for CacheMutation<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.slot
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .state = CacheMutationState::Unknown;
        }
    }
}

/// The generation fences the complete local status I/O interval. A short
/// logical lease after I/O also closes the check -> observer/publication race;
/// no std MutexGuard crosses an await. This is not an external-process lock.
#[cfg(target_os = "linux")]
struct CacheStatusPublication<'a> {
    slot: &'a Mutex<CacheMutationSlot>,
    generation: Arc<()>,
}

#[cfg(target_os = "linux")]
impl<'a> CacheStatusPublication<'a> {
    fn begin(slot: &'a Mutex<CacheMutationSlot>, generation: Arc<()>) -> Result<Self, CacheError> {
        let mut state = slot.lock().unwrap_or_else(|error| error.into_inner());
        if state.state != CacheMutationState::Idle || !Arc::ptr_eq(&state.generation, &generation) {
            return Err(CacheError::Busy);
        }
        state.state = CacheMutationState::PublishingStatus;
        Ok(Self { slot, generation })
    }
}

#[cfg(target_os = "linux")]
impl Drop for CacheStatusPublication<'_> {
    fn drop(&mut self) {
        let mut state = self.slot.lock().unwrap_or_else(|error| error.into_inner());
        if state.state == CacheMutationState::PublishingStatus
            && Arc::ptr_eq(&state.generation, &self.generation)
        {
            state.state = CacheMutationState::Idle;
        }
    }
}

#[cfg(target_os = "linux")]
struct CacheRead<'a> {
    result: Result<cache::Status, CacheError>,
    _publication: CacheStatusPublication<'a>,
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
                if matches!(
                    &error,
                    BrowserError::Refused(_) | BrowserError::Io(IoError::Busy)
                ) {
                    // A typed host refusal or LocalIo's pre-worker admission
                    // refusal proves that no reservation was granted.
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
    github: Option<Github>,
    remote: Option<Remote>,
    browser: Option<BrowserUseClient>,
    browser_registry: Mutex<BrowserRegistry>,
    #[cfg(target_os = "linux")]
    cache: Option<CacheClient>,
    #[cfg(target_os = "linux")]
    cache_mutation: Mutex<CacheMutationSlot>,
}

impl Drop for NativeAgent {
    fn drop(&mut self) {
        self.close();
    }
}

impl NativeAgent {
    pub fn discover() -> Result<Self, AgentError> {
        Self::discover_with_cache_base(None)
    }

    /// The cache base is supplied by the per-host assembly, never discovered,
    /// defaulted or synchronized as user intent. None says nothing about any
    /// durable binding previously installed in this OS user's tool files.
    pub fn discover_with_cache_base(cache_port: Option<u16>) -> Result<Self, AgentError> {
        // Validate before any Scope/discovery/probe can run.
        let cache_base = validated_cache_base(cache_port)?;
        #[cfg(not(target_os = "linux"))]
        if cache_base.is_some() {
            return Err(AgentError::UnsupportedPlatform);
        }
        let graph = crate::module_graph()?;
        let platform = current_platform();
        let supported = |id: &str| {
            graph
                .iter()
                .find(|descriptor| descriptor.id.as_str() == id)
                .is_some_and(|descriptor| descriptor.platforms.contains(&platform))
        };
        let io = NativeIo::new(8).map_err(io_error)?;
        #[cfg(target_os = "linux")]
        let cache = configured_cache(io.local_handle(), cache_base, CacheScope::user)?;
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
        let github = if supported("github") {
            bundled_git_worker()?
                .map(|path| {
                    Github::new(
                        io.process_handle(),
                        path,
                        std::time::Duration::from_secs(12),
                    )
                })
                .transpose()?
        } else {
            None
        };
        let remote = if supported("remote") {
            executable("rds")
                .map(|path| Remote::new(io.process_handle(), path, None))
                .transpose()
                .map_err(remote_error)?
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
                        "github" => github.is_some(),
                        "remote" => remote.is_some(),
                        "browser-use" => browser.is_some(),
                        "cache" => {
                            #[cfg(target_os = "linux")]
                            {
                                cache.is_some()
                            }
                            #[cfg(not(target_os = "linux"))]
                            {
                                false
                            }
                        }
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
            github,
            remote,
            browser,
            // Provider discovery grants no browser attempt. Shared explicitly
            // validates configuration, drains, then resumes this composition.
            browser_registry: Mutex::new(BrowserRegistry {
                denied: true,
                ..Default::default()
            }),
            #[cfg(target_os = "linux")]
            cache,
            #[cfg(target_os = "linux")]
            cache_mutation: Mutex::default(),
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

    /// Read-only observation of the supplied base and this user's managed
    /// content. Neither marker presence nor HTTP 200 authenticates a remote-module route
    /// or proves that the content names this port. This never binds/unbinds.
    pub async fn cache_status(&self) -> Result<cache::Status, CacheError> {
        #[cfg(target_os = "linux")]
        {
            self.observe_mapped(
                "cache",
                |cancellation| async move {
                    let generation = {
                        let slot = self
                            .cache_mutation
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        if slot.state != CacheMutationState::Idle {
                            return Err(CacheError::Busy);
                        }
                        slot.generation.clone()
                    };
                    let result = match &self.cache {
                        Some(cache) => cache.status(cancellation).await,
                        None => Err(CacheError::Io(IoError::Unavailable)),
                    };
                    // Retain the lease for BOTH provider success and refusal,
                    // through the unchanged observer and final result handoff.
                    let publication =
                        CacheStatusPublication::begin(&self.cache_mutation, generation)?;
                    Ok(CacheRead {
                        result,
                        _publication: publication,
                    })
                },
                cache_gate_error,
                cache_observation,
                |read| match &read.result {
                    Ok(status) => cache_success(status),
                    Err(error) => Err(cache_observation(error)),
                },
            )
            .await?
            .result
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.observe_mapped(
                "cache",
                |_| async { Err(CacheError::UnsupportedPlatform) },
                cache_gate_error,
                cache_observation,
                cache_success,
            )
            .await
        }
    }

    /// Explicitly bind this user's tools to the supplied cache base. Once
    /// admitted, retain/join this future even after revocation or caller loss.
    /// A later cancellation observation cannot mean that no files changed.
    pub async fn cache_bind(&self) -> Result<cache::Status, CacheError> {
        self.mutate_cache(true).await
    }

    /// Explicitly remove only the owning client's managed bindings. Shutdown,
    /// logout and revoke never call this or imply that direct mode was restored.
    pub async fn cache_unbind(&self) -> Result<cache::Status, CacheError> {
        self.mutate_cache(false).await
    }

    async fn mutate_cache(&self, bind: bool) -> Result<cache::Status, CacheError> {
        #[cfg(target_os = "linux")]
        {
            self.cache_mutation_with(|cancellation| async move {
                let cache = self
                    .cache
                    .as_ref()
                    .ok_or(CacheError::Io(IoError::Unavailable))?;
                if bind {
                    cache.bind(cancellation).await
                } else {
                    cache.unbind(cancellation).await
                }
            })
            .await
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = bind;
            self.observe_mapped(
                "cache",
                |_| async { Err(CacheError::UnsupportedPlatform) },
                cache_gate_error,
                cache_observation,
                cache_success,
            )
            .await
        }
    }

    #[cfg(target_os = "linux")]
    async fn cache_mutation_with<F>(
        &self,
        work: impl FnOnce(CancellationToken) -> F,
    ) -> Result<cache::Status, CacheError>
    where
        F: Future<Output = Result<cache::Status, CacheError>>,
    {
        // A result cell, not a second observer: the unchanged query kernel owns
        // admission/observation/telemetry, including its post-cancel masking.
        // Keep the exact non-Clone provider result before that masking occurs.
        let effect = Mutex::new(None);
        let completed = &effect;
        let observation = self
            .observe_mapped(
                "cache",
                |lifetime| async move {
                    let call = CacheMutation::begin(&self.cache_mutation)?;
                    if self.cancellation.is_cancelled() || lifetime.is_cancelled() {
                        call.finish(&Err(CacheError::Io(IoError::Cancelled)));
                        return Err(AgentError::Cancelled);
                    }
                    // Fresh only AFTER admission. The owner must retain/join
                    // the call; this token is not a dropped-task recovery tool.
                    let result = work(CancellationToken::new()).await;
                    let observed = match &result {
                        Ok(status) => cache_success(status),
                        Err(error) => Err(cache_observation(error)),
                    };
                    call.finish(&result);
                    *completed.lock().unwrap_or_else(|error| error.into_inner()) = Some(result);
                    observed
                },
                |error| error,
                |error| *error,
                |_| Ok(()),
            )
            .await;
        let effect = effect
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        effect.unwrap_or_else(|| {
            Err(cache_gate_error(
                observation.err().unwrap_or(AgentError::InvalidResponse),
            ))
        })
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
        self.observe_mapped(
            "browser-use",
            work,
            browser_gate_error,
            browser_observation,
            |_| Ok(()),
        )
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
                // Finish this already-admitted bounded reservation so revoke
                // cannot discard its handle. The normal lifetime still gates
                // every subsequent open/execute attempt below.
                None => call.acquired(
                    browser
                        .create_owned(project, CancellationToken::new())
                        .await,
                )?,
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
        self.observe_browser(|_| async move {
            let browser = self.browser_port()?;
            let (call, handle) =
                BrowserRegistry::begin(&self.browser_registry, project, BrowserCallKind::Close)?;
            let handle = handle.ok_or(BrowserError::InvalidResponse)?;
            // Retain the actual bounded cleanup ACK across normal revocation.
            // The owning task must still be kept/joined; dropping it is unknown.
            call.finish(
                browser
                    .close_owned(&handle, close_tabs, CancellationToken::new())
                    .await,
            )
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
        self.observe_mapped(module, work, |error| error, |error| *error, |_| Ok(()))
            .await
    }

    async fn observe_mapped<T, E, F: Future<Output = Result<T, E>>>(
        &self,
        module: &'static str,
        work: impl FnOnce(CancellationToken) -> F,
        from_gate: fn(AgentError) -> E,
        project: fn(&E) -> AgentError,
        success: fn(&T) -> Result<(), AgentError>,
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
            let observation = match &result {
                Ok(value) => success(value),
                Err(error) => Err(project(error)),
            };
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
    ) -> Result<nddev_device_sync_github::Status, AgentError> {
        self.observe("github", |cancellation| async move {
            // Fixed sibling and build-embedded digest, never runtime PATH/env.
            bundled_git_worker()?.ok_or(AgentError::Unavailable)?;
            self.github
                .as_ref()
                .ok_or(AgentError::Unavailable)?
                .status(path, cancellation)
                .await
        })
        .await
    }

    pub async fn remote_sessions(
        &self,
    ) -> Result<nddev_device_sync_remote::view::RemoteSnapshot, AgentError> {
        self.observe("remote", |cancellation| async move {
            self.remote
                .as_ref()
                .ok_or(AgentError::Unavailable)?
                .sessions(cancellation)
                .await
                .map_err(remote_error)
        })
        .await
    }
}

fn validated_cache_base(port: Option<u16>) -> Result<Option<CacheBase>, AgentError> {
    port.map(|port| CacheBase::new(port).ok_or(AgentError::InvalidInput))
        .transpose()
}

#[cfg(target_os = "linux")]
fn configured_cache(
    io: nddev_device_sync_adapter_io::LocalIo,
    base: Option<CacheBase>,
    scope: impl FnOnce() -> Result<CacheScope, CacheError>,
) -> Result<Option<CacheClient>, AgentError> {
    let Some(base) = base else {
        return Ok(None);
    };
    let scope = scope().map_err(|error| cache_observation(&error))?;
    Ok(Some(CacheClient::new(io, scope, base)))
}

fn cache_success(status: &cache::Status) -> Result<(), AgentError> {
    if status.ready {
        Ok(())
    } else {
        Err(AgentError::Unavailable)
    }
}

fn cache_gate_error(error: AgentError) -> CacheError {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        match error {
            AgentError::UnsupportedPlatform => CacheError::UnsupportedPlatform,
            AgentError::Unavailable => IoError::Unavailable.into(),
            AgentError::Busy => CacheError::Busy,
            AgentError::InvalidInput => CacheError::Invalid,
            AgentError::Timeout => IoError::Timeout.into(),
            AgentError::Cancelled => IoError::Cancelled.into(),
            AgentError::ProviderFailed => IoError::Transport.into(),
            AgentError::InvalidResponse | AgentError::InvalidContract => {
                IoError::InvalidResponse.into()
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = error;
        CacheError::UnsupportedPlatform
    }
}

/// Observation only: callers keep the exact owning refusal/result.
fn cache_observation(error: &CacheError) -> AgentError {
    match error {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        CacheError::Io(error) => io_error_ref(error),
        CacheError::Conflict | CacheError::Invalid => AgentError::InvalidInput,
        CacheError::NotReady => AgentError::Unavailable,
        CacheError::Busy => AgentError::Busy,
        CacheError::Uncertain => AgentError::ProviderFailed,
        CacheError::UnsupportedPlatform => AgentError::UnsupportedPlatform,
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

fn remote_error(error: nddev_device_sync_remote::Error) -> AgentError {
    match error {
        nddev_device_sync_remote::Error::Io(error) => io_error(error),
        nddev_device_sync_remote::Error::Protocol => AgentError::InvalidResponse,
        nddev_device_sync_remote::Error::UnsupportedPlatform => AgentError::UnsupportedPlatform,
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

    #[test]
    fn zero_cache_base_is_rejected_before_any_discovery_or_scope() {
        assert_eq!(
            NativeAgent::discover_with_cache_base(Some(0)).err(),
            Some(AgentError::InvalidInput)
        );
        assert!(validated_cache_base(None).unwrap().is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn explicit_cache_base_is_unsupported_before_non_linux_discovery() {
        assert_eq!(
            NativeAgent::discover_with_cache_base(Some(1)).err(),
            Some(AgentError::UnsupportedPlatform)
        );
    }

    #[cfg(target_os = "linux")]
    mod cache_status {
        use super::*;
        use nddev_device_sync_cache_client::binding::{BEGIN, END, Target};
        use std::{
            io::{BufReader, Read, Write},
            net::TcpListener,
            sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        };

        const WAIT: Duration = Duration::from_secs(5);
        struct Probe {
            base: CacheBase,
            stop: Arc<AtomicBool>,
            accepted: Arc<AtomicUsize>,
            task: Option<std::thread::JoinHandle<()>>,
        }
        impl Probe {
            fn new(ready: bool) -> Self {
                let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
                listener.set_nonblocking(true).unwrap();
                let base = CacheBase::new(listener.local_addr().unwrap().port()).unwrap();
                let stop = Arc::new(AtomicBool::new(false));
                let accepted = Arc::new(AtomicUsize::new(0));
                let (stopping, observed) = (stop.clone(), accepted.clone());
                let task = std::thread::spawn(move || {
                    let deadline = Instant::now() + WAIT;
                    while !stopping.load(Ordering::Acquire) && Instant::now() < deadline {
                        match listener.accept() {
                            Ok((mut stream, _)) => {
                                observed.fetch_add(1, Ordering::AcqRel);
                                stream.set_read_timeout(Some(WAIT)).unwrap();
                                stream.set_write_timeout(Some(WAIT)).unwrap();
                                let mut request = Vec::new();
                                {
                                    let mut input = BufReader::new(&mut stream).take(512);
                                    while !request.ends_with(b"\r\n\r\n") {
                                        let mut byte = [0u8; 1];
                                        input.read_exact(&mut byte).unwrap();
                                        request.push(byte[0]);
                                    }
                                }
                                assert!(request.starts_with(b"GET /v1/ready HTTP/1.1\r\n"));
                                let response: &[u8] = if ready {
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                } else {
                                    b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                };
                                stream.write_all(response).unwrap();
                                break;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            Err(error) => panic!("private readiness listener: {:?}", error.kind()),
                        }
                    }
                });
                Self {
                    base,
                    stop,
                    accepted,
                    task: Some(task),
                }
            }
        }
        impl Drop for Probe {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Release);
                if let Some(task) = self.task.take() {
                    let result = task.join();
                    if !std::thread::panicking() {
                        result.expect("private readiness peer");
                    }
                }
            }
        }
        fn lane(root: &Path) -> CacheScope {
            CacheScope::lane_in(root, |name| {
                (name == "HOME").then(|| root.as_os_str().to_owned())
            })
            .unwrap()
        }
        fn agent(client: Option<CacheClient>) -> NativeAgent {
            let mut agent = browser_agent();
            let configured = client.is_some();
            agent.cache = client;
            agent
                .modules
                .lock()
                .unwrap()
                .iter_mut()
                .find(|slot| slot.state.id == "cache")
                .unwrap()
                .state
                .configured = configured;
            agent
        }
        fn files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
            let mut pending = vec![root.to_owned()];
            let mut found = Vec::new();
            while let Some(directory) = pending.pop() {
                for entry in std::fs::read_dir(directory).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        pending.push(path);
                    } else {
                        found.push((
                            path.strip_prefix(root).unwrap().to_owned(),
                            std::fs::read(path).unwrap(),
                        ));
                    }
                }
            }
            found.sort();
            found
        }

        #[tokio::test]
        async fn absent_cache_base_never_requests_a_scope_and_does_not_claim_direct_mode() {
            let client = configured_cache(
                NativeIo::new(1).unwrap().local_handle(),
                validated_cache_base(None).unwrap(),
                || panic!("None must not inspect a cache scope"),
            )
            .unwrap();
            let agent = agent(client);
            assert_eq!(
                tokio::time::timeout(WAIT, agent.cache_status())
                    .await
                    .unwrap()
                    .err(),
                Some(CacheError::Io(IoError::Unavailable))
            );
            let state = agent
                .modules()
                .into_iter()
                .find(|state| state.id == "cache")
                .unwrap();
            assert!(!state.configured && state.observed_at_ms.is_none());
        }
        #[test]
        fn explicit_scope_refusal_is_not_silently_treated_as_absent_configuration() {
            assert_eq!(
                configured_cache(
                    NativeIo::new(1).unwrap().local_handle(),
                    validated_cache_base(Some(1)).unwrap(),
                    || Err(CacheError::Conflict)
                )
                .err(),
                Some(AgentError::InvalidInput)
            );
        }
        #[tokio::test]
        async fn ready_status_uses_real_client_and_never_changes_the_disposable_scope() {
            let root = tempfile::tempdir().unwrap();
            let peer = Probe::new(true);
            let client = configured_cache(
                NativeIo::new(1).unwrap().local_handle(),
                Some(peer.base.clone()),
                || Ok(lane(root.path())),
            )
            .unwrap();
            assert_eq!(
                peer.accepted.load(Ordering::Acquire),
                0,
                "construction must not probe"
            );
            let agent = agent(client);
            let before = files(root.path());
            let status = tokio::time::timeout(WAIT, agent.cache_status())
                .await
                .unwrap()
                .unwrap();
            assert!(status.ready);
            assert_eq!(status.port, peer.base.port());
            assert!(status.bindings.iter().all(|binding| !binding.bound));
            assert_eq!(files(root.path()), before);
            let state = agent
                .modules()
                .into_iter()
                .find(|state| state.id == "cache")
                .unwrap();
            assert!(state.error.is_none() && state.observed_at_ms.is_some());
            assert_eq!(peer.accepted.load(Ordering::Acquire), 1);
        }
        #[tokio::test]
        async fn nonready_status_is_returned_losslessly_but_not_observed_as_ready() {
            let root = tempfile::tempdir().unwrap();
            let peer = Probe::new(false);
            let client = configured_cache(
                NativeIo::new(1).unwrap().local_handle(),
                Some(peer.base.clone()),
                || Ok(lane(root.path())),
            )
            .unwrap();
            let agent = agent(client);
            let status = tokio::time::timeout(WAIT, agent.cache_status())
                .await
                .unwrap()
                .unwrap();
            assert!(!status.ready);
            assert_eq!(status.port, peer.base.port());
            assert_eq!(peer.accepted.load(Ordering::Acquire), 1);
            let state = agent
                .modules()
                .into_iter()
                .find(|state| state.id == "cache")
                .unwrap();
            assert_eq!(state.error, Some(AgentError::Unavailable));
            assert!(state.observed_at_ms.is_some());
            assert!(files(root.path()).is_empty());
        }
        #[tokio::test]
        async fn managed_marker_presence_does_not_claim_binding_to_supplied_base() {
            let root = tempfile::tempdir().unwrap();
            let peer = Probe::new(true);
            let old = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
            let old_port = old.local_addr().unwrap().port();
            assert_ne!(old_port, peer.base.port());
            let scope = lane(root.path());
            let path = scope.path(Target::Cargo);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, format!("{BEGIN}\n[source.crates-io]\nreplace-with = 'nds-cache'\n[source.nds-cache]\nregistry = 'sparse+http://127.0.0.1:{old_port}/crates-index/'\n{END}\n")).unwrap();
            let before = files(root.path());
            let client = configured_cache(
                NativeIo::new(1).unwrap().local_handle(),
                Some(peer.base.clone()),
                || Ok(scope),
            )
            .unwrap();
            let status = tokio::time::timeout(WAIT, agent(client).cache_status())
                .await
                .unwrap()
                .unwrap();
            assert!(status.ready);
            assert_eq!(status.port, peer.base.port());
            // A managed file naming another port is visible but not in force
            // for the supplied base; the client reports exact bindings only.
            assert!(
                status
                    .bindings
                    .iter()
                    .any(|binding| binding.kind == "cargo" && !binding.bound)
            );
            assert_eq!(files(root.path()), before);
        }
        #[tokio::test]
        async fn observer_preserves_exact_owning_refusals_while_projecting_coarse_errors() {
            let cases: [(fn() -> CacheError, AgentError); 10] = [
                (|| CacheError::Busy, AgentError::Busy),
                (|| CacheError::Conflict, AgentError::InvalidInput),
                (|| CacheError::Invalid, AgentError::InvalidInput),
                (|| CacheError::NotReady, AgentError::Unavailable),
                (|| CacheError::Uncertain, AgentError::ProviderFailed),
                (
                    || CacheError::UnsupportedPlatform,
                    AgentError::UnsupportedPlatform,
                ),
                (|| CacheError::Io(IoError::Busy), AgentError::Busy),
                (|| CacheError::Io(IoError::Timeout), AgentError::Timeout),
                (|| CacheError::Io(IoError::Cancelled), AgentError::Cancelled),
                (
                    || CacheError::Io(IoError::InvalidFrame),
                    AgentError::InvalidResponse,
                ),
            ];
            // Explicit synthetic admission through the REAL shared observer,
            // not a cache mutation or a claim about an absent provider.
            let agent = browser_agent();
            for (make, expected) in cases {
                let before = agent
                    .modules()
                    .into_iter()
                    .find(|state| state.id == "cache")
                    .unwrap();
                let result: Result<cache::Status, CacheError> = agent
                    .observe_mapped(
                        "cache",
                        |_| async move { Err(make()) },
                        cache_gate_error,
                        cache_observation,
                        cache_success,
                    )
                    .await;
                assert_eq!(result, Err(make()));
                let state = agent
                    .modules()
                    .into_iter()
                    .find(|state| state.id == "cache")
                    .unwrap();
                if matches!(
                    query_outcome::<()>(&Err(expected)),
                    nddev_device_sync_domain::modules::ModuleOutcome::NotAdmitted
                        | nddev_device_sync_domain::modules::ModuleOutcome::Cancelled
                ) {
                    assert_eq!(state.error, before.error);
                    assert_eq!(state.observed_at_ms, before.observed_at_ms);
                    assert!(state.reachability == before.reachability);
                } else {
                    assert_eq!(state.error, Some(expected));
                }
            }
        }

        /// Three real readiness exchanges: bind preflight/readback, then an
        /// explicit unbind readback. The first reply is held; every thread and
        /// socket has a finite bound, and Drop always releases/stops/joins it.
        struct MutationProbe {
            base: CacheBase,
            first: CancellationToken,
            release: Option<std::sync::mpsc::Sender<()>>,
            stop: Arc<AtomicBool>,
            task: Option<std::thread::JoinHandle<()>>,
        }
        impl MutationProbe {
            fn new() -> Self {
                let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
                listener.set_nonblocking(true).unwrap();
                let base = CacheBase::new(listener.local_addr().unwrap().port()).unwrap();
                let first = CancellationToken::new();
                let observed = first.clone();
                let stop = Arc::new(AtomicBool::new(false));
                let stopping = stop.clone();
                let (release, released) = std::sync::mpsc::channel();
                let task = std::thread::spawn(move || {
                    let deadline = Instant::now() + WAIT;
                    let mut accepted = 0;
                    while !stopping.load(Ordering::Acquire)
                        && Instant::now() < deadline
                        && accepted < 3
                    {
                        match listener.accept() {
                            Ok((mut stream, _)) => {
                                stream.set_read_timeout(Some(WAIT)).unwrap();
                                stream.set_write_timeout(Some(WAIT)).unwrap();
                                let mut request = Vec::new();
                                {
                                    let mut input = BufReader::new(&mut stream).take(512);
                                    while !request.ends_with(b"\r\n\r\n") {
                                        let mut byte = [0; 1];
                                        input.read_exact(&mut byte).unwrap();
                                        request.push(byte[0]);
                                    }
                                }
                                assert!(request.starts_with(b"GET /v1/ready HTTP/1.1\r\n"));
                                if accepted == 0 {
                                    observed.cancel();
                                    if released.recv_timeout(WAIT).is_err() {
                                        return;
                                    }
                                }
                                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                                accepted += 1;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            Err(error) => panic!("private mutation peer: {:?}", error.kind()),
                        }
                    }
                });
                Self {
                    base,
                    first,
                    release: Some(release),
                    stop,
                    task: Some(task),
                }
            }
            fn release(&mut self) {
                if let Some(release) = self.release.take() {
                    let _ = release.send(());
                }
            }
        }
        impl Drop for MutationProbe {
            fn drop(&mut self) {
                self.release();
                self.stop.store(true, Ordering::Release);
                if let Some(task) = self.task.take() {
                    let result = task.join();
                    if !std::thread::panicking() {
                        result.expect("private mutation peer");
                    }
                }
            }
        }

        #[tokio::test]
        async fn admitted_bind_survives_revocation_then_explicit_unbind_preserves_foreign_files() {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join("foreign.bin"), b"foreign\0unchanged").unwrap();
            let before = files(root.path());
            let mut peer = MutationProbe::new();
            let client = CacheClient::new(
                NativeIo::new(1).unwrap().local_handle(),
                lane(root.path()),
                peer.base.clone(),
            );
            let agent = Arc::new(agent(Some(client)));
            let owned = agent.clone();
            let bind = tokio::spawn(async move { owned.cache_bind().await });
            let held = tokio::time::timeout(WAIT, peer.first.cancelled()).await;
            // Retain every result until the held worker has been released and
            // its actual async owner joined, including on an assertion failure.
            let status = agent.cache_status().await;
            let competing = agent.cache_unbind().await;
            let revoked = agent.invalidate_module("cache");
            let replacement = agent.cache_bind().await;
            peer.release();
            let bound = bind.await;
            assert!(held.is_ok());
            assert_eq!(status, Err(CacheError::Busy));
            assert_eq!(competing, Err(CacheError::Busy));
            assert_eq!(revoked, Ok(()));
            assert_eq!(replacement, Err(CacheError::Busy));
            let bound = bound.unwrap().unwrap();
            assert!(bound.ready && bound.bindings.iter().any(|binding| binding.bound));
            assert_ne!(files(root.path()), before, "revoke must not unbind");
            let unbound = agent.cache_unbind().await.unwrap();
            assert!(unbound.bindings.iter().all(|binding| !binding.bound));
            assert_eq!(files(root.path()), before);
        }

        #[tokio::test]
        async fn dropped_mutation_future_keeps_unknown_across_invalidation_and_close() {
            let agent = browser_agent();
            let browser_lifetime = agent
                .modules
                .lock()
                .unwrap()
                .iter()
                .find(|slot| slot.state.id == "browser-use")
                .unwrap()
                .lifetime
                .clone();
            // Exercise the actual admission/observer/drop seam without leaving
            // an unjoinable OS worker in a test. Real LocalIo drop behavior is
            // the reason this guard must retain Unknown, not a mock join proof.
            let mut held = Box::pin(agent.cache_mutation_with(|worker| async move {
                worker.cancelled().await;
                Err(CacheError::Io(IoError::Cancelled))
            }));
            std::future::poll_fn(|cx| {
                assert!(held.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            assert_eq!(agent.cache_status().await, Err(CacheError::Busy));
            agent.invalidate_module("cache").unwrap();
            std::future::poll_fn(|cx| {
                assert!(held.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            drop(held);
            assert!(!browser_lifetime.is_cancelled());
            assert!(!agent.cancellation.is_cancelled());
            assert_eq!(agent.cache_bind().await, Err(CacheError::Busy));
            assert_eq!(agent.cache_unbind().await, Err(CacheError::Busy));
            agent.invalidate_module("cache").unwrap();
            assert_eq!(agent.cache_status().await, Err(CacheError::Busy));
            agent.close();
            assert!(matches!(
                agent.cache_mutation.lock().unwrap().state,
                CacheMutationState::Unknown
            ));
        }

        #[tokio::test]
        async fn joined_uncertain_preserves_written_effect_and_exact_error_after_cancellation() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("owned-effect");
            let owned = path.clone();
            let agent = browser_agent();
            let revoked = agent
                .modules
                .lock()
                .unwrap()
                .iter()
                .find(|slot| slot.state.id == "cache")
                .unwrap()
                .lifetime
                .clone();
            let io = NativeIo::new(1).unwrap().local_handle();
            // A deterministic provider-result seam through REAL LocalIo; not
            // a claim to reproduce the cache client's post-write read failure.
            let result = agent
                .cache_mutation_with(|worker| async move {
                    io.local(worker, move |_| {
                        std::fs::write(owned, b"effect remains").unwrap();
                        revoked.cancel();
                        Ok(Err::<cache::Status, CacheError>(CacheError::Uncertain))
                    })
                    .await?
                })
                .await;
            assert_eq!(result, Err(CacheError::Uncertain));
            assert_eq!(std::fs::read(path).unwrap(), b"effect remains");
            assert!(matches!(
                agent.cache_mutation.lock().unwrap().state,
                CacheMutationState::Idle
            ));
        }

        #[tokio::test]
        async fn blocking_worker_panic_returns_transport_and_keeps_unknown() {
            let agent = browser_agent();
            let io = NativeIo::new(1).unwrap().local_handle();
            let result = agent
                .cache_mutation_with(|worker| async move {
                    io.local(worker, |_| -> Result<cache::Status, IoError> {
                        panic!("synthetic owned cache worker failure");
                    })
                    .await
                    .map_err(CacheError::Io)
                })
                .await;
            assert_eq!(result, Err(CacheError::Io(IoError::Transport)));
            assert!(matches!(
                agent.cache_mutation.lock().unwrap().state,
                CacheMutationState::Unknown
            ));
            agent.invalidate_module("cache").unwrap();
            assert_eq!(agent.cache_status().await, Err(CacheError::Busy));
            assert_eq!(agent.cache_bind().await, Err(CacheError::Busy));
        }

        #[tokio::test]
        async fn closed_admission_never_polls_mutation_work_or_poisons_an_idle_slot() {
            let agent = browser_agent();
            agent.close();
            let result = agent
                .cache_mutation_with(|_| async {
                    panic!("denied mutation must not start");
                })
                .await;
            assert_eq!(result, Err(CacheError::Io(IoError::Cancelled)));
            assert!(matches!(
                agent.cache_mutation.lock().unwrap().state,
                CacheMutationState::Idle
            ));
        }

        async fn status_crossed_by_owned_mutation(unknown: bool) {
            let root = tempfile::tempdir().unwrap();
            let mut peer = MutationProbe::new();
            let io = NativeIo::new(2).unwrap();
            let client = CacheClient::new(io.local_handle(), lane(root.path()), peer.base.clone());
            let agent = Arc::new(agent(Some(client)));
            let owned = agent.clone();
            let status = tokio::spawn(async move { owned.cache_status().await });
            let held = tokio::time::timeout(WAIT, peer.first.cancelled()).await;
            let mutation = if unknown {
                // The real status request is held. Admit then drop the actual
                // mutation future seam without leaking an OS worker in a test.
                let mut work = Box::pin(agent.cache_mutation_with(|_| {
                    std::future::pending::<Result<cache::Status, CacheError>>()
                }));
                let pending = std::future::poll_fn(|cx| {
                    // Record rather than assert until status is released/joined.
                    std::task::Poll::Ready(work.as_mut().poll(cx).is_pending())
                })
                .await;
                drop(work);
                if pending {
                    Ok(())
                } else {
                    Err(CacheError::Invalid)
                }
            } else {
                let local = io.local_handle();
                let changed = root.path().join("owned-completed-effect");
                // A real, joined LocalIo effect with known Uncertain makes an
                // honest ProviderFailed observation before the stale reply.
                // This is a completion seam, not cache readback fault injection.
                agent
                    .cache_mutation_with(|worker| async move {
                        local
                            .local(worker, move |_| {
                                std::fs::write(changed, b"known completed effect").unwrap();
                                Ok(Err::<cache::Status, CacheError>(CacheError::Uncertain))
                            })
                            .await?
                    })
                    .await
                    .map(|_| ())
            };
            peer.release();
            let status = status.await;
            assert!(held.is_ok());
            assert_eq!(status.unwrap(), Err(CacheError::Busy));
            let observation = agent
                .modules()
                .into_iter()
                .find(|state| state.id == "cache")
                .unwrap();
            if unknown {
                assert_eq!(mutation, Ok(()));
                assert!(matches!(
                    agent.cache_mutation.lock().unwrap().state,
                    CacheMutationState::Unknown
                ));
                assert!(observation.reachability == Reachability::NotChecked);
                assert!(observation.observed_at_ms.is_none());
            } else {
                assert_eq!(mutation, Err(CacheError::Uncertain));
                assert!(matches!(
                    agent.cache_mutation.lock().unwrap().state,
                    CacheMutationState::Idle
                ));
                assert_eq!(observation.error, Some(AgentError::ProviderFailed));
                assert!(observation.observed_at_ms.is_some());
            }
        }

        #[tokio::test]
        async fn held_real_status_cannot_publish_ready_after_mutation_becomes_unknown() {
            status_crossed_by_owned_mutation(true).await;
        }

        #[tokio::test]
        async fn held_real_status_cannot_erase_a_known_completed_mutation_observation() {
            status_crossed_by_owned_mutation(false).await;
        }

        #[test]
        fn status_publication_excludes_mutation_until_final_handoff() {
            let slot = Mutex::<CacheMutationSlot>::default();
            let generation = slot.lock().unwrap().generation.clone();
            let publication = CacheStatusPublication::begin(&slot, generation.clone()).unwrap();
            assert!(matches!(CacheMutation::begin(&slot), Err(AgentError::Busy)));
            drop(publication);
            let mutation = CacheMutation::begin(&slot).unwrap();
            mutation.finish(&Err(CacheError::Uncertain));
            assert!(matches!(
                CacheStatusPublication::begin(&slot, generation),
                Err(CacheError::Busy)
            ));
        }
    }

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
            github: None,
            remote: None,
            browser: Some(
                BrowserUseClient::new(
                    NativeIo::new(1).unwrap().local_handle(),
                    std::env::temp_dir().join("unopened-agent-browser-unit.sock"),
                )
                .unwrap(),
            ),
            browser_registry: Mutex::default(),
            #[cfg(target_os = "linux")]
            cache: None,
            #[cfg(target_os = "linux")]
            cache_mutation: Mutex::default(),
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

    #[cfg(unix)]
    mod browser_transport {
        use super::*;
        use nddev_device_sync_browser_use::protocol::{FRAME_LIMIT, Header, Reply, Request};
        use std::{
            io::{BufRead, BufReader, Read, Write},
            os::unix::net::{UnixListener, UnixStream},
        };

        const PEER_WAIT: Duration = Duration::from_secs(5);

        // Real private framed IPC, not a browser host/Chrome or permission fixture.
        fn fixture() -> (Arc<NativeAgent>, UnixListener, tempfile::TempDir) {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("browser.sock");
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            let mut agent = browser_agent();
            agent.browser = Some(
                BrowserUseClient::new(NativeIo::new(1).unwrap().local_handle(), path).unwrap(),
            );
            (Arc::new(agent), listener, root)
        }

        struct Peer(Option<std::thread::JoinHandle<()>>);
        impl Peer {
            fn start(work: impl FnOnce() + Send + 'static) -> Self {
                Self(Some(std::thread::spawn(work)))
            }
            fn join(mut self) {
                self.0
                    .take()
                    .unwrap()
                    .join()
                    .expect("private IPC peer failed");
            }
        }
        impl Drop for Peer {
            fn drop(&mut self) {
                // Accept/read/channel waits below are finite even if an assertion
                // fails. Join before the owned socket directory is removed.
                if let Some(peer) = self.0.take() {
                    let _ = peer.join();
                }
            }
        }

        fn request(listener: &UnixListener) -> (UnixStream, Request) {
            let deadline = Instant::now() + PEER_WAIT;
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "private IPC accept timed out");
                        // Only listener acceptance polls; held ACK ordering uses
                        // explicit channels, not an assumed sleep duration.
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => panic!("private IPC accept failed"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(PEER_WAIT)).unwrap();
            stream.set_write_timeout(Some(PEER_WAIT)).unwrap();
            let mut bytes = Vec::new();
            {
                let mut input = BufReader::new(&mut stream).take((FRAME_LIMIT + 1) as u64);
                input.read_until(b'\n', &mut bytes).unwrap();
            }
            assert!(bytes.len() <= FRAME_LIMIT && bytes.last() == Some(&b'\n'));
            (stream, serde_json::from_slice(&bytes).unwrap())
        }

        fn reply(stream: &mut UnixStream, value: Reply) {
            let payload = serde_json::to_vec(&value).unwrap();
            let header = serde_json::to_vec(&Header {
                bytes: payload.len(),
            })
            .unwrap();
            stream.write_all(&header).unwrap();
            stream.write_all(b"\n").unwrap();
            stream.write_all(&payload).unwrap();
            stream.flush().unwrap();
        }

        #[tokio::test]
        async fn local_admission_busy_sends_nothing_and_does_not_poison_the_next_reservation() {
            let (agent, listener, root) = fixture();
            let mut agent = Arc::try_unwrap(agent).ok().unwrap();
            let local = NativeIo::new(1).unwrap().local_handle();
            agent.browser = Some(
                BrowserUseClient::new(local.clone(), root.path().join("browser.sock")).unwrap(),
            );
            let agent = Arc::new(agent);
            let (entered, occupied) = tokio::sync::oneshot::channel();
            let (release, held) = std::sync::mpsc::sync_channel(1);
            let blocker = tokio::spawn(async move {
                local
                    .local(CancellationToken::new(), move |_| {
                        entered.send(()).unwrap();
                        held.recv_timeout(PEER_WAIT).map_err(|_| IoError::Timeout)?;
                        Ok(())
                    })
                    .await
            });
            tokio::time::timeout(PEER_WAIT, occupied)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                agent.browser_open("owned").await.err(),
                Some(IoError::Busy.into())
            );
            assert!(agent.browser_registry.lock().unwrap().entries.is_empty());
            assert_eq!(
                listener.accept().err().unwrap().kind(),
                std::io::ErrorKind::WouldBlock
            );
            release.send(()).unwrap();
            tokio::time::timeout(PEER_WAIT, blocker)
                .await
                .unwrap()
                .unwrap()
                .unwrap();

            let owned = handle("owned", "after-local-admission");
            let expected = owned.clone();
            let (entered, received) = tokio::sync::oneshot::channel();
            let (release, held) = std::sync::mpsc::sync_channel(1);
            let peer = Peer::start(move || {
                let (mut stream, call) = request(&listener);
                assert!(matches!(call, Request::CreateOwned { project } if project == "owned"));
                entered.send(()).unwrap();
                held.recv_timeout(PEER_WAIT).unwrap();
                reply(&mut stream, Reply::OwnedSession(expected.clone()));
                drop(stream);
                let (mut stream, call) = request(&listener);
                assert!(
                    matches!(call, Request::CloseOwned { session, close_tabs: false } if session == expected)
                );
                reply(&mut stream, Reply::Closed);
            });
            let opening = {
                let agent = agent.clone();
                tokio::spawn(async move { agent.browser_open("owned").await })
            };
            tokio::time::timeout(PEER_WAIT, received)
                .await
                .unwrap()
                .unwrap();
            agent.cancel_browser();
            release.send(()).unwrap();
            assert_eq!(
                tokio::time::timeout(PEER_WAIT, opening)
                    .await
                    .unwrap()
                    .unwrap()
                    .err(),
                Some(IoError::Cancelled.into())
            );
            assert_eq!(
                agent.browser_registry.lock().unwrap().entries[0]
                    .handle
                    .as_ref(),
                Some(&owned)
            );
            tokio::time::timeout(PEER_WAIT, agent.drain_browser())
                .await
                .unwrap()
                .unwrap();
            peer.join();
            assert!(agent.browser_registry.lock().unwrap().entries.is_empty());
        }

        #[tokio::test]
        async fn held_reserve_ack_survives_module_cancel_and_retains_handle_without_open() {
            let (agent, listener, _root) = fixture();
            let owned = handle("owned", "bounded-reserve");
            let (entered, observed) = tokio::sync::oneshot::channel();
            let (release, held) = std::sync::mpsc::sync_channel(1);
            let expected = owned.clone();
            let peer = Peer::start(move || {
                let (mut stream, call) = request(&listener);
                assert!(matches!(call, Request::CreateOwned { project } if project == "owned"));
                entered.send(()).unwrap();
                held.recv_timeout(PEER_WAIT).unwrap();
                reply(&mut stream, Reply::OwnedSession(expected.clone()));
                drop(stream);
                let (mut stream, call) = request(&listener);
                // There must be no OpenOwned between late reserve and drain.
                assert!(
                    matches!(call, Request::CloseOwned { session, close_tabs: false } if session == expected)
                );
                reply(&mut stream, Reply::Closed);
            });
            let opened = {
                let agent = agent.clone();
                tokio::spawn(async move { agent.browser_open("owned").await })
            };
            tokio::time::timeout(PEER_WAIT, observed)
                .await
                .unwrap()
                .unwrap();
            agent.cancel_browser();
            release.send(()).unwrap();
            assert_eq!(
                tokio::time::timeout(PEER_WAIT, opened)
                    .await
                    .unwrap()
                    .unwrap()
                    .err(),
                Some(IoError::Cancelled.into())
            );
            {
                let registry = agent.browser_registry.lock().unwrap();
                assert_eq!(registry.entries.len(), 1);
                assert_eq!(registry.entries[0].handle.as_ref(), Some(&owned));
                assert!(registry.denied && registry.entries[0].needs_close && registry.calls == 0);
            }
            tokio::time::timeout(PEER_WAIT, agent.drain_browser())
                .await
                .unwrap()
                .unwrap();
            peer.join();
            let registry = agent.browser_registry.lock().unwrap();
            assert!(registry.entries.is_empty() && registry.drained && registry.denied);
        }

        #[tokio::test]
        async fn held_close_ack_survives_module_cancel_and_is_recorded_before_empty_drain() {
            let (agent, listener, _root) = fixture();
            let owned = handle("owned", "bounded-close");
            retain(&agent.browser_registry, "owned", owned.clone());
            let (entered, observed) = tokio::sync::oneshot::channel();
            let (release, held) = std::sync::mpsc::sync_channel(1);
            let peer = Peer::start(move || {
                let (mut stream, call) = request(&listener);
                assert!(
                    matches!(call, Request::CloseOwned { session, close_tabs: false } if session == owned)
                );
                entered.send(()).unwrap();
                held.recv_timeout(PEER_WAIT).unwrap();
                reply(&mut stream, Reply::Closed);
            });
            let closed = {
                let agent = agent.clone();
                tokio::spawn(async move { agent.browser_close("owned", false).await })
            };
            tokio::time::timeout(PEER_WAIT, observed)
                .await
                .unwrap()
                .unwrap();
            agent.cancel_browser();
            release.send(()).unwrap();
            // Normal query authorization is canceled, but the exact cleanup ACK
            // must already have removed the private owner handle.
            assert_eq!(
                tokio::time::timeout(PEER_WAIT, closed)
                    .await
                    .unwrap()
                    .unwrap()
                    .err(),
                Some(IoError::Cancelled.into())
            );
            peer.join();
            assert!(agent.browser_registry.lock().unwrap().entries.is_empty());
            tokio::time::timeout(PEER_WAIT, agent.drain_browser())
                .await
                .unwrap()
                .unwrap();
            let registry = agent.browser_registry.lock().unwrap();
            assert!(registry.drained && registry.denied && registry.calls == 0);
        }

        #[tokio::test]
        async fn actually_closed_reserve_or_close_reply_remains_unknown_not_a_drain_receipt() {
            for closing in [false, true] {
                let (agent, listener, _root) = fixture();
                let owned = handle("owned", "lost-reply");
                if closing {
                    retain(&agent.browser_registry, "owned", owned.clone());
                }
                let peer = Peer::start(move || {
                    let (stream, call) = request(&listener);
                    assert!(match call {
                        Request::CreateOwned { project } => !closing && project == "owned",
                        Request::CloseOwned {
                            session,
                            close_tabs: false,
                        } => closing && session == owned,
                        _ => false,
                    });
                    drop(stream); // Actual EOF before any reply/header/ACK.
                });
                let result = tokio::time::timeout(PEER_WAIT, async {
                    if closing {
                        agent.browser_close("owned", false).await
                    } else {
                        agent.browser_open("owned").await.map(|_| ())
                    }
                })
                .await
                .unwrap();
                assert!(matches!(result, Err(BrowserError::Io(_))));
                peer.join();
                agent.cancel_browser();
                let registry = agent.browser_registry.lock().unwrap();
                assert_eq!(registry.entries.len(), 1);
                assert_eq!(registry.entries[0].handle.is_some(), closing);
                assert!(
                    registry.entries[0].needs_close && registry.calls == 0 && !registry.drained
                );
                drop(registry);
                assert_eq!(agent.resume_browser().err(), Some(Refusal::Busy.into()));
            }
        }
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
            agent.observe("github", |_| work).await,
            Err(AgentError::UnsupportedPlatform)
        ));
        let state = agent
            .modules()
            .into_iter()
            .find(|module| module.id == "github")
            .unwrap();
        assert!(
            state.reachability == Reachability::NotChecked
                && state.observed_at_ms.is_none()
                && state.error.is_none()
        );
    }
}
