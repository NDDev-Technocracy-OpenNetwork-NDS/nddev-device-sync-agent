use crate::{CancellationToken, IoError, ProcessIo, transport, valid_timeout};
use process_wrap::tokio::{ChildWrapper, CommandWrap, KillOnDrop};
use std::{
    ffi::OsString,
    path::PathBuf,
    process::{ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

pub struct ProcessRequest {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    /// Explicit repository scope, or the executable's directory when absent.
    pub directory: Option<PathBuf>,
    pub timeout: Duration,
    /// Combined stdout + stderr ceiling, at most 1 MiB.
    pub max_output_bytes: usize,
}

/// Native point-of-use input. No Debug/Serialize; never accept environment names
/// from a presentation DTO. Provider credentials use official environment support.
#[derive(Default)]
pub struct ProcessInput {
    pub stdin: Zeroizing<Vec<u8>>,
    pub credential: Option<(CredentialEnvironment, Zeroizing<String>)>,
}
#[derive(Clone, Copy)]
pub enum CredentialEnvironment {
    GitHub,
    /// A pre-encoded GitHub HTTPS Authorization header, used only through
    /// Git's --config-env. No terminal, ambient Git config or credential helper.
    GitHttps,
    Cloudflare,
    DigitalOcean,
}
impl CredentialEnvironment {
    fn name(self) -> &'static str {
        match self {
            Self::GitHub => "GH_TOKEN",
            Self::GitHttps => "NDS_GITHUB_AUTHORIZATION",
            Self::Cloudflare => "CLOUDFLARE_API_TOKEN",
            Self::DigitalOcean => "DIGITALOCEAN_ACCESS_TOKEN",
        }
    }
}

// Deliberately no Debug: tool output can contain private paths and account data.
pub struct ProcessOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

struct OwnedChild {
    child: Box<dyn ChildWrapper>,
    scope_terminated: bool,
    #[cfg(target_os = "macos")]
    leader_exited: bool,
}

impl OwnedChild {
    fn terminate_scope(&mut self) -> std::io::Result<()> {
        if self.scope_terminated {
            return Ok(());
        }
        let result = self.child.start_kill();
        #[cfg(unix)]
        let result = result.or_else(|error| {
            // Darwin may already have removed the exited leader from an empty
            // group. Its unreaped PID is still reserved: ESRCH means no helpers.
            if error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) {
                Ok(())
            } else {
                #[cfg(target_os = "macos")]
                if self.leader_exited
                    && error.raw_os_error() == Some(rustix::io::Errno::PERM.raw_os_error())
                    && self.child.id().is_some_and(macos_group_has_no_helpers)
                {
                    return Ok(());
                }
                Err(error)
            }
        });
        result?;
        self.scope_terminated = true;
        Ok(())
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.scope_terminated {
            // ProcessGroup/JobObject kills the owned group. Tokio kill-on-drop
            // also ensures the direct child is reaped if the future is aborted.
            let _ = self.terminate_scope();
        }
    }
}

impl ProcessIo {
    /// Decode a complete native response only after its owning adapter's exit
    /// policy accepts it. Never treat a truncated or failed command as success.
    pub async fn json<T: serde::de::DeserializeOwned>(
        &self,
        request: ProcessRequest,
        accepted_exit_codes: &[i32],
        cancellation: CancellationToken,
    ) -> Result<(T, i32), IoError> {
        let output = self.process(request, cancellation).await?;
        let code = output.status.code().ok_or(IoError::ProviderExit)?;
        if !accepted_exit_codes.contains(&code) {
            return Err(IoError::ProviderExit);
        }
        let value = serde_json::from_slice(&output.stdout).map_err(|_| IoError::InvalidResponse)?;
        Ok((value, code))
    }

    pub async fn process(
        &self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> Result<ProcessOutput, IoError> {
        self.process_input(request, ProcessInput::default(), cancellation)
            .await
    }

    pub async fn process_input(
        &self,
        request: ProcessRequest,
        input: ProcessInput,
        cancellation: CancellationToken,
    ) -> Result<ProcessOutput, IoError> {
        let started = Instant::now();
        let result = self.run_process(request, input, cancellation).await;
        match &result {
            Ok(output) => tracing::info!(
                event.name = "native.process.completed",
                duration_ms = started.elapsed().as_millis() as u64,
                outcome = if output.status.success() {
                    "ok"
                } else {
                    "error"
                },
            ),
            Err(error) => tracing::warn!(
                event.name = "native.process.failed",
                duration_ms = started.elapsed().as_millis() as u64,
                error.type = error.code(),
                outcome = "error",
            ),
        }
        result
    }

    async fn run_process(
        &self,
        request: ProcessRequest,
        input: ProcessInput,
        cancellation: CancellationToken,
    ) -> Result<ProcessOutput, IoError> {
        if input.stdin.len() > 16_384
            || input.credential.as_ref().is_some_and(|(_, value)| {
                value.is_empty() || value.len() > 16_384 || value.contains('\0')
            })
            || !request.executable.is_absolute()
            || request
                .directory
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            || !valid_timeout(request.timeout)
            || !(1..=1_048_576).contains(&request.max_output_bytes)
            || request.arguments.len() > 32
            || request.arguments.iter().any(|arg| arg.len() > 4096)
            || request.arguments.iter().map(|arg| arg.len()).sum::<usize>() > 16_384
        {
            return Err(IoError::InvalidConfiguration);
        }
        if cancellation.is_cancelled() {
            return Err(IoError::Cancelled);
        }
        let _permit = self.permits.try_acquire().map_err(|_| IoError::Busy)?;
        let directory = request
            .directory
            .as_deref()
            .or_else(|| request.executable.parent())
            .ok_or(IoError::InvalidConfiguration)?;
        let mut command = CommandWrap::with_new(&request.executable, |command| {
            command
                .args(&request.arguments)
                .env_clear()
                .envs(native_environment())
                .current_dir(directory)
                .stdin(if input.stdin.is_empty() {
                    Stdio::null()
                } else {
                    Stdio::piped()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            if let Some((name, value)) = &input.credential {
                command.env(name.name(), value.as_str());
                if matches!(name, CredentialEnvironment::GitHttps) {
                    command
                        .env("GIT_TERMINAL_PROMPT", "0")
                        .env("GIT_CONFIG_NOSYSTEM", "1")
                        .env(
                            "GIT_CONFIG_GLOBAL",
                            if cfg!(windows) { "NUL" } else { "/dev/null" },
                        )
                        .env("GIT_ATTR_NOSYSTEM", "1")
                        .env("GIT_OPTIONAL_LOCKS", "0");
                }
            }
        });
        command.wrap(KillOnDrop);
        #[cfg(unix)]
        command.wrap(process_wrap::tokio::ProcessGroup::leader());
        #[cfg(windows)]
        command.wrap(process_wrap::tokio::JobObject);
        // Register before spawn so a very short-lived child cannot exit between
        // the status probe and subscribing to its SIGCHLD notification.
        #[cfg(unix)]
        let mut changed = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
            .map_err(transport)?;
        let mut owned = OwnedChild {
            child: command.spawn().map_err(transport)?,
            scope_terminated: false,
            #[cfg(target_os = "macos")]
            leader_exited: false,
        };
        let mut stdin = owned.child.stdin().take();
        let stdout = owned.child.stdout().take().ok_or(IoError::Transport)?;
        let stderr = owned.child.stderr().take().ok_or(IoError::Transport)?;
        let bytes = Arc::new(AtomicUsize::new(0));
        let result = {
            let capture = async {
                tokio::try_join!(
                    async {
                        #[cfg(unix)]
                        wait_owned_scope(&mut owned, &mut changed).await?;
                        owned.child.wait().await.map_err(transport)
                    },
                    bounded_read(stdout, bytes.clone(), request.max_output_bytes),
                    bounded_read(stderr, bytes, request.max_output_bytes),
                    async {
                        if let Some(mut stdin) = stdin.take() {
                            stdin.write_all(&input.stdin).await.map_err(transport)?;
                            stdin.shutdown().await.map_err(transport)?;
                        }
                        Ok::<_, IoError>(())
                    },
                )
            };
            tokio::select! {
                biased;
                () = cancellation.cancelled() => Err(IoError::Cancelled),
                result = tokio::time::timeout(request.timeout, capture) => {
                    result.unwrap_or(Err(IoError::Timeout))
                }
            }
        };
        match result {
            Ok((status, stdout, stderr, ())) => {
                #[cfg(windows)]
                owned.terminate_scope().map_err(transport)?;
                Ok(ProcessOutput {
                    status,
                    stdout,
                    stderr,
                })
            }
            Err(error) => {
                let _ = owned.terminate_scope();
                // Do not hang indefinitely while reaping an unresponsive child.
                let _ = tokio::time::timeout(Duration::from_secs(1), owned.child.wait()).await;
                Err(error)
            }
        }
    }
}

#[cfg(unix)]
async fn wait_owned_scope(
    owned: &mut OwnedChild,
    changed: &mut tokio::signal::unix::Signal,
) -> Result<(), IoError> {
    use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
    let pid = owned
        .child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw)
        .ok_or(IoError::Transport)?;
    loop {
        match waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
        ) {
            Ok(Some(_)) => {
                // The unreaped leader reserves its PID/group identity. Kill
                // remaining helpers before reaping, even when they closed all
                // pipes and the leader exited successfully. No PID-reuse gap.
                #[cfg(target_os = "macos")]
                {
                    owned.leader_exited = true;
                }
                return owned.terminate_scope().map_err(transport);
            }
            Ok(None) => {
                changed.recv().await.ok_or(IoError::Transport)?;
            }
            Err(error) if error == rustix::io::Errno::INTR => continue,
            Err(_) => return Err(IoError::Transport),
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_group_has_no_helpers(leader: u32) -> bool {
    // XNU's group signal path excludes zombies and returns EPERM when it found
    // no signalable process. Do not hide a real permission denial: inspect only
    // this reserved group and accept solely the already-exited leader/empty set.
    // libproc distinguishes an empty result using errno; discard the preceding
    // killpg errno before querying. No command lines or unrelated inventory.
    errno::set_errno(errno::Errno(0));
    libproc::processes::pids_by_type(libproc::processes::ProcFilter::ByProgramGroup {
        pgrpid: leader,
    })
    .is_ok_and(|pids| pids.iter().all(|pid| *pid == 0 || *pid == leader))
}

/// Native user/session discovery only. Do not inherit provider API tokens,
/// loader overrides, shell startup hooks or Git directory/index redirections.
fn native_environment() -> impl Iterator<Item = (&'static str, OsString)> {
    [
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "TMP",
        "TEMP",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "DBUS_SESSION_BUS_ADDRESS",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "USERPROFILE",
        "USERNAME",
        "LOCALAPPDATA",
        "APPDATA",
        "PROGRAMDATA",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        // These references select native owner state/preservation policy.
        "RLDYOUR_UPDATER_CONFIG",
        "RLDYOUR_UPDATER_STATE",
        "GDS_ESTATE_ROOT",
        "GDS_TRUST_POLICY_FILE",
        "UV_CACHE_DIR",
        "UV_LINK_MODE",
    ]
    .into_iter()
    .filter_map(|name| std::env::var_os(name).map(|value| (name, value)))
}

async fn bounded_read(
    mut stream: impl AsyncRead + Unpin,
    total: Arc<AtomicUsize>,
    limit: usize,
) -> Result<Vec<u8>, IoError> {
    let mut output = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let count = stream.read(&mut chunk).await.map_err(transport)?;
        if count == 0 {
            return Ok(output);
        }
        if total
            .fetch_add(count, Ordering::Relaxed)
            .saturating_add(count)
            > limit
        {
            return Err(IoError::OutputLimit);
        }
        output.extend_from_slice(&chunk[..count]);
    }
}
