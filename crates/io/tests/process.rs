use nddev_device_sync_adapter_io::{CancellationToken, IoError, NativeIo, ProcessRequest};
use std::{
    ffi::OsString,
    io::Write,
    time::{Duration, Instant},
};

#[cfg(unix)]
#[tokio::test]
async fn native_nowait_retains_the_exit_status_for_the_owned_reaper() {
    use process_wrap::tokio::{CommandWrap, KillOnDrop, ProcessGroup};
    use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
    let mut changed =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child()).unwrap();
    let mut command = CommandWrap::with_new("/bin/sh", |command| {
        command.args(["-c", "exit 0"]);
    });
    command.wrap(KillOnDrop).wrap(ProcessGroup::leader());
    let mut child = command.spawn().unwrap();
    let pid = Pid::from_raw(child.id().unwrap().try_into().unwrap()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if waitid(
                WaitId::Pid(pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
            )
            .expect("observe without reaping")
            .is_some()
            {
                break;
            }
            changed.recv().await.unwrap();
        }
        if let Err(error) = child.start_kill() {
            let missing = error.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error());
            #[cfg(target_os = "macos")]
            let missing = missing || {
                errno::set_errno(errno::Errno(0));
                error.raw_os_error() == Some(rustix::io::Errno::PERM.raw_os_error())
                    && libproc::processes::pids_by_type(
                        libproc::processes::ProcFilter::ByProgramGroup {
                            pgrpid: pid.as_raw_pid() as u32,
                        },
                    )
                    .unwrap()
                    .iter()
                    .all(|id| *id == 0 || *id == pid.as_raw_pid() as u32)
            };
            assert!(missing, "terminate owned group: {:?}", error.raw_os_error());
        }
        assert!(
            child
                .wait()
                .await
                .expect("reap original exit status")
                .success()
        );
    })
    .await
    .expect("native status notification deadline");
}

fn request(mode: &str) -> ProcessRequest {
    ProcessRequest {
        executable: std::env::current_exe().unwrap(),
        arguments: ["--exact", mode, "--nocapture"]
            .into_iter()
            .map(OsString::from)
            .collect(),
        directory: None,
        timeout: Duration::from_secs(2),
        max_output_bytes: 4096,
    }
}

// These run as real OS child processes. They exercise transport failure paths,
// not a substitute for acceptance against installed native providers.
#[test]
fn child_unicode() {
    println!("Native UTF-8: Проверка Android");
    eprintln!("stderr is separate");
}

#[test]
#[ignore = "only launched by bounded process acceptance"]
fn child_flood() {
    loop {
        std::io::stdout().write_all(&[b'x'; 4096]).unwrap();
        std::io::stderr().write_all(&[b'y'; 4096]).unwrap();
    }
}

#[test]
#[ignore = "only launched by bounded process acceptance"]
fn child_wait() {
    std::thread::sleep(Duration::from_secs(30));
}

fn ignored_request(mode: &str) -> ProcessRequest {
    let mut request = request(mode);
    request.arguments.push("--ignored".into());
    request
}

#[tokio::test]
async fn preserves_exit_status_and_separate_unicode_streams() {
    let output = NativeIo::new(1)
        .unwrap()
        .process_handle()
        .process(request("child_unicode"), CancellationToken::new())
        .await
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Проверка Android")
    );
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("stderr is separate")
    );
}

#[tokio::test]
async fn bounds_aggregate_output_and_releases_admission() {
    let io = NativeIo::new(1).unwrap().process_handle();
    assert!(matches!(
        io.process(ignored_request("child_flood"), CancellationToken::new())
            .await,
        Err(IoError::OutputLimit)
    ));
    assert!(
        io.process(request("child_unicode"), CancellationToken::new())
            .await
            .unwrap()
            .status
            .success()
    );
}

#[tokio::test]
async fn rejects_overload_and_cancels_owned_process() {
    let io = NativeIo::new(1).unwrap().process_handle();
    let token = CancellationToken::new();
    let operation = io.process(ignored_request("child_wait"), token.clone());
    tokio::pin!(operation);
    tokio::select! {
        _ = &mut operation => panic!("sleeping child exited early"),
        () = tokio::time::sleep(Duration::from_millis(100)) => {}
    }
    assert!(matches!(
        io.process(request("child_unicode"), CancellationToken::new())
            .await,
        Err(IoError::Busy)
    ));
    token.cancel();
    assert!(matches!(operation.await, Err(IoError::Cancelled)));
    assert!(
        io.process(request("child_unicode"), CancellationToken::new())
            .await
            .unwrap()
            .status
            .success()
    );
}

#[tokio::test]
async fn deadline_covers_child_exit_and_pipe_drain() {
    let mut request = ignored_request("child_wait");
    request.timeout = Duration::from_millis(100);
    let start = Instant::now();
    assert!(matches!(
        NativeIo::new(1)
            .unwrap()
            .process_handle()
            .process(request, CancellationToken::new())
            .await,
        Err(IoError::Timeout)
    ));
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
#[ignore = "only launched as a real native credential consumer"]
fn child_secret_input() {
    use std::io::Read;
    let credential = std::env::var("GH_TOKEN").unwrap();
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    assert_eq!(input, credential.as_bytes());
    assert!(std::env::var_os("GH_DEBUG").is_none());
    print!("consumed");
}

#[tokio::test]
async fn actual_native_stdin_and_official_credential_environment() {
    use nddev_device_sync_adapter_io::{CredentialEnvironment, ProcessInput};
    use zeroize::Zeroizing;
    let io = NativeIo::new(1).unwrap().process_handle();
    let input = ProcessInput {
        stdin: Zeroizing::new(b"owned private native input".to_vec()),
        credential: Some((
            CredentialEnvironment::GitHub,
            Zeroizing::new("owned private native input".into()),
        )),
    };
    let output = io
        .process_input(
            ignored_request("child_secret_input"),
            input,
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("consumed")
    );
}

#[tokio::test]
async fn native_private_input_is_bounded_before_spawn() {
    use nddev_device_sync_adapter_io::ProcessInput;
    use zeroize::Zeroizing;
    let io = NativeIo::new(1).unwrap().process_handle();
    let request = request("child_unicode");
    let input = ProcessInput {
        stdin: Zeroizing::new(vec![0; 16_385]),
        credential: None,
    };
    assert!(matches!(
        io.process_input(request, input, CancellationToken::new())
            .await,
        Err(IoError::InvalidConfiguration)
    ));
}

#[test]
#[ignore = "launched as the actual isolated Git-profile child"]
fn child_git_profile() {
    assert_eq!(
        std::env::var("NDS_GITHUB_AUTHORIZATION").unwrap(),
        "Authorization: Basic generated-invalid-fixture"
    );
    assert!(std::env::var_os("GH_TOKEN").is_none());
    assert!(std::env::var_os("GIT_TRACE").is_none());
    for (name, expected) in [
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
    ] {
        assert_eq!(std::env::var(name).unwrap(), expected);
    }
    assert_eq!(
        std::env::var("GIT_CONFIG_GLOBAL").unwrap(),
        if cfg!(windows) { "NUL" } else { "/dev/null" }
    );
    print!("isolated Git configuration");
}

#[tokio::test]
async fn git_profile_does_not_inherit_global_configuration_or_provider_tokens() {
    let output = NativeIo::new(1)
        .unwrap()
        .process_handle()
        .git_process(
            ignored_request("child_git_profile"),
            Some(zeroize::Zeroizing::new(
                "Authorization: Basic generated-invalid-fixture".into(),
            )),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("isolated Git configuration")
    );
}

#[test]
#[ignore = "launched as an actual credential-free Git-profile child"]
fn child_git_local_profile() {
    assert!(std::env::var_os("NDS_GITHUB_AUTHORIZATION").is_none());
    assert!(std::env::var_os("GH_TOKEN").is_none());
    assert_eq!(std::env::var("GIT_CONFIG_NOSYSTEM").unwrap(), "1");
    assert_eq!(std::env::var("GIT_TERMINAL_PROMPT").unwrap(), "0");
    print!("no Git credential");
}

#[tokio::test]
async fn local_git_reads_have_the_same_isolation_without_an_authorization_header() {
    let output = NativeIo::new(1)
        .unwrap()
        .process_handle()
        .git_process(
            ignored_request("child_git_local_profile"),
            None,
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("no Git credential")
    );
}
