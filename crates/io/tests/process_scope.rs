#![cfg(unix)]
use nddev_device_sync_adapter_io::{CancellationToken, NativeIo, ProcessRequest};
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

fn request(receipt: &Path, parent_waits: bool) -> ProcessRequest {
    let script = if parent_waits {
        r#"sleep 30 >/dev/null 2>&1 & printf '%s %s\n' "$$" "$!" > "$1"; wait"#
    } else {
        r#"sleep 30 >/dev/null 2>&1 & printf '%s %s\n' "$$" "$!" > "$1"; exit 0"#
    };
    ProcessRequest {
        executable: "/bin/sh".into(),
        arguments: vec![
            "-c".into(),
            script.into(),
            "native-scope-test".into(),
            receipt.as_os_str().into(),
        ],
        directory: None,
        timeout: Duration::from_secs(3),
        max_output_bytes: 1024,
    }
}

fn read_receipt(path: &Path) -> Option<(u32, u32)> {
    let text = std::fs::read_to_string(path).ok()?;
    let (leader, helper) = text.strip_suffix('\n')?.split_once(' ')?;
    let leader = leader.parse::<u32>().ok()?;
    let helper = helper.parse::<u32>().ok()?;
    (leader > 1 && helper > 1 && leader != helper).then_some((leader, helper))
}

async fn terminated(pid: u32) {
    let pid_arg = pid.to_string();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let output = Command::new("ps")
            .args(["-o", "stat=", "-p", &pid_arg])
            .output()
            .unwrap();
        let state = String::from_utf8(output.stdout).unwrap();
        // An orphan zombie awaits the OS reaper but cannot keep doing work.
        if !output.status.success() || state.trim().is_empty() || state.trim().starts_with('Z') {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "owned process {pid} survived operation lifetime with state {state:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn successful_parent_exit_cannot_leave_a_closed_pipe_helper_running() {
    let fixture = tempfile::tempdir().unwrap();
    let receipt = fixture.path().join("helper.pid");
    let output = NativeIo::new(1)
        .unwrap()
        .process_handle()
        .process(request(&receipt, false), CancellationToken::new())
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "preserve the real parent exit status"
    );
    let (_, helper) = read_receipt(&receipt).expect("complete helper receipt");
    terminated(helper).await;
}

#[tokio::test]
async fn dropping_the_caller_terminates_owned_parent_and_helper_scope() {
    let fixture = tempfile::tempdir().unwrap();
    let receipt = fixture.path().join("helper.pid");
    let request = request(&receipt, true);
    let io = NativeIo::new(1).unwrap().process_handle();
    let task = tokio::spawn(async move { io.process(request, CancellationToken::new()).await });
    let deadline = Instant::now() + Duration::from_secs(1);
    let (leader, helper) = loop {
        if let Some(pids) = read_receipt(&receipt) {
            break pids;
        }
        assert!(
            Instant::now() < deadline,
            "process fixture did not publish its PIDs"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let group = Command::new("ps")
        .args(["-o", "pgid=", "-p", &helper.to_string()])
        .output()
        .unwrap();
    assert!(group.status.success(), "helper must be alive before abort");
    assert_eq!(
        String::from_utf8(group.stdout)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap(),
        leader,
        "helper must belong to the owned process group"
    );
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    tokio::join!(terminated(leader), terminated(helper));
}
