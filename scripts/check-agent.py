#!/usr/bin/env python3
"""Qualify the assembled agent against an isolated real sysinfo daemon."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

if sys.platform != "linux":
    raise SystemExit("This provider qualification requires Linux")
root = Path(__file__).resolve().parent.parent
provider = Path(os.environ["NDS_TEST_SYSINFO_DAEMON"]).resolve(strict=True)
artifact = subprocess.run(
    ["cargo", "run", "--locked", "-p", "nddev-device-sync-agent", "--bin",
     "nds-package-gds-worker", "--", "--bundle", str(root / "target/agent-worker-fixture")],
    cwd=root, text=True, capture_output=True, check=True, timeout=300,
)
receipt = json.loads(artifact.stdout.splitlines()[-1])
worker = root / "target/agent-worker-fixture/nds-gds-readonly-worker"
build_environment = {**os.environ, **receipt["host_build_environment"]}
build = subprocess.run(
    ["cargo", "test", "--locked", "-p", "nddev-device-sync-agent", "--test", "lifecycle",
     "--no-run", "--message-format=json"],
    cwd=root, env=build_environment, text=True, capture_output=True, check=True, timeout=180,
)
executables = [item["executable"] for line in build.stdout.splitlines()
               if (item := json.loads(line)).get("reason") == "compiler-artifact"
               and item.get("executable") and item.get("target", {}).get("name") == "lifecycle"
               and "test" in item.get("target", {}).get("kind", [])]
if len(executables) != 1:
    raise RuntimeError("expected one agent acceptance executable")
with tempfile.TemporaryDirectory(prefix="nds-agent-provider-") as temporary:
    fixture = Path(temporary)
    fixture.chmod(0o700)
    # Execute an owned copy beside the verified worker, matching the NDS bundle.
    import shutil
    shutil.copy2(worker, fixture / worker.name)
    executable = fixture / "agent-acceptance"
    shutil.copy2(executables[0], executable)
    environment = {**os.environ, "XDG_RUNTIME_DIR": temporary, "NDS_ISOLATED_PROVIDER": "1"}
    repository = fixture / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "--quiet", "--initial-branch=main", str(repository)],
                   check=True, timeout=10)
    environment.update(
        NDS_AGENT_TEST_REPOSITORY=str(repository),
    )
    for key in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"]:
        environment.pop(key, None)
    daemon = subprocess.Popen([str(provider)], env=environment, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while not (fixture / "rldyour-sysinfo.sock").exists():
            if daemon.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("native provider did not become ready")
            time.sleep(0.02)
        subprocess.run([str(executable), "--ignored", "native_query_updates_only_its_own_observation"],
                       env=environment, check=True, timeout=30)
        subprocess.run([str(executable), "--ignored", "cached_missing_provider_is_not_a_fresh_native_observation"],
                       env={**environment, "PATH": ""}, check=True, timeout=30)
        subprocess.run([str(executable), "--ignored", "native_gds_query_uses_core_observation_and_projection"],
                       env=environment, check=True, timeout=30)
        # Pause only this owned daemon to exercise a genuine stalled local I/O.
        daemon.send_signal(signal.SIGSTOP)
        deadline = time.monotonic() + 2
        while True:
            status = Path(f"/proc/{daemon.pid}/status").read_text()
            if any(line.startswith("State:") and "T (stopped)" in line for line in status.splitlines()):
                break
            if time.monotonic() >= deadline or daemon.poll() is not None:
                raise RuntimeError("owned native provider did not pause")
            time.sleep(0.02)
        subprocess.run([str(executable), "--ignored", "closing_an_in_flight_query_preserves_unobserved_state"],
                       env={**environment, "NDS_PAUSED_PROVIDER": "1"}, check=True, timeout=15)
        subprocess.run([str(executable), "--ignored", "native_timeout_uses_core_failure_observation_and_error_span"],
                       env={**environment, "NDS_PAUSED_PROVIDER": "1"}, check=True, timeout=15)
    finally:
        daemon.send_signal(signal.SIGCONT)
        daemon.terminate()
        try:
            daemon.wait(timeout=3)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait(timeout=3)
print("Assembled agent: real sysinfo/GDS queries, core observations, cancellation/timeout and OTLP outcomes passed")
