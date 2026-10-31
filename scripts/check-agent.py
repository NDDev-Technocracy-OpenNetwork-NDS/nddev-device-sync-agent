#!/usr/bin/env python3
"""Qualify the assembled agent against an isolated real sysinfo daemon."""
import json
import hashlib
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
metadata = subprocess.run(
    ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
    cwd=root, text=True, capture_output=True, check=True, timeout=60,
)
bundle = Path(json.loads(metadata.stdout)["target_directory"]) / "agent-worker-fixture"
artifact = subprocess.run(
    ["cargo", "run", "--locked", "-p", "nddev-device-sync-agent", "--bin",
     "nds-package-github-worker", "--", "--bundle", str(bundle)],
    cwd=root, text=True, capture_output=True, check=True, timeout=300,
)
receipt = json.loads(artifact.stdout.splitlines()[-1])
worker = bundle / "nds-github-readonly-worker"
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
        subprocess.run([str(executable), "--ignored", "native_github_query_uses_core_observation_and_projection"],
                       env=environment, check=True, timeout=30)
        # Invalid owned copies must fail before execution, even with an executable
        # named gds in PATH and a runtime attempt to replace the embedded digest.
        for case in ["corrupt", "missing", "wrong-sibling", "symlink", "oversized"]:
            with tempfile.TemporaryDirectory(prefix="nds-worker-admission-") as invalid_dir:
                invalid = Path(invalid_dir)
                owned_host = invalid / "agent-acceptance"
                owned_worker = invalid / worker.name
                marker = invalid / "executed"
                shutil.copy2(executable, owned_host)
                shutil.copy2(worker, owned_worker)
                fake = ("#!/bin/sh\ntouch '" + str(marker) + "'\nexit 0\n").encode()
                path_dir = invalid / "path"
                path_dir.mkdir()
                fallback = path_dir / "gds"
                fallback.write_bytes(fake)
                fallback.chmod(0o700)
                if case == "corrupt":
                    owned_worker.write_bytes(fake)
                elif case == "missing":
                    owned_worker.unlink()
                elif case == "wrong-sibling":
                    owned_worker.rename(invalid / "misplaced-worker")
                elif case == "symlink":
                    owned_worker.rename(invalid / "outside-worker")
                    owned_worker.symlink_to(invalid / "outside-worker")
                elif case == "oversized":
                    with owned_worker.open("r+b") as handle:
                        handle.truncate(128 * 1024 * 1024 + 1)
                subprocess.run(
                    [str(owned_host), "--ignored", "github_worker_admission_has_no_path_fallback"],
                    env={**environment, "PATH":str(path_dir), "NDS_INVALID_WORKER":case,
                         "NDS_GITHUB_EXECUTION_MARKER":str(marker),
                         "NDS_GITHUB_WORKER_SHA256":hashlib.sha256(fake).hexdigest()},
                    check=True, timeout=15)
                if marker.exists():
                    raise RuntimeError("invalid/fallback worker executed")
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
        subprocess.run([str(executable), "--ignored", "invalidating_a_module_cancels_its_actual_query_without_refreshing_health"],
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
print("Assembled agent: packaged Rust worker, five pre-execution refusals/no PATH fallback, real sysinfo queries, core observations, cancellation/timeout and OTLP outcomes passed")
