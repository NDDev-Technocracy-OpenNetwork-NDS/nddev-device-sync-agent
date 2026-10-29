//! Cargo boundary regression; real managed-cache packaging is qualified separately.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn package(mismatched_manifest: bool, managed: bool) {
    let owned = tempfile::tempdir().unwrap();
    let root = owned.path();
    let manifest = root.join("Cargo.toml");
    let other = root.join("other.toml");
    fs::write(&manifest, "fixture").unwrap();
    fs::write(&other, "different fixture").unwrap();
    let artifact = root.join("actual-worker");
    let bytes = b"owned worker bytes, never executed";
    fs::write(&artifact, bytes).unwrap();
    let fixture = root.join("cargo.json");
    fs::write(&fixture, serde_json::to_vec(&json!({
        "managed": managed,
                "metadata": {
            "target_directory":root.join("uninitialized-managed-target"),
            "packages":[{
                "name":"nddev-device-sync-gds", "version":"0.0.1-alpha.7",
                "source":format!("git+https://github.com/NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-gds?rev={}#{}","a".repeat(40),"a".repeat(40)),
                "manifest_path":manifest,
                "targets":[{"name":"nds-gds-readonly-worker"}]
            }]
        },
        "artifact": {
            "reason":"compiler-artifact",
            "manifest_path":if mismatched_manifest {&other} else {&manifest},
            "target":{"name":"nds-gds-readonly-worker","kind":["bin"]},
            "executable":artifact
        }
    })).unwrap()).unwrap();
    let cargo = root.join("cargo");
    fs::write(
        &cargo,
        r#"#!/usr/bin/python3
import json, os, sys
with open(os.environ['NDS_PACKAGE_FIXTURE']) as source:
    fixture = json.load(source)
if sys.argv[1] == 'metadata':
    print(json.dumps(fixture['metadata']))
else:
    assert sys.argv[1] == 'build'
    if fixture['managed']:
        assert '--target-dir' not in sys.argv
        for name in ('CARGO_TARGET_DIR', 'CARGO_BUILD_TARGET_DIR', 'CARGO_BUILD_BUILD_DIR'):
            assert name not in os.environ
    else:
        target = sys.argv[sys.argv.index('--target-dir') + 1]
        assert target.startswith(fixture['metadata']['target_directory'] + '/providers/gds/')
        assert os.environ['CARGO_BUILD_BUILD_DIR'] == target + '/build'
    assert '--locked' in sys.argv and '--release' in sys.argv
    assert '--message-format=json-render-diagnostics' in sys.argv
    print(json.dumps(fixture['artifact']))
    print(json.dumps({'reason':'build-finished','success':True}))
"#,
    )
    .unwrap();
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o700)).unwrap();
    let bundle = root.join("bundle");
    let mut command = Command::new(env!("CARGO_BIN_EXE_nds-package-gds-worker"));
    if managed {
        command.env("NDS_CACHE_FRONTENDS", root);
    } else {
        command.env_remove("NDS_CACHE_FRONTENDS");
    }
    let result = command
        .args(["--bundle", bundle.to_str().unwrap()])
        .env("PATH", root)
        .env("NDS_PACKAGE_FIXTURE", fixture)
        .env("CARGO_TARGET_DIR", root.join("parent-final"))
        .env("CARGO_BUILD_TARGET_DIR", root.join("parent-target"))
        .env("CARGO_BUILD_BUILD_DIR", root.join("parent-build"))
        .output()
        .unwrap();
    let staged = bundle.join("nds-gds-readonly-worker");
    if mismatched_manifest {
        assert!(!result.status.success());
        assert!(!staged.exists());
        assert!(!bundle.join("nds-gds-worker.build.json").exists());
    } else {
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(&staged).unwrap(), bytes);
        let receipt: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(
            receipt["sha256"],
            base16ct::lower::encode_string(&Sha256::digest(bytes))
        );
        assert_eq!(
            receipt["host_build_environment"]["NDS_GDS_WORKER_SHA256"],
            receipt["sha256"]
        );
        assert_eq!(
            fs::metadata(staged).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(!root.join("uninitialized-managed-target").exists());
    }
}

#[test]
fn managed_build_uses_its_reported_artifact_without_inheriting_host_placement() {
    package(false, true);
}

#[test]
fn an_artifact_of_another_manifest_cannot_be_packaged() {
    package(true, true);
}

#[test]
fn standalone_build_preserves_separate_placement_and_uses_the_reported_artifact() {
    package(false, false);
}
