//! Build-time packaging of the fixed Rust worker from the locked dependency.
fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if let Err(error) = qualified::package() {
        eprintln!("gds_worker_packaging_failed: {error}");
        std::process::exit(1);
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        eprintln!("gds_worker_packaging_failed: unsupported_host");
        std::process::exit(1);
    }
}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod qualified {
    use nddev_device_sync_agent::GDS_WORKER_MAX_BYTES;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::{Read, Write},
        path::PathBuf,
        process::{Command, Stdio},
    };

    pub(super) fn package() -> Result<(), Box<dyn std::error::Error>> {
        let mut args = std::env::args_os().skip(1);
        if args.next().is_none_or(|arg| arg != "--bundle") {
            return Err("expected --bundle <absolute staging directory>".into());
        }
        let bundle = PathBuf::from(args.next().ok_or("missing staging directory")?);
        if !bundle.is_absolute() || args.next().is_some() {
            return Err("one absolute staging directory is required".into());
        }
        let target = "x86_64-unknown-linux-gnu";
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let metadata = Command::new("cargo")
            .args(["metadata", "--locked", "--format-version", "1"])
            .current_dir(&root)
            .stdin(Stdio::null())
            .output()?;
        if !metadata.status.success() {
            return Err("locked dependency metadata failed".into());
        }
        let metadata: Value = serde_json::from_slice(&metadata.stdout)?;
        let packages = metadata["packages"]
            .as_array()
            .ok_or("invalid dependency metadata")?;
        let found = packages
            .iter()
            .filter(|item| item["name"] == "nddev-device-sync-gds")
            .collect::<Vec<_>>();
        if found.len() != 1 {
            return Err("one canonical GDS package is required".into());
        }
        let gds = found[0];
        let source = gds["source"]
            .as_str()
            .ok_or("GDS requires an immutable Git source")?;
        let revision = source
            .rsplit_once('#')
            .ok_or("GDS requires an immutable Git revision")?
            .1;
        if !source.starts_with(
            "git+https://github.com/NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-gds?",
        ) || revision.len() != 40
            || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !source.contains(&format!("rev={revision}#"))
        {
            return Err("GDS source is not the canonical immutable pin".into());
        }
        let manifest = PathBuf::from(
            gds["manifest_path"]
                .as_str()
                .ok_or("missing GDS manifest")?,
        );
        if !gds["targets"]
            .as_array()
            .ok_or("missing GDS targets")?
            .iter()
            .any(|target| target["name"] == "nds-gds-readonly-worker")
        {
            return Err("the pinned GDS package contains no Rust worker".into());
        }
        fs::create_dir_all(&bundle)?;
        let bundle = bundle.canonicalize()?;
        // Keep the nested build's lock separate from the host and reuse its
        // immutable provider artifacts across different bundle staging paths.
        let build = PathBuf::from(
            metadata["target_directory"]
                .as_str()
                .ok_or("missing Cargo target directory")?,
        )
        .join("providers/gds")
        .join(revision);
        let mut command = Command::new("cargo");
        command
            .args([
                "build",
                "--locked",
                "--release",
                "--bin",
                "nds-gds-readonly-worker",
                "--target",
                target,
                "--message-format=json-render-diagnostics",
                "--manifest-path",
            ])
            .arg(&manifest)
            .current_dir(&root);
        if std::env::var_os("NDS_CACHE_FRONTENDS").is_some() {
            // The managed frontend owns nested source-scoped placement and
            // leases. Host-only final/intermediate overrides must not force the
            // provider into its parent's target or an uninitialized cache path.
            command
                .env_remove("CARGO_TARGET_DIR")
                .env_remove("CARGO_BUILD_TARGET_DIR")
                .env_remove("CARGO_BUILD_BUILD_DIR");
        } else {
            command
                .arg("--target-dir")
                .arg(&build)
                .env("CARGO_BUILD_BUILD_DIR", build.join("build"));
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        const BUILD_OUTPUT_LIMIT: u64 = 32 * 1024 * 1024;
        let mut output = Vec::new();
        let read = child
            .stdout
            .take()
            .ok_or("missing Cargo build output")?
            .take(BUILD_OUTPUT_LIMIT + 1)
            .read_to_end(&mut output);
        if read.is_err() || output.len() as u64 > BUILD_OUTPUT_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Cargo build output exceeded its bound or could not be read".into());
        }
        if !child.wait()?.success() {
            return Err("locked GDS worker build failed".into());
        }
        let manifest = manifest.canonicalize()?;
        let mut worker = None;
        for line in output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let event: Value = serde_json::from_slice(line)?;
            if event["reason"] != "compiler-artifact"
                || event["target"]["name"] != "nds-gds-readonly-worker"
                || !event["target"]["kind"]
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
            {
                continue;
            }
            let owner = PathBuf::from(
                event["manifest_path"]
                    .as_str()
                    .ok_or("missing worker artifact manifest")?,
            )
            .canonicalize()?;
            if owner != manifest || worker.is_some() {
                return Err("worker artifact is not uniquely owned by the pinned manifest".into());
            }
            let path = PathBuf::from(
                event["executable"]
                    .as_str()
                    .ok_or("missing worker executable artifact")?,
            );
            if !path.is_absolute() {
                return Err("worker artifact path must be absolute".into());
            }
            worker = Some(path);
        }
        let worker = worker.ok_or("Cargo reported no canonical worker artifact")?;
        let size = fs::metadata(&worker)?.len();
        if size == 0 || size > GDS_WORKER_MAX_BYTES {
            return Err("worker size is outside the artifact bound".into());
        }
        let staged = bundle.join(".nds-gds-readonly-worker.tmp");
        let mut source_file = fs::File::open(&worker)?;
        let mut staged_file = fs::File::create(&staged)?;
        let mut hash = Sha256::new();
        let mut chunk = [0; 16 * 1024];
        let mut count = 0u64;
        loop {
            let bytes = source_file.read(&mut chunk)?;
            if bytes == 0 {
                break;
            }
            count = count
                .checked_add(bytes as u64)
                .ok_or("worker size overflow")?;
            if count > GDS_WORKER_MAX_BYTES {
                return Err("worker exceeded the artifact bound".into());
            }
            hash.update(&chunk[..bytes]);
            staged_file.write_all(&chunk[..bytes])?;
        }
        if count != size {
            return Err("worker changed during packaging".into());
        }
        staged_file.sync_all()?;
        drop(staged_file);
        let digest = base16ct::lower::encode_string(&hash.finalize());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;
        }
        fs::rename(staged, bundle.join("nds-gds-readonly-worker"))?;
        let receipt = json!({"schema_version":1,"worker":"nds-gds-readonly-worker","target":target,"source":source,"version":gds["version"],"sha256":digest,"host_build_environment":{"NDS_GDS_WORKER_SHA256":digest}});
        fs::write(
            bundle.join("nds-gds-worker.build.json"),
            serde_json::to_vec_pretty(&receipt)?,
        )?;
        println!("{receipt}");
        Ok(())
    }
}
