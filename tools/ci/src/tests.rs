// SPDX-License-Identifier: Apache-2.0
use super::*;
use flate2::{Compression, write::GzEncoder};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn directory() -> Destination {
    let root = std::env::temp_dir().join(format!(
        "nds-provider-test-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    Destination::create(&root).expect("owned fixture")
}

fn value() -> serde_json::Value {
    serde_json::json!({
        "repository": "NDDev-Technocracy-OpenNetwork/nddev-systeminfo",
        "release": "v0.3.3",
        "linux_asset": "provider.tar.gz",
        "sha256": "0".repeat(64),
        "size": 3,
        "executables": {"NDS_TEST_PROVIDER": "provider/bin/daemon"}
    })
}

fn write_spec(root: &Path, value: &serde_json::Value) -> PathBuf {
    let path = root.join("provider.lock.json");
    fs::write(&path, serde_json::to_vec(value).expect("fixture JSON")).expect("fixture spec");
    path
}

fn spec(root: &Path) -> Spec {
    Spec::read(&write_spec(root, &value()))
        .expect("valid spec")
        .0
}

fn archive(root: &Path, entries: &[(&str, &[u8])]) -> PathBuf {
    let path = root.join("input.tar.gz");
    let encoder = GzEncoder::new(
        File::create(&path).expect("archive file"),
        Compression::fast(),
    );
    let mut archive = tar::Builder::new(encoder);
    for (name, contents) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o755);
        header.set_size(contents.len() as u64);
        assert!(name.len() < 100, "fixture header name");
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        archive
            .append(&header, *contents)
            .expect("actual archive entry");
    }
    archive
        .into_inner()
        .expect("finish TAR")
        .finish()
        .expect("finish gzip");
    path
}

#[test]
fn invalid_identity_paths_and_exports_refuse_before_destination_creation() {
    let fixture = directory();
    for (field, replacement) in [
        ("repository", serde_json::json!("outside-owner/project")),
        (
            "repository",
            serde_json::json!("NDDev-Technocracy-OpenNetwork/../elsewhere"),
        ),
        ("release", serde_json::json!("../latest")),
        ("linux_asset", serde_json::json!("..")),
        ("size", serde_json::json!(ARCHIVE_LIMIT + 1)),
        ("sha256", serde_json::json!("bad")),
        (
            "executables",
            serde_json::json!({"PATH": "provider/bin/daemon"}),
        ),
        (
            "executables",
            serde_json::json!({"NDS_TEST_PROVIDER": "../outside"}),
        ),
        (
            "executables",
            serde_json::json!({"NDS_TEST_PROVIDER": "C:\\outside"}),
        ),
        (
            "executables",
            serde_json::json!({"NDS_TEST_PROVIDER": "provider/bin/daemon\nPATH=bad"}),
        ),
        ("attestation_bundle", serde_json::json!("../outside")),
    ] {
        let mut input = value();
        input[field] = replacement;
        let path = write_spec(&fixture.root, &input);
        let destination = fixture.root.join("not-created");
        assert!(prepare(&path, &destination, None).is_err(), "{field}");
        assert!(!destination.exists());
    }
}

#[test]
fn duplicate_executable_keys_refuse() {
    let fixture = directory();
    let text = serde_json::to_string(&value()).expect("fixture");
    let text = text.replace(
        "\"NDS_TEST_PROVIDER\":\"provider/bin/daemon\"",
        "\"NDS_TEST_PROVIDER\":\"provider/bin/daemon\",\"NDS_TEST_PROVIDER\":\"provider/bin/other\"",
    );
    assert!(text.contains("other"));
    let path = fixture.root.join("duplicate.json");
    fs::write(&path, text).expect("duplicate input");
    assert!(Spec::read(&path).is_err());
}

#[test]
fn a_preexisting_destination_is_preserved() {
    let fixture = directory();
    let marker = fixture.root.join("existing");
    fs::write(&marker, b"preserve").expect("marker");
    assert!(Destination::create(&fixture.root).is_err());
    assert_eq!(fs::read(marker).expect("marker preserved"), b"preserve");
}

#[test]
fn source_size_and_same_length_corruption_refuse_before_extraction() {
    let fixture = directory();
    let mut spec = spec(&fixture.root);
    spec.sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned();
    let input = fixture.root.join("bytes");
    fs::write(&input, b"abc").expect("known SHA input");
    verify_archive(&input, &spec, &Budget::new()).expect("known SHA256");
    fs::write(&input, b"abC").expect("corrupt same length");
    assert!(matches!(
        verify_archive(&input, &spec, &Budget::new()),
        Err(Error::Digest)
    ));
    fs::write(&input, b"abcd").expect("oversized input");
    assert!(matches!(
        verify_archive(&input, &spec, &Budget::new()),
        Err(Error::Digest)
    ));
    assert!(!fixture.root.join("extracted").exists());
}

#[test]
fn release_asset_name_is_unique_and_bound_to_size_and_digest() {
    let fixture = directory();
    let spec = spec(&fixture.root);
    let good = serde_json::json!({"id": 42, "name": spec.linux_asset, "size": spec.size, "digest": format!("sha256:{}", spec.sha256)});
    let release: Release =
        serde_json::from_value(serde_json::json!({"assets": [good.clone()]})).expect("release");
    assert_eq!(select_asset(&spec, &release).expect("exact asset").id, 42);
    for assets in [
        serde_json::json!([]),
        serde_json::json!([good.clone(), good.clone()]),
        serde_json::json!([{ "id": 42, "name": spec.linux_asset, "size": spec.size + 1 }]),
        serde_json::json!([{ "id": 42, "name": spec.linux_asset, "size": spec.size, "digest": "sha256:bad" }]),
    ] {
        let release: Release =
            serde_json::from_value(serde_json::json!({"assets": assets})).expect("release fixture");
        assert!(select_asset(&spec, &release).is_err());
    }
}

#[test]
fn real_gzip_tar_extracts_only_declared_regular_executables() {
    let fixture = directory();
    let spec = spec(&fixture.root);
    let input = archive(
        &fixture.root,
        &[
            ("./provider/bin/daemon", b"actual binary bytes"),
            ("provider/NOTICE", b"unselected notice"),
        ],
    );
    let output = fixture.root.join("output");
    fs::create_dir(&output).expect("owned output");
    let exports = extract(&input, &spec, &output, &Budget::new()).expect("real extraction");
    assert_eq!(exports.len(), 1);
    assert_eq!(exports[0].0, "NDS_TEST_PROVIDER");
    assert_eq!(
        fs::read(&exports[0].1).expect("executable bytes"),
        b"actual binary bytes"
    );
    assert!(!output.join("extracted/provider/NOTICE").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&exports[0].1)
                .expect("executable mode")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }
}

#[test]
fn duplicate_missing_and_link_members_refuse_and_owned_partial_output_is_removed() {
    let fixture = directory();
    let spec = spec(&fixture.root);
    for entries in [
        vec![
            ("provider/bin/daemon", b"one".as_slice()),
            ("provider/bin/daemon", b"two".as_slice()),
        ],
        vec![
            ("provider/bin/daemon", b"one".as_slice()),
            ("./provider/bin/daemon", b"two".as_slice()),
        ],
        vec![("provider/other", b"missing".as_slice())],
        vec![("provider/bin/daemon", b"".as_slice())],
        vec![("../outside", b"traversal".as_slice())],
        vec![("/outside", b"absolute".as_slice())],
    ] {
        let input = archive(&fixture.root, &entries);
        let output = fixture.root.join("output");
        {
            let destination = Destination::create(&output).expect("owned destination");
            assert!(extract(&input, &spec, &destination.root, &Budget::new()).is_err());
        }
        assert!(!output.exists());
    }
    let path = fixture.root.join("link.tar.gz");
    let encoder = GzEncoder::new(
        File::create(&path).expect("archive file"),
        Compression::fast(),
    );
    let mut archive = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o755);
    header.set_link_name("../../outside").expect("link bytes");
    archive
        .append_data(&mut header, "provider/bin/daemon", std::io::empty())
        .expect("link member");
    archive.into_inner().expect("TAR").finish().expect("gzip");
    let output = Destination::create(&fixture.root.join("link-output")).expect("owned output");
    assert!(extract(&path, &spec, &output.root, &Budget::new()).is_err());
    assert!(!fixture.root.join("outside").exists());
}

#[test]
fn selected_metadata_requires_one_real_package_and_preserves_nested_lock_location() {
    let fixture = directory();
    let path = fixture.root.join("metadata.json");
    let package = serde_json::json!({"name": "nddev-device-sync-sysinfo", "manifest_path": fixture.root.join("source/Cargo.toml")});
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({"packages": [package.clone()]})).expect("metadata"),
    )
    .expect("metadata file");
    assert_eq!(
        selected_spec(&path, "sysinfo").expect("selected source"),
        fixture.root.join("source/provider.lock.json")
    );
    fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({"packages": [package.clone(), package]}))
            .expect("metadata"),
    )
    .expect("duplicate metadata");
    assert!(selected_spec(&path, "sysinfo").is_err());
    assert!(selected_spec(&path, "../sysinfo").is_err());
}
