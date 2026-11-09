// SPDX-License-Identifier: Apache-2.0
//! Execution-host tooling for immutable public native-provider inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use flate2::read::MultiGzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const INPUT_LIMIT: u64 = 1_000_000;
const ARCHIVE_LIMIT: u64 = 100_000_000;
const UNPACKED_LIMIT: u64 = 1_000_000_000;
const ENTRY_LIMIT: usize = 4096;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("invalid provider input: {0}")]
    Input(&'static str),
    #[error("provider input exceeded its resource budget")]
    Budget,
    #[error("native HTTPS provider failed with exit code {0:?}")]
    Transport(Option<i32>),
    #[error("provider size or digest differs from the immutable lock")]
    Digest,
    #[error("provider attestation verification failed")]
    Attestation,
    #[error("native provider archive is invalid")]
    Archive,
    #[error("native provider I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("native provider JSON is invalid")]
    Json(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, Error>;

fn require(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::Input(message))
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn digest_text(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || b"abcdef".contains(&byte))
}

fn relative_path(value: &str) -> Result<PathBuf> {
    require(
        !value.is_empty() && value.len() <= 4096,
        "executable path length",
    )?;
    require(
        !value.starts_with('/') && !value.contains(['\\', ':', '\r', '\n', '\0']),
        "executable path",
    )?;
    require(
        value
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | "..")),
        "executable path component",
    )?;
    Ok(PathBuf::from(value))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file() && metadata.len() > 0 && metadata.len() <= maximum,
        "bounded regular input file",
    )?;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    require(
        !bytes.is_empty() && bytes.len() as u64 <= maximum,
        "input file grew",
    )?;
    Ok(bytes)
}

#[derive(Debug, Deserialize)]
struct Spec {
    repository: String,
    release: String,
    linux_asset: String,
    sha256: String,
    size: u64,
    #[serde(deserialize_with = "unique_executables")]
    executables: BTreeMap<String, String>,
    #[serde(default)]
    attestation: bool,
    attestation_bundle: Option<PathBuf>,
    source_commit: Option<String>,
}

fn unique_executables<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded executable map without duplicate names")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut result = BTreeMap::new();
            while let Some((name, path)) = map.next_entry::<String, String>()? {
                if result.len() >= 64 || result.insert(name, path).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive executable map",
                    ));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Visitor)
}

impl Spec {
    fn read(path: &Path) -> Result<(Self, Option<PathBuf>)> {
        let path = path.canonicalize()?;
        let spec: Self = serde_json::from_slice(&read_bounded(&path, INPUT_LIMIT)?)?;
        let Some((owner, name)) = spec.repository.split_once('/') else {
            return Err(Error::Input("provider repository"));
        };
        require(
            matches!(owner, "NDDev-OpenNetwork" | "NDDev-Technocracy-OpenNetwork")
                && !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "provider repository",
        )?;
        require(
            identifier(&spec.release) && identifier(&spec.linux_asset),
            "provider release or asset",
        )?;
        require(
            !matches!(spec.linux_asset.as_str(), ".transport" | "extracted"),
            "reserved asset name",
        )?;
        require(
            digest_text(&spec.sha256, 64) && spec.size > 0 && spec.size <= ARCHIVE_LIMIT,
            "provider size or digest",
        )?;
        require(
            !spec.executables.is_empty() && spec.executables.len() <= 64,
            "executable map",
        )?;
        for (variable, relative) in &spec.executables {
            require(
                variable.starts_with("NDS_TEST_")
                    && variable.len() > 9
                    && variable.len() <= 128
                    && variable
                        .bytes()
                        .all(|byte| byte.is_ascii_uppercase() || byte == b'_'),
                "executable variable",
            )?;
            relative_path(relative)?;
            if !spec.linux_asset.ends_with(".tar.gz") {
                require(relative == &spec.linux_asset, "raw executable path")?;
            }
        }
        let bundle = if let Some(relative) = &spec.attestation_bundle {
            require(spec.attestation, "bundle requires attestation")?;
            let source = spec.source_commit.as_deref().unwrap_or("");
            require(digest_text(source, 40), "attested source commit")?;
            let relative = relative_path(
                relative
                    .to_str()
                    .ok_or(Error::Input("bundle path encoding"))?,
            )?;
            let parent = path.parent().ok_or(Error::Input("specification parent"))?;
            let resolved = parent.join(relative).canonicalize()?;
            require(
                resolved.starts_with(parent),
                "attestation bundle escapes the specification",
            )?;
            read_bounded(&resolved, INPUT_LIMIT)?;
            Some(resolved)
        } else {
            None
        };
        Ok((spec, bundle))
    }
}

struct Destination {
    root: PathBuf,
    retained: bool,
}

impl Destination {
    fn create(path: &Path) -> Result<Self> {
        require(
            path.to_str()
                .is_some_and(|text| !text.contains(['\r', '\n', '\0'])),
            "destination encoding",
        )?;
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let parent = absolute
            .parent()
            .ok_or(Error::Input("destination parent"))?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.recursive(true).create(parent)?;
        builder.recursive(false).create(&absolute)?;
        let mut destination = Self {
            root: absolute,
            retained: false,
        };
        destination.root = destination.root.canonicalize()?;
        require(
            destination
                .root
                .to_str()
                .is_some_and(|text| !text.contains(['\r', '\n', '\0'])),
            "canonical destination encoding",
        )?;
        Ok(destination)
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        if !self.retained {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

struct Budget(Instant);
impl Budget {
    fn new() -> Self {
        Self(Instant::now() + Duration::from_secs(180))
    }
    fn remaining(&self) -> Result<Duration> {
        self.0
            .checked_duration_since(Instant::now())
            .ok_or(Error::Budget)
    }
}

fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn wait_process(mut command: Command, budget: &Budget, output: Option<(&Path, u64)>) -> Result<()> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    loop {
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        };
        if let Some(status) = status {
            return if status.success() {
                Ok(())
            } else {
                Err(Error::Transport(status.code()))
            };
        }
        let excessive = output.is_some_and(|(path, limit)| {
            fs::metadata(path).is_ok_and(|metadata| metadata.len() > limit)
        });
        if excessive || budget.remaining().is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Budget);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn download(
    url: &str,
    accept: &str,
    destination: &Path,
    headers: &Path,
    maximum: u64,
    budget: &Budget,
) -> Result<()> {
    let seconds = budget.remaining()?.as_secs().max(1).to_string();
    let mut command = Command::new("curl");
    command.args([
        "--disable",
        "--fail",
        "--location",
        "--silent",
        "--show-error",
        "--globoff",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--max-redirs",
        "5",
        "--connect-timeout",
        "20",
        "--max-time",
        &seconds,
        "--retry",
        "2",
        "--retry-max-time",
        &seconds,
        "--max-filesize",
        &maximum.to_string(),
        "--header",
        &format!("Accept: {accept}"),
        "--header",
        "Accept-Encoding: identity",
        "--header",
    ]);
    let header_argument = format!(
        "@{}",
        headers
            .to_str()
            .ok_or(Error::Input("header path encoding"))?
    );
    command
        .arg(header_argument)
        .arg("--output")
        .arg(destination)
        .arg(url);
    wait_process(command, budget, Some((destination, maximum)))?;
    require(
        fs::symlink_metadata(destination)?.is_file(),
        "downloaded regular file",
    )?;
    if fs::metadata(destination)?.len() > maximum {
        return Err(Error::Budget);
    }
    Ok(())
}

#[derive(Deserialize)]
struct Release {
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    id: u64,
    name: String,
    size: u64,
    digest: Option<String>,
}

fn select_asset<'a>(spec: &Spec, release: &'a Release) -> Result<&'a Asset> {
    require(release.assets.len() <= 4096, "release asset inventory")?;
    let selected: Vec<_> = release
        .assets
        .iter()
        .filter(|asset| asset.name == spec.linux_asset)
        .collect();
    require(selected.len() == 1, "missing or ambiguous release asset")?;
    let asset = selected[0];
    require(
        asset.id > 0 && asset.size == spec.size,
        "release asset identity or size",
    )?;
    if let Some(digest) = &asset.digest {
        require(
            digest == &format!("sha256:{}", spec.sha256),
            "release asset digest",
        )?;
    }
    Ok(asset)
}

fn verify_archive(path: &Path, spec: &Spec, budget: &Budget) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() != spec.size {
        return Err(Error::Digest);
    }
    let mut input = File::open(path)?;
    let mut hash = Sha256::new();
    let mut size = 0;
    let mut buffer = [0; 65536];
    loop {
        budget.remaining()?;
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > spec.size {
            return Err(Error::Digest);
        }
        hash.update(&buffer[..count]);
    }
    if size != spec.size || format!("{:x}", hash.finalize()) != spec.sha256 {
        return Err(Error::Digest);
    }
    Ok(())
}

fn attest(path: &Path, spec: &Spec, bundle: Option<&Path>, budget: &Budget) -> Result<()> {
    if !spec.attestation {
        return Ok(());
    }
    let mut command = Command::new("gh");
    command.args(["attestation", "verify"]).arg(path).args([
        "--repo",
        &spec.repository,
        "--signer-workflow",
        &format!("{}/.github/workflows/release.yml", spec.repository),
        "--source-ref",
        &format!("refs/tags/{}", spec.release),
        "--deny-self-hosted-runners",
    ]);
    if let Some(bundle) = bundle {
        command
            .arg("--bundle")
            .arg(bundle)
            .arg("--source-digest")
            .arg(
                spec.source_commit
                    .as_deref()
                    .ok_or(Error::Input("attested source"))?,
            );
    }
    let attestation_budget = Budget(budget.0.min(Instant::now() + Duration::from_secs(60)));
    wait_process(command, &attestation_budget, None).map_err(|_| Error::Attestation)
}

fn extract(
    path: &Path,
    spec: &Spec,
    root: &Path,
    budget: &Budget,
) -> Result<Vec<(String, PathBuf)>> {
    let extracted = root.join("extracted");
    fs::create_dir(&extracted)?;
    let wanted: BTreeSet<_> = spec.executables.values().cloned().collect();
    let mut found = BTreeSet::new();
    if spec.linux_asset.ends_with(".tar.gz") {
        let input = MultiGzDecoder::new(File::open(path)?)
            .take(UNPACKED_LIMIT + (ENTRY_LIMIT as u64 * 1024) + 1);
        let mut archive = tar::Archive::new(input);
        let mut total: u64 = 0;
        let mut seen = BTreeSet::new();
        for (number, item) in archive.entries()?.enumerate() {
            budget.remaining()?;
            if number >= ENTRY_LIMIT {
                return Err(Error::Budget);
            }
            let mut entry = item?;
            let mut normalized = PathBuf::new();
            for component in entry.path()?.components() {
                match component {
                    std::path::Component::CurDir => {}
                    std::path::Component::Normal(part) => normalized.push(part),
                    _ => return Err(Error::Archive),
                }
            }
            let kind = entry.header().entry_type();
            if normalized.as_os_str().is_empty() {
                require(kind.is_dir() && entry.size() == 0, "archive root entry")?;
                continue;
            }
            let name = normalized.to_str().ok_or(Error::Archive)?.to_owned();
            let relative = relative_path(&name)?;
            require(seen.insert(name.clone()), "duplicate archive path")?;
            require(
                kind.is_file() || kind.is_dir(),
                "archive links or special entries",
            )?;
            total = total.checked_add(entry.size()).ok_or(Error::Budget)?;
            if total > UNPACKED_LIMIT || entry.size() > 256 * 1024 * 1024 {
                return Err(Error::Budget);
            }
            if wanted.contains(&name) {
                require(
                    kind.is_file() && entry.size() > 0,
                    "executable is not a nonempty regular archive member",
                )?;
                let output = extracted.join(relative);
                fs::create_dir_all(output.parent().ok_or(Error::Archive)?)?;
                let mut target = private_file(&output)?;
                let expected = entry.size();
                let mut size = 0;
                let mut buffer = [0; 65536];
                loop {
                    budget.remaining()?;
                    let count = entry.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    size += count as u64;
                    if size > expected {
                        return Err(Error::Archive);
                    }
                    target.write_all(&buffer[..count])?;
                }
                if size != expected {
                    return Err(Error::Archive);
                }
                found.insert(name);
            }
        }
    } else {
        fs::rename(path, extracted.join(&spec.linux_asset))?;
        found.insert(spec.linux_asset.clone());
    }
    require(found == wanted, "missing executable archive member")?;
    let mut outputs = Vec::new();
    for (variable, relative) in &spec.executables {
        let path = extracted.join(relative).canonicalize()?;
        require(
            path.starts_with(&extracted) && fs::symlink_metadata(&path)?.is_file(),
            "executable path outside the owned archive",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        }
        outputs.push((variable.clone(), path));
    }
    Ok(outputs)
}

struct Prepared {
    destination: Destination,
    outputs: Vec<(String, PathBuf)>,
}

fn prepare(spec_path: &Path, destination: &Path, token: Option<&str>) -> Result<Prepared> {
    let (spec, bundle) = Spec::read(spec_path)?;
    let destination = Destination::create(destination)?;
    let budget = Budget::new();
    let transport = destination.root.join(".transport");
    fs::create_dir(&transport)?;
    let headers = transport.join("headers");
    let mut header_file = private_file(&headers)?;
    if let Some(token) = token {
        require(
            !token.is_empty()
                && token.len() <= 16384
                && token.bytes().all(|byte| byte.is_ascii_graphic()),
            "credential header encoding",
        )?;
        writeln!(header_file, "Authorization: Bearer {token}")?;
    }
    drop(header_file);
    let release_path = transport.join("release.json");
    download(
        &format!(
            "https://api.github.com/repos/{}/releases/tags/{}",
            spec.repository, spec.release
        ),
        "application/vnd.github+json",
        &release_path,
        &headers,
        INPUT_LIMIT,
        &budget,
    )?;
    let release: Release = serde_json::from_slice(&read_bounded(&release_path, INPUT_LIMIT)?)?;
    let asset = select_asset(&spec, &release)?;
    let archive = destination.root.join(&spec.linux_asset);
    download(
        &format!(
            "https://api.github.com/repos/{}/releases/assets/{}",
            spec.repository, asset.id
        ),
        "application/octet-stream",
        &archive,
        &headers,
        spec.size,
        &budget,
    )?;
    verify_archive(&archive, &spec, &budget)?;
    attest(&archive, &spec, bundle.as_deref(), &budget)?;
    let outputs = extract(&archive, &spec, &destination.root, &budget)?;
    fs::remove_dir_all(transport)?;
    Ok(Prepared {
        destination,
        outputs,
    })
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
}
#[derive(Deserialize)]
struct Package {
    name: String,
    manifest_path: PathBuf,
}

fn selected_spec(metadata: &Path, name: &str) -> Result<PathBuf> {
    require(
        !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "provider package name",
    )?;
    let metadata: Metadata = serde_json::from_slice(&read_bounded(metadata, 32 * 1024 * 1024)?)?;
    let matching: Vec<_> = metadata
        .packages
        .iter()
        .filter(|package| package.name == format!("nddev-device-sync-{name}"))
        .collect();
    require(matching.len() == 1, "missing or ambiguous provider package")?;
    Ok(matching[0]
        .manifest_path
        .parent()
        .ok_or(Error::Input("provider manifest parent"))?
        .join("provider.lock.json"))
}

fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() == 1 && arguments[0] == "--version" {
        println!("nds-agent-ci {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if arguments.len() == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
        println!(
            "nds-agent-ci fetch-provider SPEC DESTINATION\nnds-agent-ci fetch-selected METADATA NAME DESTINATION"
        );
        return Ok(());
    }
    let (spec, destination) = match arguments.as_slice() {
        [command, spec, destination] if command == "fetch-provider" => {
            (PathBuf::from(spec), PathBuf::from(destination))
        }
        [command, metadata, name, destination] if command == "fetch-selected" => (
            selected_spec(
                Path::new(metadata),
                name.to_str()
                    .ok_or(Error::Input("provider name encoding"))?,
            )?,
            PathBuf::from(destination),
        ),
        _ => {
            return Err(Error::Input(
                "use fetch-provider SPEC DESTINATION or fetch-selected METADATA NAME DESTINATION",
            ));
        }
    };
    let token = std::env::var("GH_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .ok()
        .filter(|value| !value.is_empty());
    let mut prepared = prepare(&spec, &destination, token.as_deref())?;
    let mut text = String::new();
    for (variable, path) in &prepared.outputs {
        let path = path
            .to_str()
            .ok_or(Error::Input("executable path encoding"))?;
        require(!path.contains(['\r', '\n']), "executable environment value")?;
        text.push_str(&format!("{variable}={path}\n"));
    }
    if let Some(environment) = std::env::var_os("GITHUB_ENV") {
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(environment)?
            .write_all(text.as_bytes())?;
    } else {
        std::io::stdout().write_all(text.as_bytes())?;
    }
    prepared.destination.retained = true;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests;
