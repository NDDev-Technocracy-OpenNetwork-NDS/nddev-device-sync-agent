//! Composition verifies the fixed worker delivered with the NDS host artifact.
//! Build tooling embeds its digest; no runtime environment or presentation input
//! can select an executable or change the expected bytes.
use crate::{GDS_WORKER_MAX_BYTES, view::AgentError};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

pub const WORKER_NAME: &str = if cfg!(windows) {
    "nds-gds-readonly-worker.exe"
} else {
    "nds-gds-readonly-worker"
};

pub(crate) fn bundled_git_worker() -> Result<Option<PathBuf>, AgentError> {
    let Some(expected) = option_env!("NDS_GDS_WORKER_SHA256") else {
        return Ok(None);
    };
    let host = std::env::current_exe().map_err(|_| AgentError::Unavailable)?;
    resolve(&host, expected)
}

fn resolve(host: &Path, expected: &str) -> Result<Option<PathBuf>, AgentError> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(AgentError::InvalidContract);
    }
    let host = host.canonicalize().map_err(|_| AgentError::Unavailable)?;
    let worker = host
        .parent()
        .ok_or(AgentError::InvalidContract)?
        .join(WORKER_NAME);
    let metadata = match std::fs::symlink_metadata(&worker) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(AgentError::Unavailable),
    };
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > GDS_WORKER_MAX_BYTES {
        return Err(AgentError::InvalidContract);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(AgentError::InvalidContract);
        }
    }
    let mut file = std::fs::File::open(&worker).map_err(|_| AgentError::Unavailable)?;
    let mut hash = Sha256::new();
    let mut chunk = [0; 16 * 1024];
    let mut count = 0u64;
    loop {
        let bytes = file.read(&mut chunk).map_err(|_| AgentError::Unavailable)?;
        if bytes == 0 {
            break;
        }
        count = count
            .checked_add(bytes as u64)
            .ok_or(AgentError::InvalidContract)?;
        if count > GDS_WORKER_MAX_BYTES {
            return Err(AgentError::InvalidContract);
        }
        hash.update(&chunk[..bytes]);
    }
    if count != metadata.len() || format!("{:x}", hash.finalize()) != expected {
        return Err(AgentError::InvalidContract);
    }
    Ok(Some(worker))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, PathBuf, String) {
        let root = tempfile::tempdir().unwrap();
        let host = root.path().join("owned-host");
        std::fs::write(&host, b"host").unwrap();
        let worker = root.path().join(WORKER_NAME);
        std::fs::write(&worker, b"owned-worker").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(worker, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        (root, host, format!("{:x}", Sha256::digest(b"owned-worker")))
    }
    #[test]
    fn only_the_fixed_verified_sibling_is_admitted() {
        let (root, host, digest) = fixture();
        assert_eq!(
            resolve(&host, &digest).unwrap(),
            Some(root.path().join(WORKER_NAME))
        );
        std::fs::write(root.path().join(WORKER_NAME), b"replaced-worker").unwrap();
        assert!(matches!(
            resolve(&host, &digest),
            Err(AgentError::InvalidContract)
        ));
    }
    #[test]
    fn oversized_worker_is_refused_before_reading_or_execution() {
        let (root, host, digest) = fixture();
        std::fs::File::options()
            .write(true)
            .open(root.path().join(WORKER_NAME))
            .unwrap()
            .set_len(GDS_WORKER_MAX_BYTES + 1)
            .unwrap();
        assert!(matches!(
            resolve(&host, &digest),
            Err(AgentError::InvalidContract)
        ));
    }
    #[test]
    fn another_sibling_name_does_not_configure_the_worker() {
        let (root, host, digest) = fixture();
        std::fs::rename(
            root.path().join(WORKER_NAME),
            root.path().join("unrelated-worker"),
        )
        .unwrap();
        assert!(resolve(&host, &digest).unwrap().is_none());
    }
    #[cfg(unix)]
    #[test]
    fn a_worker_symlink_cannot_escape_the_artifact() {
        let (root, host, digest) = fixture();
        let worker = root.path().join(WORKER_NAME);
        std::fs::remove_file(&worker).unwrap();
        std::os::unix::fs::symlink(&host, &worker).unwrap();
        assert!(matches!(
            resolve(&host, &digest),
            Err(AgentError::InvalidContract)
        ));
    }
}
