//! File identity utilities: hashing, size, timestamps.

use crate::types::{FileHash, FileIdentity, FileTimestamps, HashAlgorithm};
use crate::MetadataResult;
use chrono::{DateTime, Utc};
use md5::{Digest, Md5};
use sha2::Sha256;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

/// Compute MD5 hash of data.
pub fn compute_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute SHA-256 hash of data.
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute hashes based on algorithm selection.
pub fn compute_hashes(data: &[u8], algorithm: HashAlgorithm) -> FileHash {
    match algorithm {
        HashAlgorithm::None => FileHash::default(),
        HashAlgorithm::Md5 => FileHash {
            md5: Some(compute_md5(data)),
            sha256: None,
        },
        HashAlgorithm::Sha256 => FileHash {
            md5: None,
            sha256: Some(compute_sha256(data)),
        },
        HashAlgorithm::Both => FileHash {
            md5: Some(compute_md5(data)),
            sha256: Some(compute_sha256(data)),
        },
    }
}

/// Get file identity information.
///
/// Returns the `FileIdentity` and the raw file bytes (caller can pass them
/// to handlers without re-reading).
pub fn get_file_identity(
    path: &Path,
    hash_algorithm: HashAlgorithm,
) -> MetadataResult<(FileIdentity, Vec<u8>)> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let mut data = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut data)?;

    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let extension = path
        .extension()
        .map(|s| format!(".{}", s.to_string_lossy().to_lowercase()))
        .unwrap_or_default();

    let hash = compute_hashes(&data, hash_algorithm);
    let timestamps = get_timestamps(&metadata);

    let identity = FileIdentity {
        path: path.to_path_buf(),
        name,
        extension,
        size: metadata.len(),
        hash,
        timestamps,
    };

    Ok((identity, data))
}

/// Extract timestamps from file metadata.
fn get_timestamps(metadata: &fs::Metadata) -> FileTimestamps {
    let modified = metadata
        .modified()
        .ok()
        .map(DateTime::<Utc>::from)
        .unwrap_or_else(Utc::now);

    let created = metadata.created().ok().map(DateTime::<Utc>::from);
    let accessed = metadata.accessed().ok().map(DateTime::<Utc>::from);

    FileTimestamps {
        created,
        modified,
        accessed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_known_value() {
        // MD5 of empty string.
        let hash = compute_md5(b"");
        assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn sha256_known_value() {
        // SHA-256 of empty string.
        let hash = compute_sha256(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn compute_hashes_none() {
        let h = compute_hashes(b"hello", HashAlgorithm::None);
        assert!(h.md5.is_none());
        assert!(h.sha256.is_none());
    }

    #[test]
    fn compute_hashes_md5_only() {
        let h = compute_hashes(b"hello", HashAlgorithm::Md5);
        assert!(h.md5.is_some());
        assert!(h.sha256.is_none());
    }

    #[test]
    fn compute_hashes_sha256_only() {
        let h = compute_hashes(b"hello", HashAlgorithm::Sha256);
        assert!(h.md5.is_none());
        assert!(h.sha256.is_some());
    }

    #[test]
    fn compute_hashes_both() {
        let h = compute_hashes(b"hello", HashAlgorithm::Both);
        assert!(h.md5.is_some());
        assert!(h.sha256.is_some());
    }

    #[test]
    fn get_file_identity_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, b"hello world").unwrap();

        let (id, data) = get_file_identity(&path, HashAlgorithm::Sha256).unwrap();
        assert_eq!(id.name, "test.txt");
        assert_eq!(id.extension, ".txt");
        assert_eq!(id.size, 11);
        assert!(id.hash.sha256.is_some());
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn get_file_identity_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Makefile");
        std::fs::write(&path, b"all:").unwrap();

        let (id, _) = get_file_identity(&path, HashAlgorithm::None).unwrap();
        assert_eq!(id.name, "Makefile");
        assert_eq!(id.extension, "");
    }
}
