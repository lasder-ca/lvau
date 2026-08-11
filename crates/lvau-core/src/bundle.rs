//! Sealed bundle mode: pack a directory into a single encrypted `.lvau` file.
//!
//! The format and public API live here; the active implementation is the bounded-memory
//! streaming pipeline in `bundle_stream`. Keeping a single implementation avoids security
//! fixes drifting between active and legacy extraction paths.

use crate::crypto::CryptoError;
use lvau_protocol::envelope::{ContentType, EnvelopeHeader};
use std::io;
use std::path::{Component, Path, PathBuf};

pub use crate::bundle_stream::{extract_bundle, list_bundle, pack_directory, verify_bundle};

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("Path traversal detected: {0}")]
    PathTraversal(String),
    #[error("Symlink rejected: {0}")]
    SymlinkRejected(String),
    #[error("Hardlink rejected: {0}")]
    HardlinkRejected(String),
    #[error("Special file rejected: {0}")]
    SpecialFileRejected(String),
    #[error("Refusing to overwrite: {0}")]
    OutputExists(String),
    #[error("Bundle manifest error: {0}")]
    ManifestError(String),
    #[error("Walk error: {0}")]
    WalkError(String),
    #[error("Input directory does not exist: {0}")]
    InputDirNotFound(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataProfile {
    Minimal,
    Balanced,
    Verbose,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingProfile {
    None,
    Bucket,
    Fixed(usize),
}

pub fn validate_relative_path(path: &str) -> Result<PathBuf, BundleError> {
    if path.is_empty() || path.contains('\\') {
        return Err(BundleError::PathTraversal(format!(
            "Empty or non-canonical path rejected: {path}"
        )));
    }
    let relative = Path::new(path);
    if relative.is_absolute() || path.starts_with('/') || path.starts_with('\\') {
        return Err(BundleError::PathTraversal(format!(
            "Absolute or leading-separator path rejected: {path}"
        )));
    }
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        return Err(BundleError::PathTraversal(format!(
            "Windows drive path rejected: {path}"
        )));
    }
    for component in relative.components() {
        match component {
            Component::Normal(_) => {}
            Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_)
            | Component::CurDir => {
                return Err(BundleError::PathTraversal(format!(
                    "Non-canonical path component rejected: {path}"
                )));
            }
        }
    }
    Ok(relative.to_path_buf())
}

pub fn inspect_bundle(
    in_file: &Path,
) -> Result<(EnvelopeHeader, Option<ContentType>, Option<String>), BundleError> {
    let envelope = crate::crypto::read_envelope_from_path(in_file)?;
    Ok((
        envelope.header,
        envelope.content_type,
        envelope.public_label,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_path_validation_is_cross_platform_and_canonical() {
        for invalid in [
            "",
            "/etc/passwd",
            "../secret",
            "a/../secret",
            "C:file",
            "a\\b",
        ] {
            assert!(
                validate_relative_path(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        for valid in ["file.txt", "subdir/file.txt", "a/b/c.bin"] {
            assert!(validate_relative_path(valid).is_ok(), "rejected {valid:?}");
        }
    }
}
