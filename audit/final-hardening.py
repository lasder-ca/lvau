#!/usr/bin/env python3
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one hardening anchor, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def harden_hybrid() -> None:
    replace_once(
        "crates/lvau-core/src/crypto/mod.rs",
        """        let ephem_x25519_pub = X25519PublicKey::from(&ephem_x25519_priv);\n        let x25519_ss = ephem_x25519_priv.diffie_hellman(&pubkey.x25519);\n\n        let (mlkem_ct, mlkem_ss) = pubkey.mlkem.encapsulate();\n""",
        """        let ephem_x25519_pub = X25519PublicKey::from(&ephem_x25519_priv);\n        let x25519_ss = ephem_x25519_priv.diffie_hellman(&pubkey.x25519);\n        if !x25519_ss.was_contributory() {\n            return Err(CryptoError::Validation(\n                \"Recipient X25519 public key is non-contributory\",\n            ));\n        }\n\n        let (mlkem_ct, mlkem_ss) = pubkey.mlkem.encapsulate();\n""",
    )
    replace_once(
        "crates/lvau-core/src/crypto/mod.rs",
        """        let ephem_pub = X25519PublicKey::from(*ephemeral_public_x25519);\n        let x25519_ss = priv_key.x25519.diffie_hellman(&ephem_pub);\n        let mlkem_ct = match mlkem_ciphertext.as_slice().try_into() {\n""",
        """        let ephem_pub = X25519PublicKey::from(*ephemeral_public_x25519);\n        let x25519_ss = priv_key.x25519.diffie_hellman(&ephem_pub);\n        if !x25519_ss.was_contributory() {\n            continue;\n        }\n        let mlkem_ct = match mlkem_ciphertext.as_slice().try_into() {\n""",
    )


def harden_bundle() -> None:
    (ROOT / "crates/lvau-core/src/bundle.rs").write_text(
        '''//! Sealed bundle mode: pack a directory into a single encrypted `.lvau` file.
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
    if path.is_empty() || path.contains('\\\\') {
        return Err(BundleError::PathTraversal(format!(
            "Empty or non-canonical path rejected: {path}"
        )));
    }
    let relative = Path::new(path);
    if relative.is_absolute() || path.starts_with('/') || path.starts_with('\\\\') {
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
            Component::ParentDir | Component::RootDir | Component::Prefix(_) | Component::CurDir => {
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
        for invalid in ["", "/etc/passwd", "../secret", "a/../secret", "C:file", "a\\\\b"] {
            assert!(validate_relative_path(invalid).is_err(), "accepted {invalid:?}");
        }
        for valid in ["file.txt", "subdir/file.txt", "a/b/c.bin"] {
            assert!(validate_relative_path(valid).is_ok(), "rejected {valid:?}");
        }
    }
}
''',
        encoding="utf-8",
    )

    replace_once(
        "crates/lvau-core/src/bundle_stream.rs",
        "fn persist_output(temp: NamedTempFile, target: &Path, force: bool) -> Result<(), BundleError> {\n",
        '''fn validate_extraction_directory(path: &Path) -> Result<(), BundleError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(BundleError::SymlinkRejected(path.display().to_string()));
    }
    if !metadata.file_type().is_dir() {
        return Err(BundleError::SpecialFileRejected(path.display().to_string()));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(BundleError::SymlinkRejected(path.display().to_string()));
        }
    }
    Ok(())
}

fn ensure_safe_extraction_parent(out_dir: &Path, parent: &Path) -> Result<(), BundleError> {
    validate_extraction_directory(out_dir)?;
    let relative = parent.strip_prefix(out_dir).map_err(|_| {
        BundleError::PathTraversal(format!(
            "Extraction parent is outside output directory: {}",
            parent.display()
        ))
    })?;
    let mut current = out_dir.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(BundleError::PathTraversal(parent.display().to_string()));
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(_) => validate_extraction_directory(&current)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                validate_extraction_directory(&current)?;
            }
            Err(error) => return Err(BundleError::Io(error)),
        }
    }
    Ok(())
}

fn persist_output(temp: NamedTempFile, target: &Path, force: bool) -> Result<(), BundleError> {
''',
    )
    replace_once(
        "crates/lvau-core/src/bundle_stream.rs",
        '''    fs::create_dir_all(out_dir)?;
    let canonical_out = out_dir.canonicalize()?;
    for entry in &bundle.manifest.entries {
        let relative = validate_relative_path(&entry.relative_path)?;
        let target = out_dir.join(relative);
        let parent = target.parent().unwrap_or(out_dir);
        fs::create_dir_all(parent)?;
        let canonical_parent = parent.canonicalize()?;
''',
        '''    fs::create_dir_all(out_dir)?;
    validate_extraction_directory(out_dir)?;
    let canonical_out = out_dir.canonicalize()?;
    for entry in &bundle.manifest.entries {
        let relative = validate_relative_path(&entry.relative_path)?;
        let target = out_dir.join(relative);
        let parent = target.parent().unwrap_or(out_dir);
        ensure_safe_extraction_parent(out_dir, parent)?;
        let canonical_parent = parent.canonicalize()?;
''',
    )
    replace_once(
        "crates/lvau-core/src/bundle_stream.rs",
        '''    #[test]
    fn large_bundle_roundtrip_uses_streaming_path() {
''',
        '''    #[test]
    #[cfg(unix)]
    fn extraction_rejects_symlinked_parent_even_inside_output_root() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let output = dir.path().join("output");
        let real = output.join("real");
        fs::create_dir_all(&real).unwrap();
        symlink(&real, output.join("alias")).unwrap();

        let error = ensure_safe_extraction_parent(&output, &output.join("alias")).unwrap_err();
        assert!(matches!(error, BundleError::SymlinkRejected(_)));
    }

    #[test]
    fn large_bundle_roundtrip_uses_streaming_path() {
''',
    )


def harden_docs_release() -> None:
    for path in ["SECURITY.md", ".github/ISSUE_TEMPLATE/security.md", "CONTRIBUTING.md"]:
        target = ROOT / path
        text = target.read_text(encoding="utf-8")
        text = text.replace("https://github.com/latteworkspace/lvau", "https://github.com/lasder-ca/lvau")
        text = text.replace("https://github.com/latteworkspace", "https://github.com/lasder-ca")
        text = text.replace("latteworkspace organization profile", "lasder-ca profile")
        target.write_text(text, encoding="utf-8")

    replace_once(
        ".github/workflows/release.yml",
        '''      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30 # stable
''',
        '''      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false
          fetch-depth: 0
      - name: Require the release tag to point at current master
        shell: bash
        run: |
          set -euo pipefail
          git fetch --no-tags origin master
          master_sha="$(git rev-parse origin/master)"
          test "${GITHUB_SHA}" = "${master_sha}" || {
            echo "release tag must point at current master (${master_sha}), got ${GITHUB_SHA}" >&2
            exit 1
          }
      - uses: dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30 # stable
''',
    )
    replace_once(
        ".github/workflows/release.yml",
        "uses: actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6 # v4",
        "uses: actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4.2.1",
    )


parser = argparse.ArgumentParser()
parser.add_argument("section", choices=["hybrid", "bundle", "docs-release"])
args = parser.parse_args()
if args.section == "hybrid":
    harden_hybrid()
elif args.section == "bundle":
    harden_bundle()
else:
    harden_docs_release()
