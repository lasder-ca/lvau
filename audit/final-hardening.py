#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one hardening anchor, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


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

(ROOT / "crates/lvau-core/tests").mkdir(parents=True, exist_ok=True)
(ROOT / "crates/lvau-core/tests/hybrid_hardening.rs").write_text(
    '''use lvau_core::crypto::{encrypt_file_keypairs, keys::generate_keypair, CryptoError};
use lvau_protocol::envelope::SecurityProfile;
use std::fs;
use x25519_dalek::PublicKey as X25519PublicKey;

#[test]
fn encryption_rejects_non_contributory_x25519_recipient() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.txt");
    let output = dir.path().join("output.lvau");
    fs::write(&input, b"hybrid-hardening").unwrap();

    let (_private_key, mut recipient) = generate_keypair();
    recipient.x25519 = X25519PublicKey::from([0u8; 32]);

    let error = encrypt_file_keypairs(
        &input,
        &output,
        &[recipient],
        SecurityProfile::Fast,
        None,
        None,
        false,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        CryptoError::Validation("Recipient X25519 public key is non-contributory")
    ));
    assert!(!output.exists());
}
''',
    encoding="utf-8",
)

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
    '''fn persist_output(temp: NamedTempFile, target: &Path, force: bool) -> Result<(), BundleError> {\n''',
    '''fn validate_extraction_directory(path: &Path) -> Result<(), BundleError> {\n    let metadata = fs::symlink_metadata(path)?;\n    if metadata.file_type().is_symlink() {\n        return Err(BundleError::SymlinkRejected(path.display().to_string()));\n    }\n    if !metadata.file_type().is_dir() {\n        return Err(BundleError::SpecialFileRejected(path.display().to_string()));\n    }\n    #[cfg(windows)]\n    {\n        use std::os::windows::fs::MetadataExt;\n        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;\n        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {\n            return Err(BundleError::SymlinkRejected(path.display().to_string()));\n        }\n    }\n    Ok(())\n}\n\nfn ensure_safe_extraction_parent(out_dir: &Path, parent: &Path) -> Result<(), BundleError> {\n    validate_extraction_directory(out_dir)?;\n    let relative = parent.strip_prefix(out_dir).map_err(|_| {\n        BundleError::PathTraversal(format!(\n            \"Extraction parent is outside output directory: {}\",\n            parent.display()\n        ))\n    })?;\n    let mut current = out_dir.to_path_buf();\n    for component in relative.components() {\n        let Component::Normal(name) = component else {\n            return Err(BundleError::PathTraversal(parent.display().to_string()));\n        };\n        current.push(name);\n        match fs::symlink_metadata(&current) {\n            Ok(_) => validate_extraction_directory(&current)?,\n            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {\n                fs::create_dir(&current)?;\n                validate_extraction_directory(&current)?;\n            }\n            Err(error) => return Err(BundleError::Io(error)),\n        }\n    }\n    Ok(())\n}\n\nfn persist_output(temp: NamedTempFile, target: &Path, force: bool) -> Result<(), BundleError> {\n''',
)
replace_once(
    "crates/lvau-core/src/bundle_stream.rs",
    '''    fs::create_dir_all(out_dir)?;\n    let canonical_out = out_dir.canonicalize()?;\n    for entry in &bundle.manifest.entries {\n        let relative = validate_relative_path(&entry.relative_path)?;\n        let target = out_dir.join(relative);\n        let parent = target.parent().unwrap_or(out_dir);\n        fs::create_dir_all(parent)?;\n        let canonical_parent = parent.canonicalize()?;\n''',
    '''    fs::create_dir_all(out_dir)?;\n    validate_extraction_directory(out_dir)?;\n    let canonical_out = out_dir.canonicalize()?;\n    for entry in &bundle.manifest.entries {\n        let relative = validate_relative_path(&entry.relative_path)?;\n        let target = out_dir.join(relative);\n        let parent = target.parent().unwrap_or(out_dir);\n        ensure_safe_extraction_parent(out_dir, parent)?;\n        let canonical_parent = parent.canonicalize()?;\n''',
)
replace_once(
    "crates/lvau-core/src/bundle_stream.rs",
    '''    #[test]\n    fn large_bundle_roundtrip_uses_streaming_path() {\n''',
    '''    #[test]\n    #[cfg(unix)]\n    fn extraction_rejects_symlinked_parent_even_inside_output_root() {\n        use std::os::unix::fs::symlink;\n\n        let dir = tempdir().unwrap();\n        let output = dir.path().join(\"output\");\n        let real = output.join(\"real\");\n        fs::create_dir_all(&real).unwrap();\n        symlink(&real, output.join(\"alias\")).unwrap();\n\n        let error = ensure_safe_extraction_parent(&output, &output.join(\"alias\")).unwrap_err();\n        assert!(matches!(error, BundleError::SymlinkRejected(_)));\n    }\n\n    #[test]\n    fn large_bundle_roundtrip_uses_streaming_path() {\n''',
)

for path in ["SECURITY.md", ".github/ISSUE_TEMPLATE/security.md", "CONTRIBUTING.md"]:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    text = text.replace("https://github.com/latteworkspace/lvau", "https://github.com/lasder-ca/lvau")
    text = text.replace("https://github.com/latteworkspace", "https://github.com/lasder-ca")
    text = text.replace("latteworkspace organization profile", "lasder-ca profile")
    target.write_text(text, encoding="utf-8")

replace_once(
    ".github/workflows/release.yml",
    '''      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0\n        with:\n          persist-credentials: false\n      - uses: dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30 # stable\n''',
    '''      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0\n        with:\n          persist-credentials: false\n          fetch-depth: 0\n      - name: Require the release tag to point at current master\n        shell: bash\n        run: |\n          set -euo pipefail\n          git fetch --no-tags origin master\n          master_sha=\"$(git rev-parse origin/master)\"\n          test \"${GITHUB_SHA}\" = \"${master_sha}\" || {\n            echo \"release tag must point at current master (${master_sha}), got ${GITHUB_SHA}\" >&2\n            exit 1\n          }\n      - uses: dtolnay/rust-toolchain@4be7066ada62dd38de10e7b70166bc74ed198c30 # stable\n''',
)
replace_once(
    ".github/workflows/release.yml",
    "uses: actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6 # v4",
    "uses: actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4.2.1",
)
