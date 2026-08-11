#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one anchor, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# Reuse the already-audited Windows owner-only ACL helper for other secret files.
replace_once(
    "crates/lvau-core/src/crypto/keys.rs",
    "#[cfg(windows)]\nfn set_windows_acl(path: &Path) -> Result<(), std::io::Error> {",
    "#[cfg(windows)]\npub(crate) fn set_windows_acl(path: &Path) -> Result<(), std::io::Error> {",
)

# Signing key files: bounded regular-file reads and private atomic writes.
replace_once(
    "crates/lvau-core/src/signing.rs",
    "use std::fs;\nuse std::io::Write;",
    "use std::fs::{self, File};\nuse std::io::{Read, Write};",
)
replace_once(
    "crates/lvau-core/src/signing.rs",
    "const APPROVAL_ARTIFACT_V2_DOMAIN: &[u8] = b\"Lvau approval artifact v2\\0\";\n",
    "const APPROVAL_ARTIFACT_V2_DOMAIN: &[u8] = b\"Lvau approval artifact v2\\0\";\nconst MAX_SIGNING_KEY_FILE_SIZE: u64 = 64 * 1024;\n\nfn read_key_file(path: &Path) -> Result<String, SigningError> {\n    let file = File::open(path)?;\n    let metadata = file.metadata()?;\n    if !metadata.is_file() || metadata.len() > MAX_SIGNING_KEY_FILE_SIZE {\n        return Err(SigningError::InvalidKey(\"Key file is invalid or too large\".into()));\n    }\n\n    let mut json = String::new();\n    file.take(MAX_SIGNING_KEY_FILE_SIZE + 1).read_to_string(&mut json)?;\n    if json.len() as u64 > MAX_SIGNING_KEY_FILE_SIZE {\n        return Err(SigningError::InvalidKey(\"Key file is invalid or too large\".into()));\n    }\n    Ok(json)\n}\n",
)
replace_once(
    "crates/lvau-core/src/signing.rs",
    "fn decode_capsule_parts(data: &[u8]) -> Result<(Envelope, &[u8]), SigningError> {",
    "fn write_private_atomic(path: &Path, bytes: &[u8], force: bool) -> Result<(), SigningError> {\n    if path.exists() && !force {\n        return Err(SigningError::OutputExists(path.display().to_string()));\n    }\n    let parent = path.parent().unwrap_or_else(|| Path::new(\".\"));\n    let mut temp = NamedTempFile::new_in(parent)?;\n\n    #[cfg(unix)]\n    {\n        use std::os::unix::fs::PermissionsExt;\n        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o600))?;\n    }\n\n    temp.write_all(bytes)?;\n    temp.as_file().sync_all()?;\n\n    #[cfg(windows)]\n    if force && path.exists() {\n        fs::remove_file(path)?;\n    }\n\n    if force {\n        temp.persist(path)\n            .map_err(|error| SigningError::Io(error.error))?;\n    } else {\n        temp.persist_noclobber(path)\n            .map_err(|error| SigningError::Io(error.error))?;\n    }\n\n    #[cfg(windows)]\n    crate::crypto::keys::set_windows_acl(path)?;\n\n    #[cfg(unix)]\n    File::open(parent)?.sync_all()?;\n    Ok(())\n}\n\nfn decode_capsule_parts(data: &[u8]) -> Result<(Envelope, &[u8]), SigningError> {",
)
replace_once(
    "crates/lvau-core/src/signing.rs",
    "    write_atomic(path, json.as_bytes(), force)\n}\n\n/// Load a signing key from a file.\npub fn load_signing_key(path: &Path) -> Result<SigningKey, SigningError> {\n    let json = fs::read_to_string(path)?;",
    "    write_private_atomic(path, json.as_bytes(), force)\n}\n\n/// Load a signing key from a file.\npub fn load_signing_key(path: &Path) -> Result<SigningKey, SigningError> {\n    let json = read_key_file(path)?;",
)
replace_once(
    "crates/lvau-core/src/signing.rs",
    "pub fn load_verify_key(path: &Path) -> Result<VerifyingKey, SigningError> {\n    let json = fs::read_to_string(path)?;",
    "pub fn load_verify_key(path: &Path) -> Result<VerifyingKey, SigningError> {\n    let json = read_key_file(path)?;",
)

# Recovery shares: enforce the size limit before allocation and owner-only ACL on Windows.
replace_once(
    "crates/lvau-core/src/recovery.rs",
    "use std::fs;\nuse std::io::Write;",
    "use std::fs::{self, File};\nuse std::io::{Read, Write};",
)
replace_once(
    "crates/lvau-core/src/recovery.rs",
    "const MAX_SHARE_FILE_SIZE: usize = 1024 * 1024;\n",
    "const MAX_SHARE_FILE_SIZE: u64 = 1024 * 1024;\n\nfn read_share_file(path: &Path) -> Result<Vec<u8>, CryptoError> {\n    let file = File::open(path)?;\n    let metadata = file.metadata()?;\n    if !metadata.is_file() || metadata.len() > MAX_SHARE_FILE_SIZE {\n        return Err(CryptoError::Validation(\"Recovery share is too large\"));\n    }\n\n    let mut bytes = Vec::new();\n    file.take(MAX_SHARE_FILE_SIZE + 1).read_to_end(&mut bytes)?;\n    if bytes.len() as u64 > MAX_SHARE_FILE_SIZE {\n        return Err(CryptoError::Validation(\"Recovery share is too large\"));\n    }\n    Ok(bytes)\n}\n",
)
replace_once(
    "crates/lvau-core/src/recovery.rs",
    "    #[cfg(unix)]\n    fs::File::open(parent)?.sync_all()?;\n    Ok(())",
    "    #[cfg(windows)]\n    crate::crypto::keys::set_windows_acl(path)?;\n\n    #[cfg(unix)]\n    File::open(parent)?.sync_all()?;\n    Ok(())",
)
replace_once(
    "crates/lvau-core/src/recovery.rs",
    "    pub fn from_file(path: &Path) -> Result<Self, CryptoError> {\n        let bytes = fs::read(path)?;\n        if bytes.len() > MAX_SHARE_FILE_SIZE {\n            return Err(CryptoError::Validation(\"Recovery share is too large\"));\n        }",
    "    pub fn from_file(path: &Path) -> Result<Self, CryptoError> {\n        let bytes = read_share_file(path)?;",
)

# Regression tests in independent modules to avoid reshaping existing tests.
signing = ROOT / "crates/lvau-core/src/signing.rs"
text = signing.read_text(encoding="utf-8")
if "mod private_file_hardening_tests" not in text:
    text += r'''

#[cfg(test)]
mod private_file_hardening_tests {
    use super::*;

    #[test]
    fn oversized_signing_key_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized.lvau-sign");
        fs::write(&path, vec![b'x'; MAX_SIGNING_KEY_FILE_SIZE as usize + 1]).unwrap();

        assert!(matches!(
            load_signing_key(&path),
            Err(SigningError::InvalidKey(message)) if message == "Key file is invalid or too large"
        ));
    }

    #[test]
    #[cfg(unix)]
    fn signing_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.lvau-sign");
        let (key, _) = generate_signing_keypair();
        save_signing_key(&key, &path, false).unwrap();

        assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
'''
    signing.write_text(text, encoding="utf-8")

recovery = ROOT / "crates/lvau-core/src/recovery.rs"
text = recovery.read_text(encoding="utf-8")
anchor = "    fn recovered_secret_is_written_owner_only() {"
if "oversized_recovery_share_is_rejected_before_decode" not in text:
    marker = "    #[test]\n    #[cfg(unix)]\n" + anchor
    test = r'''    #[test]
    fn oversized_recovery_share_is_rejected_before_decode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized.lvau-share");
        fs::write(&path, vec![0u8; MAX_SHARE_FILE_SIZE as usize + 1]).unwrap();

        assert!(matches!(
            RecoveryShare::from_file(&path),
            Err(CryptoError::Validation("Recovery share is too large"))
        ));
    }

'''
    if marker not in text:
        raise SystemExit("recovery test anchor not found")
    text = text.replace(marker, test + marker, 1)
    recovery.write_text(text, encoding="utf-8")
