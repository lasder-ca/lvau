use crate::crypto::CryptoError;
use blahaj::{Share as SharksShare, Sharks};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

const CURRENT_SHARE_VERSION: u32 = 2;
const MAX_SHARE_FILE_SIZE: usize = 1024 * 1024;

fn write_private_atomic(path: &Path, bytes: &[u8], force: bool) -> Result<(), CryptoError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o600))?;
    }

    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;

    #[cfg(windows)]
    if force && path.exists() {
        fs::remove_file(path)?;
    }

    let persisted = if force {
        temp.persist(path)
    } else {
        temp.persist_noclobber(path)
    };
    persisted.map_err(|error| {
        if !force && error.error.kind() == std::io::ErrorKind::AlreadyExists {
            CryptoError::OutputExists
        } else {
            CryptoError::Io(error.error)
        }
    })?;

    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RecoveryShare {
    pub magic: [u8; 4],
    pub version: u32,
    pub index: u8,
    pub threshold: u8,
    pub fingerprint: [u8; 32],
    pub share_data: Vec<u8>,
}

impl std::fmt::Debug for RecoveryShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryShare")
            .field("magic", &self.magic)
            .field("version", &self.version)
            .field("index", &self.index)
            .field("threshold", &self.threshold)
            .field("fingerprint", &self.fingerprint)
            .field("share_data_len", &self.share_data.len())
            .finish()
    }
}

impl RecoveryShare {
    pub fn to_file(&self, path: &Path) -> Result<(), CryptoError> {
        // Preserve the public API's historical overwrite behavior. Callers that
        // require no-clobber semantics must opt into it explicitly below.
        self.to_file_with_force(path, true)
    }

    pub fn to_file_with_force(&self, path: &Path, force: bool) -> Result<(), CryptoError> {
        let encoded = postcard::to_allocvec(self)?;
        write_private_atomic(path, &encoded, force)
    }

    pub fn from_file(path: &Path) -> Result<Self, CryptoError> {
        let bytes = fs::read(path)?;
        if bytes.len() > MAX_SHARE_FILE_SIZE {
            return Err(CryptoError::Validation("Recovery share is too large"));
        }
        let (share, remaining): (Self, &[u8]) = postcard::take_from_bytes(&bytes)?;
        if !remaining.is_empty() {
            return Err(CryptoError::Validation(
                "Recovery share contains trailing data",
            ));
        }
        if &share.magic != b"LVAU" {
            return Err(CryptoError::Validation("Invalid magic bytes in share"));
        }
        if !(1..=CURRENT_SHARE_VERSION).contains(&share.version) {
            return Err(CryptoError::Validation(
                "Unsupported recovery share version",
            ));
        }
        if share.threshold == 0 || share.share_data.first().copied() != Some(share.index) {
            return Err(CryptoError::Validation("Invalid recovery share metadata"));
        }
        Ok(share)
    }
}

pub fn write_recovered_secret(path: &Path, secret: &[u8], force: bool) -> Result<(), CryptoError> {
    write_private_atomic(path, secret, force)
}

pub fn split_secret(
    secret: &[u8],
    num_shares: u8,
    threshold: u8,
) -> Result<Vec<RecoveryShare>, CryptoError> {
    if threshold == 0 || num_shares == 0 || threshold > num_shares {
        return Err(CryptoError::Validation("Invalid threshold or share count"));
    }

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);

    // Version 1 published SHA-256(secret), which enabled offline guesses for
    // low-entropy secrets. Version 2 uses a random set identifier instead.
    let mut fingerprint = [0u8; 32];
    OsRng.fill_bytes(&mut fingerprint);

    let mut result = Vec::new();
    for share in dealer.take(num_shares as usize) {
        let share_bytes = Vec::from(&share);

        let index = share_bytes[0];

        result.push(RecoveryShare {
            magic: *b"LVAU",
            version: CURRENT_SHARE_VERSION,
            index,
            threshold,
            fingerprint,
            share_data: share_bytes,
        });
    }

    Ok(result)
}

pub fn combine_shares(shares: &[RecoveryShare]) -> Result<Vec<u8>, CryptoError> {
    if shares.is_empty() {
        return Err(CryptoError::Validation("No shares provided"));
    }

    let threshold = shares[0].threshold;
    let fingerprint = shares[0].fingerprint;
    let version = shares[0].version;

    if threshold == 0 || shares.len() < threshold as usize {
        return Err(CryptoError::Validation(
            "Not enough shares to reach threshold",
        ));
    }

    let mut indices = HashSet::new();
    for s in shares {
        if &s.magic != b"LVAU"
            || !(1..=CURRENT_SHARE_VERSION).contains(&s.version)
            || s.version != version
            || s.threshold != threshold
            || s.fingerprint != fingerprint
            || s.share_data.first().copied() != Some(s.index)
            || !indices.insert(s.index)
        {
            return Err(CryptoError::Validation(
                "Mismatched, duplicate, or invalid recovery shares",
            ));
        }
    }

    let sharks = Sharks(threshold);

    let mut sharks_shares = Vec::new();
    for s in shares {
        let sharks_share = SharksShare::try_from(s.share_data.as_slice())
            .map_err(|_| CryptoError::Validation("Invalid share data format"))?;
        sharks_shares.push(sharks_share);
    }

    let recovered = sharks
        .recover(&sharks_shares)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    if version == 1 && <[u8; 32]>::from(Sha256::digest(&recovered)) != fingerprint {
        return Err(CryptoError::DecryptionFailed);
    }

    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_shares_do_not_publish_a_secret_hash() {
        let secret = b"guessable password";
        let shares = split_secret(secret, 3, 2).unwrap();
        let secret_hash: [u8; 32] = Sha256::digest(secret).into();

        assert!(shares.iter().all(|share| share.version >= 2));
        assert!(shares.iter().all(|share| share.fingerprint != secret_hash));
    }

    #[test]
    fn legacy_share_fingerprint_is_checked_after_recovery() {
        let secret = b"legacy recovery secret";
        let mut shares = split_secret(secret, 3, 2).unwrap();
        for share in &mut shares {
            share.version = 1;
            share.fingerprint = [0xCC; 32];
        }

        assert!(combine_shares(&shares[..2]).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn recovery_share_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.lvau-share");
        let share = split_secret(b"secret", 2, 2).unwrap().remove(0);
        share.to_file(&path).unwrap();

        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn recovery_share_to_file_preserves_overwrite_behavior() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.lvau-share");
        let mut shares = split_secret(b"secret", 2, 2).unwrap();
        let first = shares.remove(0);
        let replacement = shares.remove(0);

        first.to_file(&path).unwrap();
        replacement.to_file(&path).unwrap();

        let loaded = RecoveryShare::from_file(&path).unwrap();
        assert_eq!(loaded.index, replacement.index);
        assert_eq!(loaded.share_data, replacement.share_data);
    }

    #[test]
    fn recovery_share_explicit_no_clobber_preserves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.lvau-share");
        fs::write(&path, b"keep me").unwrap();
        let share = split_secret(b"secret", 2, 2).unwrap().remove(0);

        assert!(matches!(
            share.to_file_with_force(&path, false),
            Err(CryptoError::OutputExists)
        ));
        assert_eq!(fs::read(path).unwrap(), b"keep me");
    }

    #[test]
    #[cfg(unix)]
    fn recovered_secret_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovered.key");
        write_recovered_secret(&path, b"secret bytes", false).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"secret bytes");
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
