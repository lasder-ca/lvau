//! Ed25519 signing for Lvau encrypted artifacts.
//!
//! Signatures cover the public envelope and all ciphertext bytes.
//! Verification does not require the decryption password or private key.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use lvau_protocol::envelope::{ApprovalSignature, Envelope, EnvelopeSignature};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use thiserror::Error;

const AUTHOR_SIGNATURE_V2_DOMAIN: &[u8] = b"Lvau author signature v2\0";
const APPROVAL_SIGNATURE_V2_DOMAIN: &[u8] = b"Lvau approval signature v2\0";
const APPROVAL_ARTIFACT_V2_DOMAIN: &[u8] = b"Lvau approval artifact v2\0";
const MAX_SIGNING_KEY_FILE_SIZE: u64 = 64 * 1024;

fn read_key_file(path: &Path) -> Result<String, SigningError> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_SIGNING_KEY_FILE_SIZE {
        return Err(SigningError::InvalidKey(
            "Key file is invalid or too large".into(),
        ));
    }

    let mut json = String::new();
    file.take(MAX_SIGNING_KEY_FILE_SIZE + 1)
        .read_to_string(&mut json)?;
    if json.len() as u64 > MAX_SIGNING_KEY_FILE_SIZE {
        return Err(SigningError::InvalidKey(
            "Key file is invalid or too large".into(),
        ));
    }
    Ok(json)
}

fn encode_envelope_checked(envelope: &Envelope) -> Result<Vec<u8>, SigningError> {
    let bytes = postcard::to_allocvec(envelope)?;
    if bytes.is_empty() || bytes.len() > crate::crypto::MAX_ENVELOPE_SIZE {
        return Err(SigningError::InvalidEnvelope);
    }
    Ok(bytes)
}

fn write_atomic(path: &Path, bytes: &[u8], force: bool) -> Result<(), SigningError> {
    if path.exists() && !force {
        return Err(SigningError::OutputExists(path.display().to_string()));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;

    #[cfg(windows)]
    if force && path.exists() {
        fs::remove_file(path)?;
    }

    if force {
        temp.persist(path)
            .map_err(|error| SigningError::Io(error.error))?;
    } else {
        temp.persist_noclobber(path)
            .map_err(|error| SigningError::Io(error.error))?;
    }

    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn write_private_atomic(path: &Path, bytes: &[u8], force: bool) -> Result<(), SigningError> {
    if path.exists() && !force {
        return Err(SigningError::OutputExists(path.display().to_string()));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(parent)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(windows)]
    crate::crypto::keys::set_windows_acl(temp.path())?;

    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;

    #[cfg(windows)]
    if force && path.exists() {
        fs::remove_file(path)?;
    }

    if force {
        temp.persist(path)
            .map_err(|error| SigningError::Io(error.error))?;
    } else {
        temp.persist_noclobber(path)
            .map_err(|error| SigningError::Io(error.error))?;
    }

    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn decode_capsule_parts(data: &[u8]) -> Result<(Envelope, &[u8]), SigningError> {
    let length_bytes: [u8; 4] = data
        .get(..4)
        .ok_or(SigningError::InvalidEnvelope)?
        .try_into()
        .map_err(|_| SigningError::InvalidEnvelope)?;
    let envelope_len = u32::from_le_bytes(length_bytes) as usize;
    if envelope_len == 0 || envelope_len > crate::crypto::MAX_ENVELOPE_SIZE {
        return Err(SigningError::InvalidEnvelope);
    }
    let envelope_end = 4usize
        .checked_add(envelope_len)
        .ok_or(SigningError::InvalidEnvelope)?;
    let envelope_bytes = data
        .get(4..envelope_end)
        .ok_or(SigningError::InvalidEnvelope)?;
    let envelope = crate::crypto::decode_envelope_bytes(envelope_bytes)
        .map_err(|_| SigningError::InvalidEnvelope)?;
    Ok((envelope, &data[envelope_end..]))
}

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
    #[error("File is not a valid Lvau envelope")]
    InvalidEnvelope,
    #[error("Refusing to overwrite: {0}")]
    OutputExists(String),
    #[error("File is not signed")]
    NotSigned,
}

/// Serializable signing key pair file format.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SigningKeyFile {
    pub ed25519_signing_key: String, // base64-encoded 32-byte seed
}

impl std::fmt::Debug for SigningKeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyFile")
            .field("ed25519_signing_key", &"<redacted>")
            .finish()
    }
}

/// Serializable verify key file format.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct VerifyKeyFile {
    pub ed25519_verify_key: String, // base64-encoded 32-byte public key
}

/// Generate a new Ed25519 signing keypair.
///
/// Returns (signing_key_bytes, verify_key_bytes).
pub fn generate_signing_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verify_key = signing_key.verifying_key();
    (signing_key, verify_key)
}

/// Compute a SHA-256 fingerprint of a verifying key.
pub fn key_fingerprint(verify_key: &VerifyingKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(verify_key.as_bytes());
    hasher.finalize().into()
}

fn author_signature_message(
    envelope: &Envelope,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SigningError> {
    let mut statement = envelope.clone();
    let mut message = Vec::new();

    if statement.header.version >= lvau_protocol::envelope::CURRENT_VERSION {
        let signature = statement
            .signature
            .as_mut()
            .ok_or(SigningError::NotSigned)?;
        signature.signature.clear();
        // Approval seals are independent attestations and may be appended
        // after the author has signed the artifact.
        statement.approvals.clear();
        message.extend_from_slice(AUTHOR_SIGNATURE_V2_DOMAIN);
    } else {
        // Preserve the exact v1 signature statement for compatibility.
        statement.signature = None;
    }

    let envelope_bytes = postcard::to_allocvec(&statement)?;
    message.reserve(envelope_bytes.len() + ciphertext.len());
    message.extend_from_slice(&envelope_bytes);
    message.extend_from_slice(ciphertext);
    Ok(message)
}

fn approval_signature_message(
    envelope: &Envelope,
    ciphertext: &[u8],
    approval: &ApprovalSignature,
) -> Result<Vec<u8>, SigningError> {
    if envelope.header.version < lvau_protocol::envelope::CURRENT_VERSION {
        return Ok(envelope.aad_hash.to_vec());
    }

    let mut artifact = envelope.clone();
    artifact.approvals.clear();
    let artifact_bytes = postcard::to_allocvec(&artifact)?;
    let mut artifact_hasher = Sha256::new();
    artifact_hasher.update(APPROVAL_ARTIFACT_V2_DOMAIN);
    artifact_hasher.update(&artifact_bytes);
    artifact_hasher.update(ciphertext);
    let artifact_digest = artifact_hasher.finalize();

    let mut message = Vec::new();
    message.extend_from_slice(APPROVAL_SIGNATURE_V2_DOMAIN);
    message.extend_from_slice(&artifact_digest);
    message.extend_from_slice(&approval.signer_fingerprint);
    message.extend_from_slice(&postcard::to_allocvec(&approval.comment)?);
    Ok(message)
}

/// Save a signing key to a file (JSON with base64).
pub fn save_signing_key(key: &SigningKey, path: &Path, force: bool) -> Result<(), SigningError> {
    if path.exists() && !force {
        return Err(SigningError::OutputExists(path.display().to_string()));
    }

    let encoded =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key.to_bytes());
    let file_data = SigningKeyFile {
        ed25519_signing_key: encoded,
    };
    let json = serde_json::to_string_pretty(&file_data)
        .map_err(|_| SigningError::InvalidKey("JSON serialization failed".into()))?;

    write_private_atomic(path, json.as_bytes(), force)
}

/// Load a signing key from a file.
pub fn load_signing_key(path: &Path) -> Result<SigningKey, SigningError> {
    let json = read_key_file(path)?;
    let file_data: SigningKeyFile = serde_json::from_str(&json)
        .map_err(|_| SigningError::InvalidKey("Invalid signing key JSON".into()))?;
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &file_data.ed25519_signing_key,
    )
    .map_err(|_| SigningError::InvalidKey("Invalid base64 in signing key".into()))?;

    if bytes.len() != 32 {
        return Err(SigningError::InvalidKey(
            "Signing key must be 32 bytes".into(),
        ));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

/// Save a verifying key to a file (JSON with base64).
pub fn save_verify_key(key: &VerifyingKey, path: &Path, force: bool) -> Result<(), SigningError> {
    if path.exists() && !force {
        return Err(SigningError::OutputExists(path.display().to_string()));
    }

    let encoded =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key.as_bytes());
    let file_data = VerifyKeyFile {
        ed25519_verify_key: encoded,
    };
    let json = serde_json::to_string_pretty(&file_data)
        .map_err(|_| SigningError::InvalidKey("JSON serialization failed".into()))?;

    write_atomic(path, json.as_bytes(), force)
}

/// Load a verifying key from a file.
pub fn load_verify_key(path: &Path) -> Result<VerifyingKey, SigningError> {
    let json = read_key_file(path)?;
    let file_data: VerifyKeyFile = serde_json::from_str(&json)
        .map_err(|_| SigningError::InvalidKey("Invalid verify key JSON".into()))?;
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &file_data.ed25519_verify_key,
    )
    .map_err(|_| SigningError::InvalidKey("Invalid base64 in verify key".into()))?;

    if bytes.len() != 32 {
        return Err(SigningError::InvalidKey(
            "Verify key must be 32 bytes".into(),
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| SigningError::InvalidKey("Invalid Ed25519 verify key".into()))
}

/// Sign an existing `.lvau` file.
///
/// The signature covers the serialized envelope (without the signature field)
/// plus all ciphertext bytes.
pub fn sign_file(
    in_file: &Path,
    out_file: &Path,
    signing_key: &SigningKey,
    comment: Option<String>,
    force: bool,
) -> Result<(), SigningError> {
    if out_file.exists() && !force {
        return Err(SigningError::OutputExists(out_file.display().to_string()));
    }

    let data = fs::read(in_file)?;
    let (mut envelope, ciphertext) = decode_capsule_parts(&data)?;
    let verify_key = signing_key.verifying_key();
    let fingerprint = key_fingerprint(&verify_key);

    // Create timestamp
    let created_at = {
        use std::time::SystemTime;
        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => Some(format!("{}Z", d.as_secs())),
            Err(_) => None,
        }
    };

    // Put the metadata in the statement before signing. The signature bytes
    // themselves are cleared by author_signature_message to avoid recursion.
    envelope.signature = Some(EnvelopeSignature {
        signer_fingerprint: fingerprint,
        signature: Vec::new(),
        created_at,
        comment,
    });
    let message = author_signature_message(&envelope, ciphertext)?;
    let signature = signing_key.sign(&message);
    envelope
        .signature
        .as_mut()
        .expect("signature metadata was just initialized")
        .signature = signature.to_bytes().to_vec();

    // Serialize the full envelope with signature, preserving the parser's
    // envelope-size invariant.
    let signed_envelope_bytes = encode_envelope_checked(&envelope)?;
    let signed_env_len =
        u32::try_from(signed_envelope_bytes.len()).map_err(|_| SigningError::InvalidEnvelope)?;

    // Write the signed file
    let mut output = Vec::with_capacity(4 + signed_envelope_bytes.len() + ciphertext.len());
    output.extend_from_slice(&signed_env_len.to_le_bytes());
    output.extend_from_slice(&signed_envelope_bytes);
    output.extend_from_slice(ciphertext);

    write_atomic(out_file, &output, force)
}

/// Verify the Ed25519 signature on an `.lvau` file.
///
/// Returns the signer fingerprint on success.
pub fn verify_signature(
    in_file: &Path,
    verify_key: &VerifyingKey,
) -> Result<[u8; 32], SigningError> {
    let data = fs::read(in_file)?;
    let (envelope, ciphertext) = decode_capsule_parts(&data)?;

    let sig_data = envelope.signature.as_ref().ok_or(SigningError::NotSigned)?;

    if sig_data.signature.len() != 64 {
        return Err(SigningError::VerificationFailed);
    }

    let actual_fingerprint = key_fingerprint(verify_key);
    if sig_data.signer_fingerprint != actual_fingerprint {
        return Err(SigningError::VerificationFailed);
    }

    let message = author_signature_message(&envelope, ciphertext)?;

    // Verify
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig_data.signature);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    verify_key
        .verify(&message, &signature)
        .map_err(|_| SigningError::VerificationFailed)?;

    Ok(actual_fingerprint)
}

/// Check if a file has a signature without verifying it.
pub fn has_signature(in_file: &Path) -> Result<Option<[u8; 32]>, SigningError> {
    let data = fs::read(in_file)?;
    let (envelope, _) = decode_capsule_parts(&data)?;

    Ok(envelope.signature.map(|s| s.signer_fingerprint))
}

/// Add an approval seal to an existing `.lvau` file.
///
/// A v2 approval seal commits to the public envelope, ciphertext, approving
/// key fingerprint, and comment. Legacy v1 seals cover only the stored AAD
/// hash and are retained solely for compatibility.
pub fn add_approval_seal(
    in_file: &Path,
    out_file: &Path,
    signing_key: &SigningKey,
    comment: Option<String>,
    force: bool,
) -> Result<(), SigningError> {
    if out_file.exists() && !force {
        return Err(SigningError::OutputExists(out_file.display().to_string()));
    }

    let data = fs::read(in_file)?;
    let (mut envelope, ciphertext) = decode_capsule_parts(&data)?;

    let verify_key = signing_key.verifying_key();
    let fingerprint = key_fingerprint(&verify_key);

    let mut approval = ApprovalSignature {
        signer_fingerprint: fingerprint,
        signature: Vec::new(),
        comment,
    };
    let message = approval_signature_message(&envelope, ciphertext, &approval)?;
    approval.signature = signing_key.sign(&message).to_bytes().to_vec();

    envelope.approvals.push(approval);

    // Re-serialize the envelope without producing a capsule that the parser
    // would reject as oversized.
    let new_envelope_bytes = encode_envelope_checked(&envelope)?;
    let new_env_len =
        u32::try_from(new_envelope_bytes.len()).map_err(|_| SigningError::InvalidEnvelope)?;

    let mut output = Vec::with_capacity(4 + new_envelope_bytes.len() + ciphertext.len());
    output.extend_from_slice(&new_env_len.to_le_bytes());
    output.extend_from_slice(&new_envelope_bytes);
    output.extend_from_slice(ciphertext);

    write_atomic(out_file, &output, force)
}

/// Verify all approval seals in a file using a given verify key.
/// Returns true if at least one valid approval from the given key exists.
pub fn verify_approvals(in_file: &Path, verify_key: &VerifyingKey) -> Result<bool, SigningError> {
    let data = fs::read(in_file)?;
    let (envelope, ciphertext) = decode_capsule_parts(&data)?;
    let fingerprint = key_fingerprint(verify_key);

    let mut found_valid = false;
    for approval in &envelope.approvals {
        if approval.signer_fingerprint == fingerprint && approval.signature.len() == 64 {
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&approval.signature);
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

            let message = approval_signature_message(&envelope, ciphertext, approval)?;
            if verify_key.verify(&message, &signature).is_ok() {
                found_valid = true;
            }
        }
    }

    Ok(found_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt_file_password;
    use lvau_protocol::envelope::SecurityProfile;
    use secrecy::SecretString;
    use tempfile::tempdir;

    #[test]
    fn keygen_sign_and_verify() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let signed = dir.path().join("signed.lvau");

        fs::write(&input, "test data for signing").unwrap();

        encrypt_file_password(
            &input,
            &encrypted,
            SecretString::from("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
            None,
            false,
        )
        .unwrap();

        let (signing_key, verify_key) = generate_signing_keypair();

        sign_file(&encrypted, &signed, &signing_key, None, false).unwrap();

        let fingerprint = verify_signature(&signed, &verify_key).unwrap();
        assert_eq!(fingerprint, key_fingerprint(&verify_key));
    }

    #[test]
    fn oversized_signature_metadata_is_rejected_without_output() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let signed = dir.path().join("signed.lvau");
        fs::write(&input, "metadata bound test").unwrap();

        encrypt_file_password(
            &input,
            &encrypted,
            SecretString::from("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
            None,
            false,
        )
        .unwrap();

        let (signing_key, _) = generate_signing_keypair();
        let result = sign_file(
            &encrypted,
            &signed,
            &signing_key,
            Some("x".repeat(crate::crypto::MAX_ENVELOPE_SIZE)),
            false,
        );

        assert!(matches!(result, Err(SigningError::InvalidEnvelope)));
        assert!(!signed.exists());
    }

    #[test]
    fn modified_ciphertext_fails_verification() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let signed = dir.path().join("signed.lvau");

        fs::write(&input, "tamper test data").unwrap();

        encrypt_file_password(
            &input,
            &encrypted,
            SecretString::from("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
            None,
            false,
        )
        .unwrap();

        let (signing_key, verify_key) = generate_signing_keypair();
        sign_file(&encrypted, &signed, &signing_key, None, false).unwrap();

        // Tamper with the signed file
        let mut data = fs::read(&signed).unwrap();
        if let Some(last) = data.last_mut() {
            *last ^= 0xFF;
        }
        fs::write(&signed, data).unwrap();

        let result = verify_signature(&signed, &verify_key);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_verify_key_fails() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let signed = dir.path().join("signed.lvau");

        fs::write(&input, "wrong key test").unwrap();

        encrypt_file_password(
            &input,
            &encrypted,
            SecretString::from("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
            None,
            false,
        )
        .unwrap();

        let (signing_key, _) = generate_signing_keypair();
        let (_, wrong_verify_key) = generate_signing_keypair();

        sign_file(&encrypted, &signed, &signing_key, None, false).unwrap();

        let result = verify_signature(&signed, &wrong_verify_key);
        assert!(result.is_err());
    }

    #[test]
    fn unsigned_file_reports_not_signed() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");

        fs::write(&input, "unsigned test data").unwrap();

        encrypt_file_password(
            &input,
            &encrypted,
            SecretString::from("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
            None,
            false,
        )
        .unwrap();

        let (_, verify_key) = generate_signing_keypair();
        let result = verify_signature(&encrypted, &verify_key);
        assert!(matches!(result, Err(SigningError::NotSigned)));

        let has_sig = has_signature(&encrypted).unwrap();
        assert!(has_sig.is_none());
    }

    #[test]
    fn save_and_load_signing_keys() {
        let dir = tempdir().unwrap();
        let sign_path = dir.path().join("test.lvau-sign");
        let verify_path = dir.path().join("test.lvau-verify");

        let (signing_key, verify_key) = generate_signing_keypair();

        save_signing_key(&signing_key, &sign_path, false).unwrap();
        save_verify_key(&verify_key, &verify_path, false).unwrap();

        let loaded_sign = load_signing_key(&sign_path).unwrap();
        let loaded_verify = load_verify_key(&verify_path).unwrap();

        assert_eq!(signing_key.to_bytes(), loaded_sign.to_bytes());
        assert_eq!(verify_key.as_bytes(), loaded_verify.as_bytes());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(sign_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn modified_envelope_fails_verification() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let signed = dir.path().join("signed.lvau");

        fs::write(&input, "envelope tamper test").unwrap();

        encrypt_file_password(
            &input,
            &encrypted,
            SecretString::from("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
            None,
            false,
        )
        .unwrap();

        let (signing_key, verify_key) = generate_signing_keypair();
        sign_file(&encrypted, &signed, &signing_key, None, false).unwrap();

        // Tamper with a byte in the envelope area (after the 4-byte length prefix)
        let mut data = fs::read(&signed).unwrap();
        if data.len() > 10 {
            data[8] ^= 0xFF; // flip a byte in the envelope
        }
        fs::write(&signed, data).unwrap();

        let result = verify_signature(&signed, &verify_key);
        assert!(result.is_err());
    }

    fn mutate_signature_envelope(path: &Path, mutate: impl FnOnce(&mut EnvelopeSignature)) {
        let data = fs::read(path).unwrap();
        let env_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let mut envelope: Envelope = postcard::from_bytes(&data[4..4 + env_len]).unwrap();
        mutate(envelope.signature.as_mut().unwrap());
        let envelope_bytes = postcard::to_allocvec(&envelope).unwrap();

        let mut output = Vec::new();
        output.extend_from_slice(&(envelope_bytes.len() as u32).to_le_bytes());
        output.extend_from_slice(&envelope_bytes);
        output.extend_from_slice(&data[4 + env_len..]);
        fs::write(path, output).unwrap();
    }

    #[test]
    fn stored_signer_fingerprint_cannot_be_spoofed() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let signed = dir.path().join("signed.lvau");
        fs::write(&input, "fingerprint binding").unwrap();
        encrypt_file_password(
            &input,
            &encrypted,
            SecretString::from("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
            None,
            false,
        )
        .unwrap();

        let (signing_key, verify_key) = generate_signing_keypair();
        sign_file(&encrypted, &signed, &signing_key, None, false).unwrap();
        mutate_signature_envelope(&signed, |signature| {
            signature.signer_fingerprint = [0xA5; 32];
        });

        assert!(verify_signature(&signed, &verify_key).is_err());
    }

    #[test]
    fn v2_signature_comment_is_authenticated() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let signed = dir.path().join("signed.lvau");
        fs::write(&input, "signature metadata binding").unwrap();
        encrypt_file_password(
            &input,
            &encrypted,
            SecretString::from("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
            None,
            false,
        )
        .unwrap();

        let (signing_key, verify_key) = generate_signing_keypair();
        sign_file(
            &encrypted,
            &signed,
            &signing_key,
            Some("reviewed".to_string()),
            false,
        )
        .unwrap();
        mutate_signature_envelope(&signed, |signature| {
            signature.comment = Some("forged comment".to_string());
        });

        assert!(verify_signature(&signed, &verify_key).is_err());
    }

    #[test]
    fn v2_approval_commits_to_ciphertext() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let approved = dir.path().join("approved.lvau");
        fs::write(&input, "approval subject").unwrap();
        encrypt_file_password(
            &input,
            &encrypted,
            SecretString::from("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
            None,
            false,
        )
        .unwrap();

        let (approval_key, approval_verify_key) = generate_signing_keypair();
        add_approval_seal(
            &encrypted,
            &approved,
            &approval_key,
            Some("approved".to_string()),
            false,
        )
        .unwrap();
        assert!(verify_approvals(&approved, &approval_verify_key).unwrap());

        let mut data = fs::read(&approved).unwrap();
        *data.last_mut().unwrap() ^= 0x40;
        fs::write(&approved, data).unwrap();
        assert!(!verify_approvals(&approved, &approval_verify_key).unwrap());
    }

    #[test]
    fn adding_v2_approval_does_not_invalidate_author_signature() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("input.txt");
        let encrypted = dir.path().join("encrypted.lvau");
        let signed = dir.path().join("signed.lvau");
        let approved = dir.path().join("approved.lvau");
        fs::write(&input, "author then approval").unwrap();
        encrypt_file_password(
            &input,
            &encrypted,
            SecretString::from("password".to_string()),
            None,
            SecurityProfile::Fast,
            None,
            None,
            false,
        )
        .unwrap();

        let (author_key, author_verify_key) = generate_signing_keypair();
        let (approval_key, approval_verify_key) = generate_signing_keypair();
        sign_file(&encrypted, &signed, &author_key, None, false).unwrap();
        add_approval_seal(&signed, &approved, &approval_key, None, false).unwrap();

        verify_signature(&approved, &author_verify_key).unwrap();
        assert!(verify_approvals(&approved, &approval_verify_key).unwrap());
    }
}

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

        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
