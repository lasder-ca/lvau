use lvau_protocol::envelope::ReleaseMetadata;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("Failed to parse, missing, or oversized envelope")]
    EnvelopeError,
}

fn encode_envelope_checked(
    envelope: &lvau_protocol::envelope::Envelope,
) -> Result<Vec<u8>, ReleaseError> {
    let bytes = postcard::to_allocvec(envelope)?;
    if bytes.is_empty() || bytes.len() > crate::crypto::MAX_ENVELOPE_SIZE {
        return Err(ReleaseError::EnvelopeError);
    }
    Ok(bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ReleaseError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;

    #[cfg(windows)]
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    temp.persist(path)
        .map_err(|error| ReleaseError::Io(error.error))?;

    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn decode_capsule_envelope(
    data: &[u8],
) -> Result<(lvau_protocol::envelope::Envelope, usize), ReleaseError> {
    let length_bytes: [u8; 4] = data
        .get(..4)
        .ok_or(ReleaseError::EnvelopeError)?
        .try_into()
        .map_err(|_| ReleaseError::EnvelopeError)?;
    let envelope_len = u32::from_le_bytes(length_bytes) as usize;
    if envelope_len == 0 || envelope_len > crate::crypto::MAX_ENVELOPE_SIZE {
        return Err(ReleaseError::EnvelopeError);
    }
    let envelope_end = 4usize
        .checked_add(envelope_len)
        .ok_or(ReleaseError::EnvelopeError)?;
    let envelope_bytes = data
        .get(4..envelope_end)
        .ok_or(ReleaseError::EnvelopeError)?;
    let envelope = crate::crypto::decode_envelope_bytes(envelope_bytes)
        .map_err(|_| ReleaseError::EnvelopeError)?;
    Ok((envelope, envelope_end))
}

pub fn attach_release_metadata(
    in_file: &Path,
    out_file: &Path,
    project_name: Option<String>,
    version: Option<String>,
    git_commit: Option<String>,
    build_timestamp: Option<String>,
) -> Result<(), ReleaseError> {
    let metadata = ReleaseMetadata {
        project_name,
        version,
        git_commit,
        build_timestamp,
    };

    let data = std::fs::read(in_file)?;
    let (mut envelope, envelope_end) = decode_capsule_envelope(&data)?;

    envelope.release_metadata = Some(metadata);

    let new_env_bytes = encode_envelope_checked(&envelope)?;
    let new_len = u32::try_from(new_env_bytes.len()).map_err(|_| ReleaseError::EnvelopeError)?;

    let mut new_data = Vec::with_capacity(4 + new_env_bytes.len() + (data.len() - envelope_end));
    new_data.extend_from_slice(&new_len.to_le_bytes());
    new_data.extend_from_slice(&new_env_bytes);
    new_data.extend_from_slice(&data[envelope_end..]);

    write_atomic(out_file, &new_data)?;

    Ok(())
}

pub fn attach_recovery_metadata(
    in_file: &Path,
    out_file: &Path,
    recovery_data: Vec<u8>,
) -> Result<(), ReleaseError> {
    let data = std::fs::read(in_file)?;
    let (mut envelope, envelope_end) = decode_capsule_envelope(&data)?;

    envelope.recovery_metadata = Some(recovery_data);

    let new_env_bytes = encode_envelope_checked(&envelope)?;
    let new_len = u32::try_from(new_env_bytes.len()).map_err(|_| ReleaseError::EnvelopeError)?;

    let mut new_data = Vec::with_capacity(4 + new_env_bytes.len() + (data.len() - envelope_end));
    new_data.extend_from_slice(&new_len.to_le_bytes());
    new_data.extend_from_slice(&new_env_bytes);
    new_data.extend_from_slice(&data[envelope_end..]);

    write_atomic(out_file, &new_data)?;

    Ok(())
}
