//! Bounded-memory bundle packing, verification, listing, and extraction.
//!
//! The on-disk payload remains compatible with the existing v2 bundle layout:
//! `[manifest length][postcard manifest][concatenated file bytes][padding]`.
//! Only the implementation strategy changes: file contents are never collected
//! into one payload-sized allocation.

use crate::bundle::{validate_relative_path, BundleError, PaddingProfile};
use crate::crypto::{decrypt_file_password, EncryptCredential};
use lvau_protocol::envelope::{BundleEntry, BundleManifest, ContentType, SecurityProfile};
use secrecy::SecretString;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use tempfile::{tempdir, NamedTempFile, TempDir};
use walkdir::WalkDir;

/// Maximum transient buffer used for bundle file contents.
pub const BUNDLE_COPY_BUFFER_SIZE: usize = 64 * 1024;
/// Maximum serialized manifest accepted or produced by the streaming pipeline.
pub const MAX_BUNDLE_MANIFEST_SIZE: usize = 16 * 1024 * 1024;

#[derive(Debug)]
struct SourceFile {
    relative_path: String,
    absolute_path: PathBuf,
    size: u64,
    blake3_hash: [u8; 32],
}

struct DecryptedBundle {
    _temp_dir: TempDir,
    file: File,
    manifest: BundleManifest,
    data_start: u64,
    payload_len: u64,
}

fn hash_reader(reader: &mut dyn Read, expected_len: u64) -> Result<[u8; 32], BundleError> {
    let mut remaining = expected_len;
    let mut buffer = [0u8; BUNDLE_COPY_BUFFER_SIZE];
    let mut hasher = blake3::Hasher::new();

    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| BundleError::ManifestError("File size is not representable".into()))?;
        let read = reader.read(&mut buffer[..requested])?;
        if read == 0 {
            return Err(BundleError::ManifestError(
                "Bundle file data is truncated".into(),
            ));
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }

    Ok(*hasher.finalize().as_bytes())
}

fn hash_file(path: &Path) -> Result<(u64, [u8; 32]), BundleError> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    let hash = hash_reader(&mut file, size)?;
    let mut trailing = [0u8; 1];
    if file.read(&mut trailing)? != 0 {
        return Err(BundleError::ManifestError(format!(
            "Input changed while hashing: {}",
            path.display()
        )));
    }
    Ok((size, hash))
}

fn collect_sources(in_dir: &Path, allow_symlinks: bool) -> Result<Vec<SourceFile>, BundleError> {
    if !in_dir.is_dir() {
        return Err(BundleError::InputDirNotFound(in_dir.display().to_string()));
    }

    let mut paths = Vec::new();
    for entry in WalkDir::new(in_dir).follow_links(false) {
        let entry = entry.map_err(|error| BundleError::WalkError(error.to_string()))?;
        let path = entry.path();
        if path == in_dir || entry.file_type().is_dir() {
            continue;
        }
        if entry.path_is_symlink() && !allow_symlinks {
            return Err(BundleError::SymlinkRejected(path.display().to_string()));
        }
        if entry.path_is_symlink() {
            if !fs::metadata(path)?.is_file() {
                return Err(BundleError::SpecialFileRejected(path.display().to_string()));
            }
        } else if !entry.file_type().is_file() {
            return Err(BundleError::SpecialFileRejected(path.display().to_string()));
        }

        let relative = path
            .strip_prefix(in_dir)
            .map_err(|_| BundleError::WalkError("Failed to compute relative path".into()))?;
        let relative_path = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join("/");
        validate_relative_path(&relative_path)?;
        paths.push((relative_path, path.to_path_buf()));
    }
    paths.sort_by(|left, right| left.0.cmp(&right.0));

    let mut sources = Vec::with_capacity(paths.len());
    for (relative_path, absolute_path) in paths {
        let (size, blake3_hash) = hash_file(&absolute_path)?;
        sources.push(SourceFile {
            relative_path,
            absolute_path,
            size,
            blake3_hash,
        });
    }
    Ok(sources)
}

fn build_manifest(sources: &[SourceFile]) -> Result<BundleManifest, BundleError> {
    let mut offset = 0u64;
    let mut entries = Vec::with_capacity(sources.len());
    for source in sources {
        entries.push(BundleEntry {
            relative_path: source.relative_path.clone(),
            size: source.size,
            blake3_hash: source.blake3_hash,
            offset,
        });
        offset = offset
            .checked_add(source.size)
            .ok_or_else(|| BundleError::ManifestError("Bundle size overflow".into()))?;
    }
    Ok(BundleManifest {
        entries,
        created_at: Some(timestamp()),
        tool_version: Some(format!("lvau {}", env!("CARGO_PKG_VERSION"))),
    })
}

fn copy_source_checked(source: &SourceFile, output: &mut dyn Write) -> Result<(), BundleError> {
    let mut input = File::open(&source.absolute_path)?;
    let current_size = input.metadata()?.len();
    if current_size != source.size {
        return Err(BundleError::ManifestError(format!(
            "Input size changed during packing: {}",
            source.absolute_path.display()
        )));
    }

    let mut remaining = source.size;
    let mut buffer = [0u8; BUNDLE_COPY_BUFFER_SIZE];
    let mut hasher = blake3::Hasher::new();
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| BundleError::ManifestError("File size is not representable".into()))?;
        let read = input.read(&mut buffer[..requested])?;
        if read == 0 {
            return Err(BundleError::ManifestError(format!(
                "Input truncated during packing: {}",
                source.absolute_path.display()
            )));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
        remaining -= read as u64;
    }
    let mut trailing = [0u8; 1];
    if input.read(&mut trailing)? != 0 || *hasher.finalize().as_bytes() != source.blake3_hash {
        return Err(BundleError::ManifestError(format!(
            "Input changed during packing: {}",
            source.absolute_path.display()
        )));
    }
    Ok(())
}

fn write_zero_padding(output: &mut dyn Write, mut bytes: u64) -> Result<(), BundleError> {
    let zeroes = [0u8; BUNDLE_COPY_BUFFER_SIZE];
    while bytes > 0 {
        let count = usize::try_from(bytes.min(zeroes.len() as u64))
            .map_err(|_| BundleError::ManifestError("Padding size is not representable".into()))?;
        output.write_all(&zeroes[..count])?;
        bytes -= count as u64;
    }
    Ok(())
}

fn padding_target(current_len: u64, padding: &PaddingProfile) -> Result<u64, BundleError> {
    match padding {
        PaddingProfile::None => Ok(current_len),
        PaddingProfile::Bucket => current_len
            .checked_next_power_of_two()
            .ok_or_else(|| BundleError::ManifestError("Padding size overflow".into())),
        PaddingProfile::Fixed(size) => Ok(current_len.max(*size as u64)),
    }
}

/// Pack a directory without buffering the complete plaintext bundle.
#[allow(clippy::too_many_arguments)]
pub fn pack_directory(
    in_dir: &Path,
    out_file: &Path,
    credential: EncryptCredential,
    profile: SecurityProfile,
    allow_symlinks: bool,
    padding: &PaddingProfile,
    force: bool,
    policy: Option<&crate::policy::CapsulePolicy>,
    allow_policy_override: bool,
) -> Result<BundleManifest, BundleError> {
    if out_file.exists() && !force {
        return Err(BundleError::OutputExists(out_file.display().to_string()));
    }

    let sources = collect_sources(in_dir, allow_symlinks)?;
    let manifest = build_manifest(&sources)?;
    let manifest_bytes = postcard::to_allocvec(&manifest)?;
    if manifest_bytes.is_empty() || manifest_bytes.len() > MAX_BUNDLE_MANIFEST_SIZE {
        return Err(BundleError::ManifestError(
            "Bundle manifest exceeds the supported limit".into(),
        ));
    }
    let manifest_len = u32::try_from(manifest_bytes.len())
        .map_err(|_| BundleError::ManifestError("Manifest size overflow".into()))?;

    let parent = out_file.parent().unwrap_or_else(|| Path::new("."));
    let mut plaintext = NamedTempFile::new_in(parent)?;
    plaintext.write_all(&manifest_len.to_le_bytes())?;
    plaintext.write_all(&manifest_bytes)?;
    for source in &sources {
        copy_source_checked(source, &mut plaintext)?;
    }

    let current_len = plaintext.as_file().metadata()?.len();
    let target_len = padding_target(current_len, padding)?;
    write_zero_padding(&mut plaintext, target_len - current_len)?;
    plaintext.as_file().sync_all()?;

    let result = match credential {
        EncryptCredential::Password(password, seed) => {
            crate::crypto::encrypt_file_password_with_content_type(
                plaintext.path(),
                out_file,
                password,
                seed,
                profile,
                None,
                policy,
                allow_policy_override,
                Some(ContentType::Bundle),
            )
        }
        EncryptCredential::Keypairs(recipients) => {
            crate::crypto::encrypt_file_keypairs_with_content_type(
                plaintext.path(),
                out_file,
                &recipients,
                profile,
                None,
                policy,
                allow_policy_override,
                Some(ContentType::Bundle),
            )
        }
    };
    result.map_err(BundleError::Crypto)?;
    Ok(manifest)
}

fn decode_manifest(bytes: &[u8]) -> Result<BundleManifest, BundleError> {
    let (manifest, remaining) = postcard::take_from_bytes(bytes)?;
    if !remaining.is_empty() {
        return Err(BundleError::ManifestError(
            "Manifest contains trailing non-canonical bytes".into(),
        ));
    }
    Ok(manifest)
}

fn validate_layout(
    manifest: &BundleManifest,
    data_start: u64,
    payload_len: u64,
) -> Result<(), BundleError> {
    let mut paths = HashSet::new();
    let mut ranges = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        validate_relative_path(&entry.relative_path)?;
        if !paths.insert(entry.relative_path.to_lowercase()) {
            return Err(BundleError::ManifestError(format!(
                "Duplicate or cross-platform-colliding path: {}",
                entry.relative_path
            )));
        }
        let start = data_start
            .checked_add(entry.offset)
            .ok_or_else(|| BundleError::ManifestError("File offset overflow".into()))?;
        let end = start
            .checked_add(entry.size)
            .ok_or_else(|| BundleError::ManifestError("File size overflow".into()))?;
        if end > payload_len {
            return Err(BundleError::ManifestError(format!(
                "File data truncated for: {}",
                entry.relative_path
            )));
        }
        if start != end {
            ranges.push((start, end, entry.relative_path.as_str()));
        }
    }
    ranges.sort_unstable_by_key(|range| range.0);
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(BundleError::ManifestError(format!(
                "Overlapping file ranges: {} and {}",
                pair[0].2, pair[1].2
            )));
        }
    }
    Ok(())
}

fn decrypt_and_open(
    in_file: &Path,
    password: SecretString,
) -> Result<DecryptedBundle, BundleError> {
    let temp_dir = tempdir()?;
    let plaintext_path = temp_dir.path().join("bundle.payload");
    decrypt_file_password(in_file, &plaintext_path, password, None, None)?;

    let mut file = File::open(&plaintext_path)?;
    let payload_len = file.metadata()?.len();
    if payload_len < 4 {
        return Err(BundleError::ManifestError(
            "Bundle payload is too small".into(),
        ));
    }
    let mut length = [0u8; 4];
    file.read_exact(&mut length)?;
    let manifest_len = u32::from_le_bytes(length) as usize;
    if manifest_len == 0 || manifest_len > MAX_BUNDLE_MANIFEST_SIZE {
        return Err(BundleError::ManifestError(
            "Bundle manifest size is invalid".into(),
        ));
    }
    let data_start = 4u64
        .checked_add(manifest_len as u64)
        .ok_or_else(|| BundleError::ManifestError("Manifest length overflow".into()))?;
    if data_start > payload_len {
        return Err(BundleError::ManifestError(
            "Bundle payload is truncated before the manifest ends".into(),
        ));
    }
    let mut bytes = vec![0u8; manifest_len];
    file.read_exact(&mut bytes)?;
    let manifest = decode_manifest(&bytes)?;
    validate_layout(&manifest, data_start, payload_len)?;

    Ok(DecryptedBundle {
        _temp_dir: temp_dir,
        file,
        manifest,
        data_start,
        payload_len,
    })
}

fn verify_entry(file: &mut File, data_start: u64, entry: &BundleEntry) -> Result<(), BundleError> {
    let start = data_start
        .checked_add(entry.offset)
        .ok_or_else(|| BundleError::ManifestError("File offset overflow".into()))?;
    file.seek(SeekFrom::Start(start))?;
    let actual = hash_reader(file, entry.size)?;
    if actual != entry.blake3_hash {
        return Err(BundleError::ManifestError(format!(
            "BLAKE3 hash mismatch for: {}",
            entry.relative_path
        )));
    }
    Ok(())
}

fn verify_all(bundle: &mut DecryptedBundle) -> Result<(), BundleError> {
    // Preserve the payload length in this validation object so future layout
    // changes cannot accidentally skip the bound checked during parsing.
    validate_layout(&bundle.manifest, bundle.data_start, bundle.payload_len)?;
    for entry in &bundle.manifest.entries {
        verify_entry(&mut bundle.file, bundle.data_start, entry)?;
    }
    Ok(())
}

/// List and authenticate every entry while retaining only the manifest in memory.
pub fn list_bundle(in_file: &Path, password: SecretString) -> Result<BundleManifest, BundleError> {
    let mut bundle = decrypt_and_open(in_file, password)?;
    verify_all(&mut bundle)?;
    Ok(bundle.manifest)
}

fn validate_existing_target(path: &Path) -> Result<(), BundleError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(BundleError::SymlinkRejected(path.display().to_string()));
    }
    if !metadata.file_type().is_file() {
        return Err(BundleError::SpecialFileRejected(path.display().to_string()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(BundleError::HardlinkRejected(path.display().to_string()));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_FLAG_OPEN_REPARSE_POINT,
        };

        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path)?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            GetFileInformationByHandle(file.as_raw_handle() as isize, std::ptr::addr_of_mut!(info))
        };
        if ok == 0 {
            return Err(BundleError::Io(std::io::Error::last_os_error()));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(BundleError::SymlinkRejected(path.display().to_string()));
        }
        if info.nNumberOfLinks != 1 {
            return Err(BundleError::HardlinkRejected(path.display().to_string()));
        }
    }
    Ok(())
}

fn validate_extraction_directory(path: &Path) -> Result<(), BundleError> {
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
    if force && target.exists() {
        validate_existing_target(target)?;
        #[cfg(windows)]
        fs::remove_file(target)?;
        temp.persist(target)
            .map_err(|error| BundleError::Io(error.error))?;
    } else {
        temp.persist_noclobber(target)
            .map_err(|error| match error.error.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    BundleError::OutputExists(target.display().to_string())
                }
                _ => BundleError::Io(error.error),
            })?;
    }
    #[cfg(unix)]
    if let Some(parent) = target.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn copy_entry(
    source: &mut File,
    data_start: u64,
    entry: &BundleEntry,
    output: &mut dyn Write,
) -> Result<(), BundleError> {
    let start = data_start
        .checked_add(entry.offset)
        .ok_or_else(|| BundleError::ManifestError("File offset overflow".into()))?;
    source.seek(SeekFrom::Start(start))?;
    let mut remaining = entry.size;
    let mut buffer = [0u8; BUNDLE_COPY_BUFFER_SIZE];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| BundleError::ManifestError("File size is not representable".into()))?;
        let read = source.read(&mut buffer[..requested])?;
        if read == 0 {
            return Err(BundleError::ManifestError(format!(
                "File data truncated for: {}",
                entry.relative_path
            )));
        }
        output.write_all(&buffer[..read])?;
        remaining -= read as u64;
    }
    Ok(())
}

/// Extract an authenticated bundle with bounded memory and atomic named outputs.
pub fn extract_bundle(
    in_file: &Path,
    out_dir: &Path,
    password: SecretString,
    _allow_symlinks: bool,
    force: bool,
    dry_run: bool,
) -> Result<BundleManifest, BundleError> {
    let mut bundle = decrypt_and_open(in_file, password)?;
    // Authenticate every entry before creating any named output.
    verify_all(&mut bundle)?;

    if dry_run {
        for entry in &bundle.manifest.entries {
            log::info!(
                "Would extract: {} ({} bytes)",
                entry.relative_path,
                entry.size
            );
        }
        return Ok(bundle.manifest);
    }

    fs::create_dir_all(out_dir)?;
    validate_extraction_directory(out_dir)?;
    let canonical_out = out_dir.canonicalize()?;
    for entry in &bundle.manifest.entries {
        let relative = validate_relative_path(&entry.relative_path)?;
        let target = out_dir.join(relative);
        let parent = target.parent().unwrap_or(out_dir);
        ensure_safe_extraction_parent(out_dir, parent)?;
        let canonical_parent = parent.canonicalize()?;
        if !canonical_parent.starts_with(&canonical_out) {
            return Err(BundleError::PathTraversal(format!(
                "Resolved path escapes output directory: {}",
                entry.relative_path
            )));
        }
        match fs::symlink_metadata(&target) {
            Ok(_) if !force => {
                return Err(BundleError::OutputExists(target.display().to_string()));
            }
            Ok(_) => validate_existing_target(&target)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(BundleError::Io(error)),
        }

        let mut output = NamedTempFile::new_in(parent)?;
        copy_entry(&mut bundle.file, bundle.data_start, entry, &mut output)?;
        output.as_file().sync_all()?;
        persist_output(output, &target, force)?;
        log::info!("Extracted: {} ({} bytes)", entry.relative_path, entry.size);
    }
    Ok(bundle.manifest)
}

/// Authenticate a bundle without extracting it.
pub fn verify_bundle(
    in_file: &Path,
    password: SecretString,
) -> Result<BundleManifest, BundleError> {
    let mut bundle = decrypt_and_open(in_file, password)?;
    verify_all(&mut bundle)?;
    log::info!("Bundle verified: {} files", bundle.manifest.entries.len());
    Ok(bundle.manifest)
}

fn timestamp() -> String {
    use std::time::SystemTime;
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => format!("{}Z", duration.as_secs()),
        Err(_) => "0Z".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password() -> SecretString {
        SecretString::from("streaming-bundle-password".to_string())
    }

    #[test]
    fn copy_buffer_is_bounded() {
        assert_eq!(BUNDLE_COPY_BUFFER_SIZE, 64 * 1024);
    }

    #[test]
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
        let dir = tempdir().unwrap();
        let input = dir.path().join("input");
        let encrypted = dir.path().join("large.lvau");
        let output = dir.path().join("output");
        fs::create_dir_all(&input).unwrap();

        let file = input.join("large.bin");
        let mut writer = File::create(&file).unwrap();
        let block = [0x5Au8; BUNDLE_COPY_BUFFER_SIZE];
        for _ in 0..48 {
            writer.write_all(&block).unwrap();
        }
        writer.sync_all().unwrap();

        pack_directory(
            &input,
            &encrypted,
            EncryptCredential::Password(password(), None),
            SecurityProfile::Fast,
            false,
            &PaddingProfile::None,
            false,
            None,
            false,
        )
        .unwrap();
        extract_bundle(&encrypted, &output, password(), false, false, false).unwrap();
        assert_eq!(
            fs::metadata(file).unwrap().len(),
            fs::metadata(output.join("large.bin")).unwrap().len()
        );
    }
}
