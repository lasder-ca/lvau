#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "crates/lvau-cli/src/main.rs"
text = PATH.read_text(encoding="utf-8")


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one anchor, found {count}: {old[:80]!r}")
    text = text.replace(old, new, 1)


replace_once(
    "use std::io::{self, Write};",
    "use std::io::{self, Read, Write};",
)

replace_once(
    "fn prompt_password(prompt: &str) -> Result<String, CliError> {",
    "const MAX_SECRET_FILE_SIZE: u64 = 64 * 1024;\n\nfn prompt_password(prompt: &str) -> Result<String, CliError> {",
)

replace_once(
    '''fn read_secret_file(path: &Path) -> Result<String, CliError> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(CliError::Message(format!(
            "Secret file is not a regular file: {}",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::Message(format!(
                "Secret file permissions are too broad: {} (use chmod 600)",
                path.display()
            )));
        }
    }

    let value = fs::read_to_string(path)?;
    Ok(value.trim_end_matches(['\\r', '\\n']).to_string())
}''',
    '''fn read_secret_file(path: &Path) -> Result<String, CliError> {
    // Keep metadata checks and reads tied to the same open file handle so a
    // path swap cannot change the file after validation.
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(CliError::Message(format!(
            "Secret file is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_SECRET_FILE_SIZE {
        return Err(CliError::Message(format!(
            "Secret file is too large: {} (maximum {} bytes)",
            path.display(),
            MAX_SECRET_FILE_SIZE
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::Message(format!(
                "Secret file permissions are too broad: {} (use chmod 600)",
                path.display()
            )));
        }
    }

    let mut value = String::new();
    file.take(MAX_SECRET_FILE_SIZE + 1).read_to_string(&mut value)?;
    if value.len() as u64 > MAX_SECRET_FILE_SIZE {
        return Err(CliError::Message(format!(
            "Secret file is too large: {} (maximum {} bytes)",
            path.display(),
            MAX_SECRET_FILE_SIZE
        )));
    }
    Ok(value.trim_end_matches(['\\r', '\\n']).to_string())
}''',
)

replace_once(
    "fn create_sfx(temp_out: &Path, out_file: &Path) -> Result<(), CliError> {",
    "fn create_sfx(temp_out: &Path, out_file: &Path, force: bool) -> Result<(), CliError> {",
)

replace_once(
    '''    fs::copy(&stub_path, out_file)?;
    let mut out_f = fs::OpenOptions::new().append(true).open(out_file)?;
    let payload_bytes = fs::read(temp_out)?;
    out_f.write_all(&payload_bytes)?;
    out_f.write_all(&(payload_bytes.len() as u64).to_le_bytes())?;
    out_f.write_all(b"LVAUSFX1")?;
    fs::remove_file(temp_out)?;
    Ok(())''',
    '''    let parent = out_file.parent().unwrap_or_else(|| Path::new("."));
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    let mut stub = fs::File::open(&stub_path)?;
    if !stub.metadata()?.is_file() {
        return Err(CliError::Message(format!(
            "SFX stub is not a regular file: {}",
            stub_path.display()
        )));
    }

    io::copy(&mut stub, &mut output)?;
    let mut payload = fs::File::open(temp_out)?;
    let payload_len = payload.metadata()?.len();
    io::copy(&mut payload, &mut output)?;
    output.write_all(&payload_len.to_le_bytes())?;
    output.write_all(b"LVAUSFX1")?;
    output.as_file().sync_all()?;

    #[cfg(unix)]
    fs::set_permissions(output.path(), stub.metadata()?.permissions())?;

    #[cfg(windows)]
    if force && out_file.exists() {
        fs::remove_file(out_file)?;
    }

    if force {
        output
            .persist(out_file)
            .map_err(|error| CliError::Io(error.error))?;
    } else {
        output
            .persist_noclobber(out_file)
            .map_err(|error| CliError::Io(error.error))?;
    }

    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;

    fs::remove_file(temp_out)?;
    Ok(())''',
)

replace_once(
    "create_sfx(&temp_out, &out_file)?;",
    "create_sfx(&temp_out, &out_file, force)?;",
)

replace_once(
    '''mod tests {
    use super::read_secret_file;''',
    '''mod tests {
    use super::{read_secret_file, MAX_SECRET_FILE_SIZE};''',
)

replace_once(
    '''    #[test]
    #[cfg(unix)]
    fn password_file_must_not_be_group_or_world_accessible() {''',
    '''    #[test]
    fn oversized_secret_file_is_rejected_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized-secret.txt");
        std::fs::write(&path, vec![b'x'; MAX_SECRET_FILE_SIZE as usize + 1]).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let error = read_secret_file(&path).unwrap_err();
        assert!(error.to_string().contains("too large"));
    }

    #[test]
    #[cfg(unix)]
    fn password_file_must_not_be_group_or_world_accessible() {''',
)

PATH.write_text(text, encoding="utf-8")
