#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/lvau-cli/src/main.rs")
text = path.read_text(encoding="utf-8")


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one anchor, found {count}: {old[:80]!r}")
    text = text.replace(old, new, 1)


replace_once(
    "fn create_sfx(temp_out: &Path, out_file: &Path, force: bool) -> Result<(), CliError> {",
    '''fn copy_exact_len(
    input: &mut dyn Read,
    output: &mut dyn Write,
    expected_len: u64,
    label: &str,
) -> Result<(), CliError> {
    let copied = io::copy(input, output)?;
    if copied != expected_len {
        return Err(CliError::Message(format!(
            "{label} changed while being copied: expected {expected_len} bytes, copied {copied}"
        )));
    }
    Ok(())
}

fn create_sfx(temp_out: &Path, out_file: &Path, force: bool) -> Result<(), CliError> {''',
)

replace_once(
    '''    let payload_len = payload.metadata()?.len();
    io::copy(&mut payload, &mut output)?;
    output.write_all(&payload_len.to_le_bytes())?;''',
    '''    let payload_len = payload.metadata()?.len();
    copy_exact_len(&mut payload, &mut output, payload_len, "SFX payload")?;
    output.write_all(&payload_len.to_le_bytes())?;''',
)

replace_once(
    "    use super::{read_secret_file, MAX_SECRET_FILE_SIZE};",
    "    use super::{copy_exact_len, read_secret_file, MAX_SECRET_FILE_SIZE};\n    use std::io::Cursor;",
)

replace_once(
    '''    #[test]
    fn oversized_secret_file_is_rejected_before_reading() {''',
    '''    #[test]
    fn sfx_payload_copy_rejects_length_changes() {
        let mut source = Cursor::new(vec![0x5au8; 3]);
        let mut output = Vec::new();
        let error = copy_exact_len(&mut source, &mut output, 4, "SFX payload").unwrap_err();
        assert!(error.to_string().contains("changed while being copied"));
        assert_eq!(output.len(), 3);
    }

    #[test]
    fn oversized_secret_file_is_rejected_before_reading() {''',
)

path.write_text(text, encoding="utf-8")
