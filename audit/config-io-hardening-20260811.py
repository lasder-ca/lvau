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


for path, kind in [
    ("crates/lvau-core/src/groups.rs", "recipient group"),
    ("crates/lvau-core/src/policy.rs", "policy"),
]:
    replace_once(path, "use std::fs;\nuse std::path::Path;", "use std::fs::{self, File};\nuse std::io::Read;\nuse std::path::Path;")

# Group files.
replace_once(
    "crates/lvau-core/src/groups.rs",
    "#[derive(Debug, Serialize, Deserialize)]\npub struct RecipientGroup {",
    '''const MAX_RECIPIENT_GROUP_FILE_SIZE: u64 = 1024 * 1024;

fn read_recipient_group_file(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|e| format!("Failed to read recipient group file: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Failed to inspect recipient group file: {e}"))?;
    if !metadata.is_file() || metadata.len() > MAX_RECIPIENT_GROUP_FILE_SIZE {
        return Err("Recipient group file is invalid or too large".into());
    }

    let mut content = String::new();
    file.take(MAX_RECIPIENT_GROUP_FILE_SIZE + 1)
        .read_to_string(&mut content)
        .map_err(|e| format!("Failed to read recipient group file: {e}"))?;
    if content.len() as u64 > MAX_RECIPIENT_GROUP_FILE_SIZE {
        return Err("Recipient group file is invalid or too large".into());
    }
    Ok(content)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecipientGroup {''',
)
replace_once(
    "crates/lvau-core/src/groups.rs",
    '''        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read recipient group file: {}", e))?;''',
    '''        let content = read_recipient_group_file(path.as_ref())?;''',
)

groups = ROOT / "crates/lvau-core/src/groups.rs"
text = groups.read_text(encoding="utf-8")
if "oversized_recipient_group_is_rejected" not in text:
    text += r'''

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_recipient_group_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized.toml");
        fs::write(
            &path,
            vec![b'x'; MAX_RECIPIENT_GROUP_FILE_SIZE as usize + 1],
        )
        .unwrap();

        let error = RecipientGroup::load_from_file(&path).unwrap_err();
        assert!(error.contains("too large"));
    }
}
'''
    groups.write_text(text, encoding="utf-8")

# Policy files.
replace_once(
    "crates/lvau-core/src/policy.rs",
    "#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]\n#[serde(rename_all = \"snake_case\")]\npub enum MinKdfProfile {",
    '''const MAX_POLICY_FILE_SIZE: u64 = 1024 * 1024;

fn read_policy_file(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_POLICY_FILE_SIZE {
        return Err("Policy file is invalid or too large".into());
    }

    let mut content = String::new();
    file.take(MAX_POLICY_FILE_SIZE + 1)
        .read_to_string(&mut content)
        .map_err(|e| e.to_string())?;
    if content.len() as u64 > MAX_POLICY_FILE_SIZE {
        return Err("Policy file is invalid or too large".into());
    }
    Ok(content)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MinKdfProfile {''',
)
replace_once(
    "crates/lvau-core/src/policy.rs",
    '''        let content = fs::read_to_string(path).map_err(|e| e.to_string())?;''',
    '''        let content = read_policy_file(path.as_ref())?;''',
)

policy = ROOT / "crates/lvau-core/src/policy.rs"
text = policy.read_text(encoding="utf-8")
anchor = "    #[test]\n    fn approval_threshold_counts_distinct_fingerprints() {"
if "oversized_policy_is_rejected" not in text:
    addition = r'''    #[test]
    fn oversized_policy_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized-policy.toml");
        fs::write(&path, vec![b'x'; MAX_POLICY_FILE_SIZE as usize + 1]).unwrap();

        let error = CapsulePolicy::load_from_file(&path).unwrap_err();
        assert!(error.contains("too large"));
    }

'''
    if anchor not in text:
        raise SystemExit("policy test anchor not found")
    text = text.replace(anchor, addition + anchor, 1)
    policy.write_text(text, encoding="utf-8")
