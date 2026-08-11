#!/usr/bin/env python3
from pathlib import Path


def patch(path: str, replacements: list[tuple[str, str]]) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    for old, new in replacements:
        count = text.count(old)
        if count != 1:
            raise SystemExit(f"{path}: expected one anchor, found {count}: {old[:80]!r}")
        text = text.replace(old, new, 1)
    p.write_text(text, encoding="utf-8")


patch(
    "crates/lvau-core/src/groups.rs",
    [
        (
            '''        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize recipient group: {}", e))?;
        fs::write(path, content).map_err(|e| format!("Failed to write recipient group file: {}", e))''',
            '''        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize recipient group: {}", e))?;
        if content.len() as u64 > MAX_RECIPIENT_GROUP_FILE_SIZE {
            return Err("Recipient group file is too large".into());
        }
        fs::write(path, content).map_err(|e| format!("Failed to write recipient group file: {}", e))''',
        ),
        (
            '''    #[test]
    fn oversized_recipient_group_is_rejected() {''',
            '''    #[test]
    fn oversized_recipient_group_is_rejected_before_saving() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("group.toml");
        fs::write(&path, "preserve-me").unwrap();
        let group = RecipientGroup {
            name: "x".repeat(MAX_RECIPIENT_GROUP_FILE_SIZE as usize),
            description: None,
            recipients: Vec::new(),
        };

        let error = group.save_to_file(&path).unwrap_err();
        assert!(error.contains("too large"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "preserve-me");
    }

    #[test]
    fn oversized_recipient_group_is_rejected() {''',
        ),
    ],
)

patch(
    "crates/lvau-core/src/policy.rs",
    [
        (
            '''        let content = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, content).map_err(|e| e.to_string())''',
            '''        let content = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        if content.len() as u64 > MAX_POLICY_FILE_SIZE {
            return Err("Policy file is too large".into());
        }
        fs::write(path, content).map_err(|e| e.to_string())''',
        ),
        (
            '''    #[test]
    fn oversized_policy_is_rejected() {''',
            '''    #[test]
    fn oversized_policy_is_rejected_before_saving() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        fs::write(&path, "preserve-me").unwrap();
        let policy = CapsulePolicy {
            allowed_ciphers: Some(vec!["x".repeat(MAX_POLICY_FILE_SIZE as usize)]),
            ..CapsulePolicy::default()
        };

        let error = policy.save_to_file(&path).unwrap_err();
        assert!(error.contains("too large"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "preserve-me");
    }

    #[test]
    fn oversized_policy_is_rejected() {''',
        ),
    ],
)
