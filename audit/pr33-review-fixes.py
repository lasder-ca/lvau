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


replace_once(
    "crates/lvau-core/src/recovery.rs",
    """    pub fn to_file(&self, path: &Path) -> Result<(), CryptoError> {\n        self.to_file_with_force(path, false)\n    }\n""",
    """    pub fn to_file(&self, path: &Path) -> Result<(), CryptoError> {\n        // Preserve the public API's historical overwrite behavior. Callers that\n        // require no-clobber semantics must opt into it explicitly below.\n        self.to_file_with_force(path, true)\n    }\n""",
)

replace_once(
    "crates/lvau-core/src/recovery.rs",
    """    #[test]\n    fn recovery_share_refuses_to_clobber_existing_file() {\n        let dir = tempfile::tempdir().unwrap();\n        let path = dir.path().join(\"secret.lvau-share\");\n        fs::write(&path, b\"keep me\").unwrap();\n        let share = split_secret(b\"secret\", 2, 2).unwrap().remove(0);\n\n        assert!(matches!(\n            share.to_file(&path),\n            Err(CryptoError::OutputExists)\n        ));\n        assert_eq!(fs::read(path).unwrap(), b\"keep me\");\n    }\n""",
    """    #[test]\n    fn recovery_share_to_file_preserves_overwrite_behavior() {\n        let dir = tempfile::tempdir().unwrap();\n        let path = dir.path().join(\"secret.lvau-share\");\n        let mut shares = split_secret(b\"secret\", 2, 2).unwrap();\n        let first = shares.remove(0);\n        let replacement = shares.remove(0);\n\n        first.to_file(&path).unwrap();\n        replacement.to_file(&path).unwrap();\n\n        let loaded = RecoveryShare::from_file(&path).unwrap();\n        assert_eq!(loaded.index, replacement.index);\n        assert_eq!(loaded.share_data, replacement.share_data);\n    }\n\n    #[test]\n    fn recovery_share_explicit_no_clobber_preserves_existing_file() {\n        let dir = tempfile::tempdir().unwrap();\n        let path = dir.path().join(\"secret.lvau-share\");\n        fs::write(&path, b\"keep me\").unwrap();\n        let share = split_secret(b\"secret\", 2, 2).unwrap().remove(0);\n\n        assert!(matches!(\n            share.to_file_with_force(&path, false),\n            Err(CryptoError::OutputExists)\n        ));\n        assert_eq!(fs::read(path).unwrap(), b\"keep me\");\n    }\n""",
)

replace_once(
    "crates/lvau-cli/src/main.rs",
    """                    share.to_file(&share_path).map_err(|e| {\n                        CliError::Message(format!(\"Failed to write share: {:?}\", e))\n                    })?;\n""",
    """                    share.to_file_with_force(&share_path, false).map_err(|e| {\n                        CliError::Message(format!(\"Failed to write share: {:?}\", e))\n                    })?;\n""",
)

replace_once(
    "crates/lvau-stub/src/main.rs",
    """                if let (Some(payload), Some(out_file)) =\n                    (self.payload.clone(), self.out_file.clone())\n                {\n                    match self.decrypt(&payload) {\n""",
    """                if let Some(out_file) = self.out_file.clone() {\n                    if let Some(payload) = self.payload.take() {\n                        let decrypt_result = self.decrypt(&payload);\n                        self.payload = Some(payload);\n                        match decrypt_result {\n""",
)

replace_once(
    "crates/lvau-stub/src/main.rs",
    """                        Err(_) => {\n                            self.status =\n                                \"Decryption Failed! Wrong password or corrupted file.\".to_string();\n                        }\n                    }\n                }\n            }\n""",
    """                            Err(_) => {\n                                self.status =\n                                    \"Decryption Failed! Wrong password or corrupted file.\".to_string();\n                            }\n                        }\n                    }\n                }\n            }\n""",
)
