use crate::crypto::keys::{HybridPublicKey, HybridPublicKeyFormat};
use crate::crypto::CryptoError;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

const MAX_RECIPIENT_GROUP_FILE_SIZE: u64 = 1024 * 1024;

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
pub struct RecipientGroup {
    pub name: String,
    pub description: Option<String>,
    pub recipients: Vec<GroupRecipient>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupRecipient {
    pub name: String,
    pub key: HybridPublicKeyFormat,
}

impl RecipientGroup {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = read_recipient_group_file(path.as_ref())?;
        toml::from_str(&content).map_err(|e| format!("Failed to parse recipient group: {}", e))
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize recipient group: {}", e))?;
        fs::write(path, content).map_err(|e| format!("Failed to write recipient group file: {}", e))
    }

    pub fn extract_public_keys(&self) -> Result<Vec<HybridPublicKey>, CryptoError> {
        let mut keys = Vec::new();
        for rec in &self.recipients {
            keys.push(HybridPublicKey::from_format(&rec.key)?);
        }
        Ok(keys)
    }
}

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
