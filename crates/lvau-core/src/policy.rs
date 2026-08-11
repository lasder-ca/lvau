use lvau_protocol::envelope::{AlgorithmId, Envelope, KdfParams, SecurityProfile};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

const MAX_POLICY_FILE_SIZE: u64 = 1024 * 1024;

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
pub enum MinKdfProfile {
    Interactive,
    Moderate,
    Strong,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MetadataProfilePolicy {
    Minimal,
    Balanced,
    Verbose,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaddingPolicy {
    None,
    Bucket,
    Fixed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsulePolicy {
    #[serde(default)]
    pub require_signature: bool,
    #[serde(default)]
    pub require_recovery: bool,
    pub min_kdf_profile: Option<MinKdfProfile>,
    pub allowed_ciphers: Option<Vec<String>>,
    pub allowed_kdfs: Option<Vec<String>>,
    #[serde(default = "default_true")]
    pub allow_lco: bool,
    #[serde(default = "default_true")]
    pub allow_experimental: bool,
    pub require_metadata_profile: Option<MetadataProfilePolicy>,
    pub require_padding: Option<PaddingPolicy>,
    #[serde(default)]
    pub require_recipient_count_min: u32,
    #[serde(default)]
    pub require_approval_signatures_min: u32,
    #[serde(default = "default_true")]
    pub public_label_allowed: bool,
    #[serde(default)]
    pub created_by_required: bool,
}

fn default_true() -> bool {
    true
}

impl Default for CapsulePolicy {
    fn default() -> Self {
        Self {
            require_signature: false,
            require_recovery: false,
            min_kdf_profile: None,
            allowed_ciphers: None,
            allowed_kdfs: None,
            allow_lco: true,
            allow_experimental: true,
            require_metadata_profile: None,
            require_padding: None,
            require_recipient_count_min: 0,
            require_approval_signatures_min: 0,
            public_label_allowed: true,
            created_by_required: false,
        }
    }
}

impl CapsulePolicy {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let content = read_policy_file(path.as_ref())?;
        toml::from_str(&content).map_err(|e| e.to_string())
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let content = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, content).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct PolicyViolation {
    pub rule: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PolicyWarning {
    pub rule: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub violations: Vec<PolicyViolation>,
    pub warnings: Vec<PolicyWarning>,
}

impl Default for PolicyResult {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyResult {
    pub fn new() -> Self {
        Self {
            violations: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Lints an envelope against a capsule policy, returning any violations or warnings.
pub fn lint_envelope(envelope: &Envelope, policy: &CapsulePolicy) -> PolicyResult {
    let mut result = PolicyResult::new();

    // 1. Signature requirement
    if policy.require_signature && envelope.signature.is_none() {
        result.violations.push(PolicyViolation {
            rule: "require_signature".into(),
            message: "Policy requires a signature, but none was found.".into(),
        });
    } else if policy.require_signature {
        result.warnings.push(PolicyWarning {
            rule: "require_signature".into(),
            message: "A signature is present, but envelope linting cannot verify it; run verify-signature with a trusted key.".into(),
        });
    }

    // 2. Recovery requirement
    if policy.require_recovery && envelope.recovery_metadata.is_none() {
        result.violations.push(PolicyViolation {
            rule: "require_recovery".into(),
            message: "Policy requires recovery metadata, but none was found.".into(),
        });
    } else if policy.require_recovery {
        result.warnings.push(PolicyWarning {
            rule: "require_recovery".into(),
            message: "Recovery metadata is present, but envelope linting cannot verify that its referenced shares are available or trusted.".into(),
        });
    }

    // 3. Min KDF Profile
    if let Some(ref min_kdf) = policy.min_kdf_profile {
        if let Some(KdfParams::Argon2id {
            m_cost,
            t_cost,
            p_cost,
            ..
        }) = &envelope.header.kdf
        {
            let is_interactive = *m_cost >= 65536 && *t_cost >= 2 && *p_cost >= 1;
            let is_moderate = *m_cost >= 262144 && *t_cost >= 3 && *p_cost >= 2;
            let is_strong = *m_cost >= 1048576 && *t_cost >= 4 && *p_cost >= 4;

            let actual_profile = if is_strong {
                MinKdfProfile::Strong
            } else if is_moderate {
                MinKdfProfile::Moderate
            } else {
                MinKdfProfile::Interactive
            };

            let fails = match min_kdf {
                MinKdfProfile::Strong => actual_profile != MinKdfProfile::Strong,
                MinKdfProfile::Moderate => actual_profile == MinKdfProfile::Interactive,
                MinKdfProfile::Interactive => !is_interactive,
            };

            if fails {
                result.violations.push(PolicyViolation {
                    rule: "min_kdf_profile".into(),
                    message: format!(
                        "Policy requires KDF profile {:?}, but the artifact's KDF is weaker.",
                        min_kdf
                    ),
                });
            }
        }
    }

    // 4. Allowed Ciphers
    if let Some(ref allowed_ciphers) = policy.allowed_ciphers {
        let alg_str = match envelope.header.algorithm {
            AlgorithmId::XChaCha20Poly1305 => "XChaCha20Poly1305",
            AlgorithmId::CascadeAesGcmXChaCha => "CascadeAesGcmXChaCha",
            AlgorithmId::TripleCascadeAesXChaChaLco => "TripleCascadeAesXChaChaLco",
            AlgorithmId::X25519 => "X25519",
            AlgorithmId::Ed25519 => "Ed25519",
            AlgorithmId::X25519MlkemHybrid => "X25519MlkemHybrid",
            AlgorithmId::Ed25519MldsaHybrid => "Ed25519MldsaHybrid",
        };

        let allowed = allowed_ciphers
            .iter()
            .any(|c| c.eq_ignore_ascii_case(alg_str));
        if !allowed {
            result.violations.push(PolicyViolation {
                rule: "allowed_ciphers".into(),
                message: format!("Algorithm {} is not in the allowed ciphers list.", alg_str),
            });
        }
    }

    // 5. Allowed KDFs
    if let Some(ref allowed_kdfs) = policy.allowed_kdfs {
        let kdf_str = match envelope.header.kdf {
            Some(KdfParams::Argon2id { .. }) => "Argon2id",
            None => "None",
        };

        let allowed = allowed_kdfs.iter().any(|k| k.eq_ignore_ascii_case(kdf_str));
        if !allowed {
            result.violations.push(PolicyViolation {
                rule: "allowed_kdfs".into(),
                message: format!("KDF {} is not in the allowed KDFs list.", kdf_str),
            });
        }
    }

    // 6. Allow LCO
    if !policy.allow_lco && envelope.header.algorithm == AlgorithmId::TripleCascadeAesXChaChaLco {
        result.violations.push(PolicyViolation {
            rule: "allow_lco".into(),
            message: "LCO obfuscation is disallowed by policy.".into(),
        });
    }

    // 7. Allow Experimental
    let has_experimental_recipient = envelope.header.recipients.iter().any(|recipient| {
        matches!(
            recipient,
            lvau_protocol::envelope::Recipient::X25519MlkemHybrid { .. }
        )
    });
    if !policy.allow_experimental
        && (envelope.header.profile == SecurityProfile::Extreme
            || envelope.header.profile == SecurityProfile::Paranoid
            || has_experimental_recipient)
    {
        result.violations.push(PolicyViolation {
            rule: "allow_experimental".into(),
            message: "Experimental profiles or hybrid recipients are disallowed by policy.".into(),
        });
    }

    // These bundle properties live inside the encrypted payload in the
    // current format, so public-envelope linting cannot prove them. Refuse to
    // silently accept a configured rule that was not evaluated.
    if policy.require_metadata_profile.is_some() {
        result.violations.push(PolicyViolation {
            rule: "require_metadata_profile".into(),
            message: "The metadata profile is encrypted and cannot be verified by public-envelope policy linting.".into(),
        });
    }
    if policy.require_padding.is_some() {
        result.violations.push(PolicyViolation {
            rule: "require_padding".into(),
            message: "The padding profile is not authenticated as a public envelope field and cannot be verified by policy linting.".into(),
        });
    }

    // 8. Public label allowed
    if !policy.public_label_allowed && envelope.public_label.is_some() {
        result.violations.push(PolicyViolation {
            rule: "public_label_allowed".into(),
            message: "Public labels are disallowed by policy.".into(),
        });
    }

    // 9. Created by required
    if policy.created_by_required
        && (envelope.release_metadata.is_none()
            || envelope
                .release_metadata
                .as_ref()
                .unwrap()
                .project_name
                .is_none())
    {
        // "created_by" is effectively project_name or similar. We check release_metadata.
        result.violations.push(PolicyViolation {
            rule: "created_by_required".into(),
            message: "Policy requires author/project metadata, but none was found.".into(),
        });
    } else if policy.created_by_required {
        result.warnings.push(PolicyWarning {
            rule: "created_by_required".into(),
            message: "Author/project metadata is present but is not an identity claim unless covered by a signature from a trusted key.".into(),
        });
    }

    // 10. Recipient count
    let count = envelope.header.recipients.len() as u32;
    if count < policy.require_recipient_count_min {
        result.violations.push(PolicyViolation {
            rule: "require_recipient_count_min".into(),
            message: format!(
                "Policy requires at least {} recipients, but found {}.",
                policy.require_recipient_count_min, count
            ),
        });
    }

    // 11. Approval signatures
    let approvals_count = envelope
        .approvals
        .iter()
        .map(|approval| approval.signer_fingerprint)
        .collect::<HashSet<_>>()
        .len() as u32;
    if approvals_count < policy.require_approval_signatures_min {
        result.violations.push(PolicyViolation {
            rule: "require_approval_signatures_min".into(),
            message: format!(
                "Policy requires at least {} distinct approval fingerprints, but found {}.",
                policy.require_approval_signatures_min, approvals_count
            ),
        });
    } else if policy.require_approval_signatures_min > 0 {
        result.warnings.push(PolicyWarning {
            rule: "require_approval_signatures_min".into(),
            message: "The required number of approval records is present, but policy linting cannot establish signer trust; verify each approval with trusted keys.".into(),
        });
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use lvau_protocol::envelope::{
        ApprovalSignature, ContentType, EnvelopeHeader, Recipient, CURRENT_VERSION, MAGIC_REAL,
    };

    fn envelope() -> Envelope {
        Envelope {
            header: EnvelopeHeader {
                magic: MAGIC_REAL,
                version: CURRENT_VERSION,
                profile: SecurityProfile::Balanced,
                algorithm: AlgorithmId::XChaCha20Poly1305,
                kdf: Some(KdfParams::Argon2id {
                    m_cost: 65_536,
                    t_cost: 2,
                    p_cost: 1,
                    salt: [1; 16],
                }),
                recipients: vec![Recipient::Password {
                    nonce: [2; 24],
                    encrypted_file_key: vec![3; 48],
                }],
            },
            plaintext_len: 0,
            nonce: [4; 24],
            secondary_nonce: None,
            aad_hash: [5; 32],
            metadata: vec![],
            content_type: Some(ContentType::SingleFile),
            signature: None,
            public_label: None,
            approvals: vec![],
            release_metadata: None,
            policy_overridden: false,
            recovery_metadata: None,
        }
    }

    #[test]
    fn oversized_policy_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized-policy.toml");
        fs::write(&path, vec![b'x'; MAX_POLICY_FILE_SIZE as usize + 1]).unwrap();

        let error = CapsulePolicy::load_from_file(&path).unwrap_err();
        assert!(error.contains("too large"));
    }

    #[test]
    fn approval_threshold_counts_distinct_fingerprints() {
        let mut envelope = envelope();
        let approval = ApprovalSignature {
            signer_fingerprint: [9; 32],
            signature: vec![0; 64],
            comment: None,
        };
        envelope.approvals = vec![approval.clone(), approval];
        let policy = CapsulePolicy {
            require_approval_signatures_min: 2,
            ..CapsulePolicy::default()
        };

        let result = lint_envelope(&envelope, &policy);

        assert!(result
            .violations
            .iter()
            .any(|violation| violation.rule == "require_approval_signatures_min"));
    }

    #[test]
    fn experimental_hybrid_recipient_is_rejected_when_disallowed() {
        let mut envelope = envelope();
        envelope.header.kdf = None;
        envelope.header.recipients = vec![Recipient::X25519MlkemHybrid {
            ephemeral_public_x25519: [7; 32],
            mlkem_ciphertext: vec![8; 32],
            encrypted_file_key: vec![9; 48],
        }];
        let policy = CapsulePolicy {
            allow_experimental: false,
            ..CapsulePolicy::default()
        };

        let result = lint_envelope(&envelope, &policy);

        assert!(result
            .violations
            .iter()
            .any(|violation| violation.rule == "allow_experimental"));
    }

    #[test]
    fn unsupported_public_checks_do_not_silently_pass() {
        let policy = CapsulePolicy {
            require_metadata_profile: Some(MetadataProfilePolicy::Minimal),
            require_padding: Some(PaddingPolicy::Bucket),
            ..CapsulePolicy::default()
        };

        let result = lint_envelope(&envelope(), &policy);

        assert!(result
            .violations
            .iter()
            .any(|violation| violation.rule == "require_metadata_profile"));
        assert!(result
            .violations
            .iter()
            .any(|violation| violation.rule == "require_padding"));
    }
}
