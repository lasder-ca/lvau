//! Versioned cryptographic-suite metadata.
//!
//! The registry describes wire-format capabilities without selecting new
//! algorithms implicitly from broad security-profile names. Format v2 keeps its
//! historical identifiers and byte layout; future formats allocate separate
//! identifier types rather than extending an existing public enum.

pub mod v3;

use lvau_protocol::envelope::AlgorithmId;

/// Stable internal identifier for a format-v2 payload suite.
///
/// This enum intentionally remains unchanged so downstream exhaustive matches
/// written against Lvau 0.5 continue to compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuiteId {
    V2XChaCha20Poly1305,
    V2AesGcmXChaCha20Poly1305,
    V2AesGcmXChaCha20Poly1305Lco,
}

/// Capabilities and framing constraints for a format-v2 payload suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoSuite {
    pub id: SuiteId,
    pub format_version: u16,
    pub layer_count: u8,
    pub xchacha_nonce_len: usize,
    pub aes_nonce_len: Option<usize>,
    pub tag_overhead_per_chunk: usize,
    pub experimental: bool,
    pub includes_legacy_obfuscation: bool,
}

impl CryptoSuite {
    /// Resolve an existing v2 payload algorithm without changing its meaning.
    pub fn for_v2_algorithm(algorithm: &AlgorithmId) -> Option<Self> {
        match algorithm {
            AlgorithmId::XChaCha20Poly1305 => Some(Self {
                id: SuiteId::V2XChaCha20Poly1305,
                format_version: 2,
                layer_count: 1,
                xchacha_nonce_len: 24,
                aes_nonce_len: None,
                tag_overhead_per_chunk: 16,
                experimental: false,
                includes_legacy_obfuscation: false,
            }),
            AlgorithmId::CascadeAesGcmXChaCha => Some(Self {
                id: SuiteId::V2AesGcmXChaCha20Poly1305,
                format_version: 2,
                layer_count: 2,
                xchacha_nonce_len: 24,
                aes_nonce_len: Some(12),
                tag_overhead_per_chunk: 32,
                experimental: true,
                includes_legacy_obfuscation: false,
            }),
            AlgorithmId::TripleCascadeAesXChaChaLco => Some(Self {
                id: SuiteId::V2AesGcmXChaCha20Poly1305Lco,
                format_version: 2,
                // LCO is reversible obfuscation, not an encryption layer.
                layer_count: 2,
                xchacha_nonce_len: 24,
                aes_nonce_len: Some(12),
                tag_overhead_per_chunk: 32,
                experimental: true,
                includes_legacy_obfuscation: true,
            }),
            _ => None,
        }
    }
}

/// Experimental format-v3 payload-suite identifier.
///
/// This is a separate type so adding v3 suites cannot break exhaustive matches
/// over the stable format-v2 [`SuiteId`] enum. It is non-exhaustive from its
/// first release because the v3 registry is expected to grow.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum V3SuiteId {
    XChaCha20Poly1305,
    Aes256GcmSivXChaCha20Poly1305,
}

/// Capabilities and framing constraints for an experimental v3 payload suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3CryptoSuite {
    pub id: V3SuiteId,
    pub format_version: u16,
    pub layer_count: u8,
    pub xchacha_nonce_len: usize,
    pub aes_nonce_len: Option<usize>,
    pub tag_overhead_per_chunk: usize,
    pub experimental: bool,
}

impl V3CryptoSuite {
    /// Resolve an experimental format-v3 payload suite.
    ///
    /// This metadata does not make v3 writable. The envelope parser, writer,
    /// and CLI opt-in remain separate promotion gates.
    pub const fn for_suite(id: V3SuiteId) -> Self {
        match id {
            V3SuiteId::XChaCha20Poly1305 => Self {
                id,
                format_version: 3,
                layer_count: 1,
                xchacha_nonce_len: 24,
                aes_nonce_len: None,
                tag_overhead_per_chunk: 16,
                experimental: true,
            },
            V3SuiteId::Aes256GcmSivXChaCha20Poly1305 => Self {
                id,
                format_version: 3,
                layer_count: 2,
                xchacha_nonce_len: 24,
                aes_nonce_len: Some(12),
                tag_overhead_per_chunk: 32,
                experimental: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_lco_is_not_counted_as_a_cipher_layer() {
        let suite = CryptoSuite::for_v2_algorithm(&AlgorithmId::TripleCascadeAesXChaChaLco)
            .expect("registered v2 suite");
        assert_eq!(suite.layer_count, 2);
        assert!(suite.includes_legacy_obfuscation);
    }

    #[test]
    fn recipient_and_signature_ids_are_not_payload_suites() {
        assert!(CryptoSuite::for_v2_algorithm(&AlgorithmId::X25519MlkemHybrid).is_none());
        assert!(CryptoSuite::for_v2_algorithm(&AlgorithmId::Ed25519).is_none());
    }

    #[test]
    fn v3_suites_are_explicit_and_do_not_include_lco() {
        let single = V3CryptoSuite::for_suite(V3SuiteId::XChaCha20Poly1305);
        assert_eq!(single.format_version, 3);
        assert_eq!(single.layer_count, 1);
        assert_eq!(single.tag_overhead_per_chunk, 16);
        assert!(single.experimental);

        let layered =
            V3CryptoSuite::for_suite(V3SuiteId::Aes256GcmSivXChaCha20Poly1305);
        assert_eq!(layered.layer_count, 2);
        assert_eq!(layered.tag_overhead_per_chunk, 32);
        assert_eq!(layered.aes_nonce_len, Some(12));
    }

    #[test]
    fn v2_registry_remains_the_original_three_variant_type() {
        let suites = [
            SuiteId::V2XChaCha20Poly1305,
            SuiteId::V2AesGcmXChaCha20Poly1305,
            SuiteId::V2AesGcmXChaCha20Poly1305Lco,
        ];
        assert_eq!(suites.len(), 3);
    }
}
