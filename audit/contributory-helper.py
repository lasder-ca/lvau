#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "crates/lvau-core/src/crypto/mod.rs"
text = TARGET.read_text(encoding="utf-8")


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one contributory-X25519 anchor, found {count}")
    text = text.replace(old, new, 1)


replace_once(
    """pub fn encrypt_file_keypairs(\n""",
    """fn derive_contributory_x25519(\n    secret: &StaticSecret,\n    public: &X25519PublicKey,\n) -> Result<x25519_dalek::SharedSecret, CryptoError> {\n    // Zero is explicitly non-contributory. The post-DH check also rejects the other\n    // low-order inputs that collapse the classical contribution of the hybrid suite.\n    if public.as_bytes().iter().all(|byte| *byte == 0) {\n        return Err(CryptoError::Validation(\n            \"Recipient X25519 public key is non-contributory\",\n        ));\n    }\n    let shared = secret.diffie_hellman(public);\n    if !shared.was_contributory() {\n        return Err(CryptoError::Validation(\n            \"Recipient X25519 public key is non-contributory\",\n        ));\n    }\n    Ok(shared)\n}\n\npub fn encrypt_file_keypairs(\n""",
)

replace_once(
    """        let ephem_x25519_pub = X25519PublicKey::from(&ephem_x25519_priv);\n        let x25519_ss = ephem_x25519_priv.diffie_hellman(&pubkey.x25519);\n        if !x25519_ss.was_contributory() {\n            return Err(CryptoError::Validation(\n                \"Recipient X25519 public key is non-contributory\",\n            ));\n        }\n\n        let (mlkem_ct, mlkem_ss) = pubkey.mlkem.encapsulate();\n""",
    """        let ephem_x25519_pub = X25519PublicKey::from(&ephem_x25519_priv);\n        let x25519_ss = derive_contributory_x25519(&ephem_x25519_priv, &pubkey.x25519)?;\n\n        let (mlkem_ct, mlkem_ss) = pubkey.mlkem.encapsulate();\n""",
)

replace_once(
    """        let ephem_pub = X25519PublicKey::from(*ephemeral_public_x25519);\n        let x25519_ss = priv_key.x25519.diffie_hellman(&ephem_pub);\n        if !x25519_ss.was_contributory() {\n            continue;\n        }\n        let mlkem_ct = match mlkem_ciphertext.as_slice().try_into() {\n""",
    """        let ephem_pub = X25519PublicKey::from(*ephemeral_public_x25519);\n        let x25519_ss = match derive_contributory_x25519(&priv_key.x25519, &ephem_pub) {\n            Ok(shared) => shared,\n            Err(_) => continue,\n        };\n        let mlkem_ct = match mlkem_ciphertext.as_slice().try_into() {\n""",
)

TARGET.write_text(text, encoding="utf-8")
