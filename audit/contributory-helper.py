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
    """fn derive_contributory_x25519(\n    secret: &StaticSecret,\n    public: &X25519PublicKey,\n) -> Result<Zeroizing<[u8; 32]>, CryptoError> {\n    // Zero is explicitly non-contributory and rejecting it before scalar multiplication also\n    // documents the hybrid suite's requirement that both classical and ML-KEM inputs contribute.\n    if public.as_bytes().iter().all(|byte| *byte == 0) {\n        return Err(CryptoError::Validation(\n            \"Recipient X25519 public key is non-contributory\",\n        ));\n    }\n    let shared = secret.diffie_hellman(public);\n    if !shared.was_contributory() {\n        return Err(CryptoError::Validation(\n            \"Recipient X25519 public key is non-contributory\",\n        ));\n    }\n    Ok(Zeroizing::new(*shared.as_bytes()))\n}\n\npub fn encrypt_file_keypairs(\n""",
)

replace_once(
    """        let ephem_x25519_pub = X25519PublicKey::from(&ephem_x25519_priv);\n        let x25519_ss = ephem_x25519_priv.diffie_hellman(&pubkey.x25519);\n        if !x25519_ss.was_contributory() {\n            return Err(CryptoError::Validation(\n                \"Recipient X25519 public key is non-contributory\",\n            ));\n        }\n\n        let (mlkem_ct, mlkem_ss) = pubkey.mlkem.encapsulate();\n\n        let mut combined_ss = Zeroizing::new(Vec::new());\n        combined_ss.extend_from_slice(x25519_ss.as_bytes());\n""",
    """        let ephem_x25519_pub = X25519PublicKey::from(&ephem_x25519_priv);\n        let x25519_ss = derive_contributory_x25519(&ephem_x25519_priv, &pubkey.x25519)?;\n\n        let (mlkem_ct, mlkem_ss) = pubkey.mlkem.encapsulate();\n\n        let mut combined_ss = Zeroizing::new(Vec::new());\n        combined_ss.extend_from_slice(&*x25519_ss);\n""",
)

replace_once(
    """        let ephem_pub = X25519PublicKey::from(*ephemeral_public_x25519);\n        let x25519_ss = priv_key.x25519.diffie_hellman(&ephem_pub);\n        if !x25519_ss.was_contributory() {\n            continue;\n        }\n        let mlkem_ct = match mlkem_ciphertext.as_slice().try_into() {\n""",
    """        let ephem_pub = X25519PublicKey::from(*ephemeral_public_x25519);\n        let x25519_ss = match derive_contributory_x25519(&priv_key.x25519, &ephem_pub) {\n            Ok(shared) => shared,\n            Err(_) => continue,\n        };\n        let mlkem_ct = match mlkem_ciphertext.as_slice().try_into() {\n""",
)
replace_once(
    """        let mut combined_ss = Zeroizing::new(Vec::new());\n        combined_ss.extend_from_slice(x25519_ss.as_bytes());\n        combined_ss.extend_from_slice(mlkem_ss.as_slice());\n\n        let kw_hk = Hkdf::<Sha256>::new(None, &combined_ss);\n""",
    """        let mut combined_ss = Zeroizing::new(Vec::new());\n        combined_ss.extend_from_slice(&*x25519_ss);\n        combined_ss.extend_from_slice(mlkem_ss.as_slice());\n\n        let kw_hk = Hkdf::<Sha256>::new(None, &combined_ss);\n""",
)

TARGET.write_text(text, encoding="utf-8")
