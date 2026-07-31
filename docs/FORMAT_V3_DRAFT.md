# Format v3 payload foundations

This document records the implemented first slice of the experimental format-v3
work tracked by issue #11. It is not a complete wire-format specification and
does not enable v3 capsule creation.

## Current status

Implemented in `lvau-core`:

- explicit suite identities for `LV3-XC20P` and
  `LV3-AESGCMSIV-XC20P`;
- suite- and purpose-separated HKDF-SHA256 subkeys;
- suite-, layer-, and chunk-separated nonce derivation;
- canonical chunk AAD binding the suite, layer, envelope commitment, chunk
  index, plaintext length, inner length, ciphertext length, and final marker;
- a bounded single-chunk `LV3-XC20P` encrypt/decrypt primitive;
- fixed key, nonce, and AAD vectors;
- negative tests for tampering, chunk-index changes, final-marker changes,
  length mismatches, and legacy-suite confusion.

Not implemented yet:

- a serialized v3 envelope and exact parser;
- a v3 file or bundle writer;
- streaming frame orchestration and total-length validation;
- CLI `--format v3` or `--suite` options;
- the AES-256-GCM-SIV inner cipher backend;
- v3 recipient slots, signatures, migration fixtures, fuzz targets, and
  benchmarks.

Format v2 remains the only writer format and its identifiers, key labels, nonce
rules, AAD, and ciphertext layout are unchanged.

## Suite identities

| Wire name | Layers | Per-chunk tag overhead | Status |
| --- | --- | ---: | --- |
| `LV3-XC20P` | XChaCha20-Poly1305 | 16 bytes | chunk primitive implemented; no capsule writer |
| `LV3-AESGCMSIV-XC20P` | AES-256-GCM-SIV inner, XChaCha20-Poly1305 outer | 32 bytes | registry, key domains, nonce domains, and AAD model only |

The layered suite does not use the existing format-v2 AES-GCM cascade and does
not include LCO. It must remain unavailable to writers until the AES-GCM-SIV
backend, layered authentication flow, vectors, tamper tests, and resource tests
are complete.

## Key schedule

Every v3 capsule will start from a random 256-bit file root key. Subkeys are
derived with HKDF-SHA256 using:

- salt/domain: `Lvau v3 key schedule\0`;
- info prefix: `Lvau v3 subkey\0`;
- the exact suite wire name;
- a zero delimiter; and
- one fixed purpose label.

Purpose labels currently reserve independent domains for the single payload
layer, layered inner and outer payload keys, recipient wrapping, envelope
commitment, bundle manifests, padding, and exporters. Existing format-v2 labels
are not reused or changed.

## Chunk nonce derivation

A random suite-appropriate base nonce is input to HKDF-SHA256 with the domain
`Lvau v3 nonce schedule\0`. The expansion info is:

```text
suite_code_u8 || layer_code_u8 || chunk_index_le_u64
```

This gives each suite, layer, and chunk its own nonce domain. The future
envelope parser must reject duplicate or malformed base nonces and chunk-index
overflow before payload processing.

## Chunk AAD

The canonical byte layout is:

```text
"Lvau v3 chunk AAD\0"
|| suite_code_u8
|| layer_code_u8
|| envelope_commitment_32
|| chunk_index_le_u64
|| plaintext_len_le_u32
|| inner_len_le_u32
|| ciphertext_len_le_u32
|| final_u8
```

`final_u8` is exactly `0` or `1`. The layered suite will use separate AAD for
its inner and outer operations while keeping the suite identity and lengths
committed at both layers.

## Promotion gates

Before a v3 writer is exposed:

1. define a bounded, exact serialized envelope and allocate version `3`;
2. implement sequential streaming first, including authenticated empty input,
   truncation rejection, trailing-byte rejection, and atomic output;
3. wire `LV3-XC20P` through file and bundle roundtrips;
4. add AES-256-GCM-SIV through a reviewed RustCrypto release and implement the
   layered suite without falling back to ordinary AES-GCM;
5. publish fixed vectors for both suites and every key/nonce/AAD domain;
6. add malformed-input, per-field tamper, cross-suite confusion, and fuzz tests;
7. document CPU, memory, and ciphertext-expansion costs;
8. add explicit experimental CLI flags while leaving v2 as the default writer;
9. preserve all supported v1/v2 reads and fixtures.

No suite should be described as stable, audited, or production-ready merely
because its chunk primitive exists.
