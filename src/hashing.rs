//! BLAKE3 helpers for deterministic hashing across the toolkit.

use blake3::Hasher;

/// Hash arbitrary data with a keyed BLAKE3 context specific to Numilock.
///
/// Using a domain separated key prevents collisions with unrelated BLAKE3 usage.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *Hasher::new_derive_key("numilock.v1")
        .update(data)
        .finalize()
        .as_bytes()
}
