//! BLAKE3 helpers for deterministic hashing across the toolkit.

use blake3::Hasher;

/// Domain-separated hash for Numilock protocol usage.
///
/// This uses BLAKE3 derive_key with the fixed context string "numilock".
/// It intentionally differs from raw/unkeyed BLAKE3 to prevent cross-protocol collisions.
pub fn numihash(data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new_derive_key("numilock");
    h.update(data);
    *h.finalize().as_bytes()
}

/// Deprecated: use `numihash`. This was never raw BLAKE3; it is a domain-separated variant.
#[deprecated(note = "use numihash() which is domain-separated via derive_key(\"numilock\")")]
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    numihash(data)
}
