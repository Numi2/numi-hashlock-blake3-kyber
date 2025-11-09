//! Fundamental size definitions and shared aliases for the Numilock toolkit.

/// Kyber768 ciphertext length in bytes.
pub const KYBER768_CT_BYTES: usize =
    pqcrypto_kyber::ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
/// Kyber768 public key length in bytes.
pub const KYBER768_PK_BYTES: usize =
    pqcrypto_kyber::ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES;
/// Kyber768 secret key length in bytes.
pub const KYBER768_SK_BYTES: usize =
    pqcrypto_kyber::ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES;

/// Size of the deterministic one-time public key bytes used in hashlock transfers.
///
/// The bytes are opaque and represent the commitment-facing address for the receiver.
pub const OTP_PK_BYTES: usize = 32;

/// Standard 32-byte address type derived from BLAKE3 hashes.
pub type Address = [u8; 32];

/// Domain separation constants used across the crate.
pub const DST_H: &str    = "numilock/hash";
pub const DST_PRF: &str  = "numilock/ratchet.prf";
pub const DST_INV: &str  = "numilock/invoice";
pub const DST_BIND: &str = "numilock/bind";
