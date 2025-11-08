//! Numilock: Kyber KEM + BLAKE3 hashlock toolkit.
//!
//! This crate extracts the stealth transfer building blocks from the Unchained
//! node so they can be reused by other products.  It bundles deterministic
//! one-time key derivation, receiver commitments, lock secret derivations and
//! reusable spend builders in a single place.

pub mod constants;
pub mod hashing;
pub mod hashlock;
pub mod spend;
pub mod stealth;

pub use constants::*;
pub use hashing::*;
pub use hashlock::*;
pub use spend::*;
pub use stealth::*;
