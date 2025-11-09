//! Kyber KEM encapsulation helpers and kem output utilities.

use anyhow::{Result, anyhow};
use pqcrypto_kyber::kyber768::*;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use zeroize::Zeroizing;

use crate::constants::{KYBER768_CT_BYTES, KYBER768_PK_BYTES};
use crate::hashlock::view_tag;

fn lp(len: usize) -> [u8; 4] {
    u32::try_from(len)
        .expect("length exceeds u32")
        .to_le_bytes()
}

/// Encapsulate a shared secret for a receiver using their Kyber768 public key.
///
/// Returns the shared secret bytes and the Kyber ciphertext.
/// The shared secret can be used to derive the one-time address and other
/// receiver-specific values.
pub fn encapsulate_for_receiver(
    receiver_pk: &[u8; KYBER768_PK_BYTES],
) -> Result<(Zeroizing<Vec<u8>>, [u8; KYBER768_CT_BYTES])> {
    let pk = PublicKey::from_bytes(receiver_pk)
        .map_err(|_| anyhow!("invalid Kyber768 public key"))?;

    let (shared_secret, ciphertext) = encapsulate(&pk);

    let mut ct_bytes = [0u8; KYBER768_CT_BYTES];
    ct_bytes.copy_from_slice(ciphertext.as_bytes());

    Ok((Zeroizing::new(shared_secret.as_bytes().to_vec()), ct_bytes))
}

/// Decapsulate a Kyber768 ciphertext using the receiver's secret key to recover the shared secret.
pub fn decapsulate_for_receiver(
    receiver_sk: &[u8; crate::constants::KYBER768_SK_BYTES],
    kyber_ct: &[u8; KYBER768_CT_BYTES],
) -> Result<Zeroizing<Vec<u8>>> {
    let sk = SecretKey::from_bytes(receiver_sk)
        .map_err(|_| anyhow!("invalid Kyber768 secret key"))?;
    let ct = Ciphertext::from_bytes(kyber_ct)
        .map_err(|_| anyhow!("invalid Kyber768 ciphertext"))?;
    let shared = decapsulate(&ct, &sk);
    Ok(Zeroizing::new(shared.as_bytes().to_vec()))
}

/// Recover the shared secret and its 1-byte view tag from a ciphertext using the receiver's SK.
pub fn recover_shared_and_view_tag(
    receiver_sk: &[u8; crate::constants::KYBER768_SK_BYTES],
    kyber_ct: &[u8; KYBER768_CT_BYTES],
) -> Result<(Zeroizing<Vec<u8>>, u8)> {
    let shared = decapsulate_for_receiver(receiver_sk, kyber_ct)?;
    let vt = view_tag(shared.as_slice());
    Ok((shared, vt))
}

/// Recover the shared secret and its 2-byte view tag from a ciphertext using the receiver's SK.
pub fn recover_shared_and_view_tag16(
    receiver_sk: &[u8; crate::constants::KYBER768_SK_BYTES],
    kyber_ct: &[u8; KYBER768_CT_BYTES],
) -> Result<(Zeroizing<Vec<u8>>, [u8; 2])> {
    let shared = decapsulate_for_receiver(receiver_sk, kyber_ct)?;
    let vt = crate::hashlock::view_tag16(shared.as_slice());
    Ok((shared, vt))
}

/// Derive a deterministic one-time public key from the shared secret and context.
///
/// This creates a 32-byte one-time address that can be used to identify
/// the receiver commitment without revealing the underlying Kyber keys.
pub fn derive_one_time_pk(
    shared_secret: &[u8],
    kyber_ct: &[u8],
    coin_id: &[u8; 32],
    chain_id: &[u8; 32],
) -> [u8; 32] {
    use blake3::Hasher;

    let mut h = Hasher::new();
    h.update(b"numilock.onetime_pk");
    h.update(&lp(shared_secret.len()));
    h.update(shared_secret);
    h.update(&lp(kyber_ct.len()));
    h.update(kyber_ct);
    h.update(&lp(coin_id.len()));
    h.update(coin_id);
    h.update(&lp(chain_id.len()));
    h.update(chain_id);
    *h.finalize().as_bytes()
}
