//! Receiver-driven hashlock ratchet wallet primitives.
//!
//! This module implements the R-HTLC construction described in the Numilock
//! receiver-ratcheted hashlock specification.  Wallets hold a private 32-byte
//! ratchet key and automatically derive the next secret and lock hash whenever
//! an incoming payment is claimed.

use std::fmt;

use anyhow::{Result, anyhow};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::Zeroize;
use subtle::ConstantTimeEq;

use crate::constants::{DST_H, DST_INV};

/// 4-byte little-endian length prefix helper.
fn lp(len: usize) -> [u8; 4] {
    (len as u32).to_le_bytes()
}

/// BLAKE3 derive_key helper that enforces 32-byte output.
fn derive32(domain: &str, input: &[u8]) -> [u8; 32] {
    blake3::derive_key(domain, input)
}

/// H(x) = BLAKE3.derive_key(DST_H, x)[:32]
fn hash_h(input: &[u8]) -> [u8; 32] {
    derive32(DST_H, input)
}

/// Compute the invoice hash H(L(DST_INV) || DST_INV || S).
fn invoice_hash_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(4 + DST_INV.len() + secret.len());
    encoded.extend_from_slice(&lp(DST_INV.as_bytes().len()));
    encoded.extend_from_slice(DST_INV.as_bytes());
    encoded.extend_from_slice(secret);
    hash_h(&encoded)
}

/// Bind the per-claim context `(chain_id, coin_id, note_presence, note)`.
fn binding_value(chain_id: &[u8; 32], coin_id: &[u8; 32], note: Option<&[u8]>) -> [u8; 32] {
    crate::bind_context(chain_id.as_slice(), coin_id.as_slice(), note)
}

/// Wallet-owned invoice consisting of the invoice hash and its private preimage.
pub struct Invoice {
    secret: [u8; 32],
    lock_hash: [u8; 32],
}

impl Invoice {
    /// Create an invoice from a caller-provided secret.
    pub fn from_secret(secret: [u8; 32]) -> Self {
        let lock_hash = invoice_hash_from_secret(&secret);
        Self { secret, lock_hash }
    }

    /// Return the 32-byte invoice hash that should be shared with the sender.
    pub fn lock_hash(&self) -> [u8; 32] {
        self.lock_hash
    }

    /// Access the private secret S associated with this invoice.
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Consume the invoice, returning the secret S.
    pub fn into_secret(mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.secret);
        self.secret.zeroize();
        out
    }
}

impl Clone for Invoice {
    fn clone(&self) -> Self {
        Self::from_secret(*self.secret())
    }
}

impl fmt::Debug for Invoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invoice")
            .field("lock_hash", &self.lock_hash)
            .finish()
    }
}

impl Drop for Invoice {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Output of a ratchet step.
pub struct RatchetStep {
    next_invoice: Invoice,
    binding: [u8; 32],
}

impl RatchetStep {
    /// Access the derived invoice that should be forwarded to the next hop.
    pub fn next_invoice(&self) -> &Invoice {
        &self.next_invoice
    }

    /// Retrieve the derived invoice, consuming the ratchet step.
    pub fn into_invoice(self) -> Invoice {
        self.next_invoice
    }

    /// Access the binding value used inside the PRF derivation.
    pub fn binding(&self) -> &[u8; 32] {
        &self.binding
    }
}

impl fmt::Debug for RatchetStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RatchetStep")
            .field("next_lock_hash", &self.next_invoice.lock_hash())
            .finish()
    }
}

/// Receiver wallet holding the ratchet key.
pub struct RatchetWallet {
    ratchet_key: [u8; 32],
}

impl RatchetWallet {
    /// Instantiate a wallet with the provided 32-byte ratchet key.
    pub fn new(ratchet_key: [u8; 32]) -> Self {
        Self { ratchet_key }
    }

    /// Generate a wallet with a fresh random ratchet key from the OS RNG.
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self::new(key)
    }

    /// Export the ratchet key for secure backup.
    pub fn ratchet_key(&self) -> &[u8; 32] {
        &self.ratchet_key
    }

    /// Issue a new invoice with a freshly sampled 32-byte secret.
    pub fn issue_invoice(&self) -> Invoice {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Invoice::from_secret(secret)
    }

    /// Derive the next secret and lock hash immediately after revealing `current_secret`.
    ///
    /// `chain_id` and `coin_id` identify the spent output. `note` binds any optional
    /// receiver metadata into the derivation. Returns the new invoice that should be
    /// forwarded to the next hop along with the binding value used inside the PRF.
    pub fn ratchet_forward(
        &self,
        current_secret: &[u8; 32],
        chain_id: &[u8; 32],
        coin_id: &[u8; 32],
        note: Option<&[u8]>,
    ) -> RatchetStep {
        let binding = binding_value(chain_id, coin_id, note);

        let next_secret = crate::derive_next_secret(
            self.ratchet_key(),
            current_secret,
            chain_id.as_slice(),
            coin_id.as_slice(),
            note,
        );
        let next_invoice = Invoice::from_secret(next_secret);

        RatchetStep {
            next_invoice,
            binding,
        }
    }

    /// Convenience wrapper that ratchets and returns the new invoice hash directly.
    pub fn ratchet_forward_lockhash(
        &self,
        current_secret: &[u8; 32],
        chain_id: &[u8; 32],
        coin_id: &[u8; 32],
        note: Option<&[u8]>,
    ) -> [u8; 32] {
        self.ratchet_forward(current_secret, chain_id, coin_id, note)
            .next_invoice()
            .lock_hash()
    }

    /// Rebuild an invoice hash from a known secret. Validates that the provided
    /// lock hash matches the recomputed value.
    pub fn validate_invoice_hash(secret: &[u8; 32], lock_hash: &[u8; 32]) -> Result<()> {
        let expected = invoice_hash_from_secret(secret);
        if expected.ct_eq(lock_hash).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(anyhow!("invoice hash mismatch"))
        }
    }
}

impl fmt::Debug for RatchetWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RatchetWallet")
            .field("ratchet_key", &"<redacted>")
            .finish()
    }
}

impl Drop for RatchetWallet {
    fn drop(&mut self) {
        self.ratchet_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoice_hash_roundtrip() {
        let wallet = RatchetWallet::random();
        let invoice = wallet.issue_invoice();
        RatchetWallet::validate_invoice_hash(invoice.secret(), &invoice.lock_hash())
            .expect("invoice hash must verify");
    }

    #[test]
    fn ratchet_changes_with_context() {
        let wallet = RatchetWallet::random();
        let invoice = wallet.issue_invoice();
        let chain_a = [0x11u8; 32];
        let chain_b = [0x22u8; 32];
        let coin_id = [0x33u8; 32];

        let a_step = wallet.ratchet_forward(invoice.secret(), &chain_a, &coin_id, None);
        let b_step = wallet.ratchet_forward(invoice.secret(), &chain_b, &coin_id, None);

        assert_ne!(
            a_step.next_invoice().lock_hash(),
            b_step.next_invoice().lock_hash()
        );
    }

    #[test]
    fn ratchet_changes_with_note() {
        let wallet = RatchetWallet::random();
        let invoice = wallet.issue_invoice();
        let chain = [0x42u8; 32];
        let coin = [0x24u8; 32];

        let with_note = wallet.ratchet_forward(invoice.secret(), &chain, &coin, Some(b"abc"));
        let without_note = wallet.ratchet_forward(invoice.secret(), &chain, &coin, None);

        assert_ne!(
            with_note.next_invoice().lock_hash(),
            without_note.next_invoice().lock_hash()
        );
    }

    #[test]
    fn ratchet_matches_public_derivation() {
        let wallet = RatchetWallet::random();
        let invoice = wallet.issue_invoice();

        let ratchet_key = *wallet.ratchet_key();
        let secret = *invoice.secret();
        let chain = [0xAAu8; 32];
        let coin = [0xBBu8; 32];
        let note = Some(b"note-ctx".as_ref());

        let with_note = wallet.ratchet_forward(&secret, &chain, &coin, note);
        let expected_with_note =
            crate::derive_next_secret(&ratchet_key, &secret, &chain, &coin, note);
        assert_eq!(with_note.next_invoice().secret(), &expected_with_note);

        let without_note = wallet.ratchet_forward(&secret, &chain, &coin, None);
        let expected_without_note =
            crate::derive_next_secret(&ratchet_key, &secret, &chain, &coin, None);
        assert_eq!(without_note.next_invoice().secret(), &expected_without_note);

        assert_ne!(expected_with_note, expected_without_note);
    }
}
