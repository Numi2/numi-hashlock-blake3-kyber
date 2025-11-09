//! Reusable spend structures and constructors for Numilock hashlocks.

use anyhow::{Result, anyhow};
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zeroize::Zeroize;

use crate::constants::{KYBER768_CT_BYTES, OTP_PK_BYTES};
use crate::hashlock::{
    commitment_hash_from_preimage, htlc_lock_hash, lock_hash_from_preimage, nullifier_from_preimage,
};

/// Kem output describing the recipient of a spend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KemOutput {
    /// One-time public key bytes for the receiver.
    pub one_time_pk: [u8; OTP_PK_BYTES],
    /// Kyber768 ciphertext encapsulating the shared secret.
    #[serde(with = "BigArray")]
    pub kyber_ct: [u8; KYBER768_CT_BYTES],
    /// Amount in little-endian format.
    pub amount_le: u64,
    /// Optional view tag for receiver-side filtering.
    pub view_tag: Option<u8>,
}

/// Spend record referencing an existing coin and authorizing its transfer to a kem output.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Spend {
    /// The spent coin identifier.
    pub coin_id: [u8; 32],
    /// Merkle root of the epoch that committed this coin.
    pub root: [u8; 32],
    /// Inclusion proof path for the coin's membership.
    pub proof: Vec<([u8; 32], bool)>,
    /// Commitment to the kem output (BLAKE3 hash of all kem output fields).
    pub commitment: [u8; 32],
    /// Nullifier derived from the unlock preimage.
    pub nullifier: [u8; 32],
    /// Kem output describing the next recipient.
    pub to: KemOutput,
    /// Hashlock unlock preimage revealed by this spend.
    #[serde(default)]
    pub unlock_preimage: Option<[u8; 32]>,
    /// Next-hop lock hash supplied by the receiver commitment.
    #[serde(default)]
    pub next_lock_hash: Option<[u8; 32]>,
    /// Optional HTLC timeout epoch.
    #[serde(default)]
    pub htlc_timeout_epoch: Option<u64>,
    /// Commitment hash for the claim path.
    #[serde(default)]
    pub htlc_ch_claim: Option<[u8; 32]>,
    /// Commitment hash for the refund path.
    #[serde(default)]
    pub htlc_ch_refund: Option<[u8; 32]>,
}

fn lp(len: usize) -> [u8; 4] {
    // Prevent silent truncation of large length values
    u32::try_from(len)
        .expect("length exceeds u32")
        .to_le_bytes()
}

/// Compute the canonical commitment for the entire kem output.
pub fn kem_output_commitment(output: &KemOutput) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"numilock.commitment.kem_output");
    h.update(&lp(output.one_time_pk.len()));
    h.update(&output.one_time_pk);
    h.update(&lp(output.kyber_ct.len()));
    h.update(&output.kyber_ct);
    h.update(&output.amount_le.to_le_bytes());
    match output.view_tag {
        Some(tag) => {
            h.update(&[1]);
            h.update(&[tag]);
        }
        None => {
            h.update(&[0]);
        }
    }
    *h.finalize().as_bytes()
}

fn validate_nonzero_32(label: &str, v: &[u8; 32]) -> Result<()> {
    if v.iter().all(|&b| b == 0) {
        return Err(anyhow!("{label} must be non-zero"));
    }
    Ok(())
}

fn validate_kem_output(output: &KemOutput) -> Result<()> {
    if output.amount_le == 0 {
        return Err(anyhow!("amount must be > 0"));
    }
    if output.one_time_pk.iter().all(|&b| b == 0) {
        return Err(anyhow!("one_time_pk must be non-zero"));
    }
    if output.kyber_ct.iter().all(|&b| b == 0) {
        return Err(anyhow!("kyber_ct must be non-zero"));
    }
    Ok(())
}

impl Spend {
    /// Construct a signatureless hashlock-based spend.
    ///
    /// The `to` parameter must contain a valid `KemOutput` with a real Kyber ciphertext.
    /// The commitment is computed as the BLAKE3 hash of the full kem output fields.
    pub fn create_hashlock(
        coin_id: [u8; 32],
        anchor_root: [u8; 32],
        proof: Vec<([u8; 32], bool)>,
        unlock_preimage: [u8; 32],
        to: KemOutput,
        chain_id32: &[u8; 32],
    ) -> Result<Self> {
        // Basic input validation
        validate_nonzero_32("coin_id", &coin_id)?;
        validate_nonzero_32("anchor_root", &anchor_root)?;
        validate_nonzero_32("unlock_preimage", &unlock_preimage)?;
        validate_kem_output(&to)?;

        let nullifier = nullifier_from_preimage(chain_id32, &coin_id, &unlock_preimage);
        // Commitment binds the entire kem output
        let commitment = kem_output_commitment(&to);

        Ok(Spend {
            coin_id,
            root: anchor_root,
            proof,
            commitment,
            nullifier,
            to,
            unlock_preimage: Some(unlock_preimage),
            next_lock_hash: None,
            htlc_timeout_epoch: None,
            htlc_ch_claim: None,
            htlc_ch_refund: None,
        })
    }

    /// Construct a hashlock-based spend while explicitly setting the next lock hash.
    ///
    /// This is useful when the protocol requires the next-hop lock to be committed alongside the spend.
    pub fn create_hashlock_with_next_lock(
        coin_id: [u8; 32],
        anchor_root: [u8; 32],
        proof: Vec<([u8; 32], bool)>,
        unlock_preimage: [u8; 32],
        to: KemOutput,
        chain_id32: &[u8; 32],
        next_lock_hash: [u8; 32],
    ) -> Result<Self> {
        // Basic input validation
        validate_nonzero_32("coin_id", &coin_id)?;
        validate_nonzero_32("anchor_root", &anchor_root)?;
        validate_nonzero_32("unlock_preimage", &unlock_preimage)?;
        validate_nonzero_32("next_lock_hash", &next_lock_hash)?;
        validate_kem_output(&to)?;

        let nullifier = nullifier_from_preimage(chain_id32, &coin_id, &unlock_preimage);
        let commitment = kem_output_commitment(&to);

        Ok(Spend {
            coin_id,
            root: anchor_root,
            proof,
            commitment,
            nullifier,
            to,
            unlock_preimage: Some(unlock_preimage),
            next_lock_hash: Some(next_lock_hash),
            htlc_timeout_epoch: None,
            htlc_ch_claim: None,
            htlc_ch_refund: None,
        })
    }

    /// Construct an HTLC-enabled hashlock spend with explicit claim and refund paths.
    ///
    /// The `to` parameter must contain a valid `KemOutput` with a real Kyber ciphertext.
    /// The commitment is computed as the BLAKE3 hash of the full kem output fields.
    #[allow(clippy::too_many_arguments)]
    pub fn create_htlc_hashlock(
        coin_id: [u8; 32],
        anchor_root: [u8; 32],
        proof: Vec<([u8; 32], bool)>,
        unlock_preimage: [u8; 32],
        to: KemOutput,
        chain_id32: &[u8; 32],
        timeout_epoch: u64,
        ch_claim: [u8; 32],
        ch_refund: [u8; 32],
    ) -> Result<Self> {
        // Basic input validation
        if timeout_epoch == 0 {
            return Err(anyhow!("htlc timeout_epoch must be > 0"));
        }
        validate_nonzero_32("coin_id", &coin_id)?;
        validate_nonzero_32("anchor_root", &anchor_root)?;
        validate_nonzero_32("unlock_preimage", &unlock_preimage)?;
        validate_nonzero_32("htlc_ch_claim", &ch_claim)?;
        validate_nonzero_32("htlc_ch_refund", &ch_refund)?;
        if ch_claim == ch_refund {
            return Err(anyhow!("htlc claim and refund commitments must differ"));
        }
        validate_kem_output(&to)?;

        let nullifier = nullifier_from_preimage(chain_id32, &coin_id, &unlock_preimage);
        // Commitment binds the entire kem output
        let commitment = kem_output_commitment(&to);

        Ok(Spend {
            coin_id,
            root: anchor_root,
            proof,
            commitment,
            nullifier,
            to,
            unlock_preimage: Some(unlock_preimage),
            next_lock_hash: None,
            htlc_timeout_epoch: Some(timeout_epoch),
            htlc_ch_claim: Some(ch_claim),
            htlc_ch_refund: Some(ch_refund),
        })
    }

    /// Recompute the expected nullifier for this spend using its stored preimage.
    pub fn expected_nullifier(&self, chain_id32: &[u8; 32]) -> Result<[u8; 32]> {
        let preimage = self
            .unlock_preimage
            .ok_or_else(|| anyhow!("spend missing unlock preimage"))?;
        Ok(nullifier_from_preimage(
            chain_id32,
            &self.coin_id,
            &preimage,
        ))
    }

    /// Recompute the expected next lock hash for the provided preimage.
    pub fn expected_lock_hash(&self, chain_id32: &[u8; 32], preimage: &[u8]) -> [u8; 32] {
        lock_hash_from_preimage(chain_id32, &self.coin_id, preimage)
    }

    /// Compute the commitment hash used in HTLC claim/refund paths for a given preimage.
    pub fn commitment_hash_for_preimage(&self, chain_id32: &[u8; 32], preimage: &[u8]) -> [u8; 32] {
        commitment_hash_from_preimage(chain_id32, &self.coin_id, preimage)
    }

    /// Compute the expected HTLC composite lock hash if the spend is HTLC-enabled.
    pub fn expected_htlc_lock_hash(&self, chain_id32: &[u8; 32]) -> Option<[u8; 32]> {
        match (
            self.htlc_timeout_epoch,
            self.htlc_ch_claim,
            self.htlc_ch_refund,
        ) {
            (Some(t), Some(claim), Some(refund)) => Some(htlc_lock_hash(
                chain_id32,
                &self.coin_id,
                t,
                &claim,
                &refund,
            )),
            _ => None,
        }
    }
}

impl Drop for Spend {
    fn drop(&mut self) {
        if let Some(ref mut preimage) = self.unlock_preimage {
            preimage.zeroize();
        }
    }
}

impl core::fmt::Debug for Spend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Spend")
            .field("coin_id", &self.coin_id)
            .field("root", &self.root)
            .field("proof_len", &self.proof.len())
            .field("commitment", &self.commitment)
            .field("nullifier", &self.nullifier)
            .field("to", &self.to)
            .field("unlock_preimage", &"<redacted>")
            .field("next_lock_hash", &self.next_lock_hash)
            .field("htlc_timeout_epoch", &self.htlc_timeout_epoch)
            .field("htlc_ch_claim", &self.htlc_ch_claim)
            .field("htlc_ch_refund", &self.htlc_ch_refund)
            .finish()
    }
}
