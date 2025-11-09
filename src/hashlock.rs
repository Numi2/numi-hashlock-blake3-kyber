//! Hashlock derivations and helpers built on top of BLAKE3.

use blake3::Hasher;

fn lp(len: usize) -> [u8; 4] {
    (len as u32).to_le_bytes()
}

/// Compute the canonical commitment for a Kyber ciphertext.
///
/// This mirrors the commitment used by `Spend` constructors, centralizing the logic.
pub fn ciphertext_commitment(kyber_ct: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"numilock.commitment.ciphertext");
    h.update(&lp(kyber_ct.len()));
    h.update(kyber_ct);
    *h.finalize().as_bytes()
}

/// Compute the payment preimage bound to chain, coin and context:
/// `p = BLAKE3("pre" || chain_id || coin_id || amount || lp(ss)||ss || lp(note)||note)`
pub fn compute_preimage(
    chain_id32: &[u8; 32],
    coin_id: &[u8; 32],
    amount_le: u64,
    shared_secret: &[u8],
    note_s: &[u8],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"pre");
    h.update(chain_id32);
    h.update(coin_id);
    h.update(&amount_le.to_le_bytes());
    h.update(&lp(shared_secret.len()));
    h.update(shared_secret);
    h.update(&lp(note_s.len()));
    h.update(note_s);
    *h.finalize().as_bytes()
}

/// Hash a preimage to the canonical lock hash domain:
/// `lh = BLAKE3("lh" || chain_id || coin_id || lp(p)||p)`
pub fn lock_hash_from_preimage(
    chain_id32: &[u8; 32],
    coin_id: &[u8; 32],
    preimage: &[u8],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"lh");
    h.update(chain_id32);
    h.update(coin_id);
    h.update(&lp(preimage.len()));
    h.update(preimage);
    *h.finalize().as_bytes()
}

/// Hash a preimage into the nullifier domain to prevent double spends:
/// `nf = BLAKE3("nf" || chain_id || coin_id || lp(p)||p)`
pub fn nullifier_from_preimage(
    chain_id32: &[u8; 32],
    coin_id: &[u8; 32],
    preimage: &[u8],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"nf");
    h.update(chain_id32);
    h.update(coin_id);
    h.update(&lp(preimage.len()));
    h.update(preimage);
    *h.finalize().as_bytes()
}

/// Hash a preimage into the commitment hash domain used by HTLC paths.
pub fn commitment_hash_from_preimage(
    chain_id32: &[u8; 32],
    coin_id: &[u8; 32],
    preimage: &[u8],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"ch");
    h.update(chain_id32);
    h.update(coin_id);
    h.update(&lp(preimage.len()));
    h.update(preimage);
    *h.finalize().as_bytes()
}

/// Construct the composite HTLC lock hash binding timeout and both paths.
pub fn htlc_lock_hash(
    chain_id32: &[u8; 32],
    coin_id: &[u8; 32],
    timeout_epoch: u64,
    ch_claim: &[u8; 32],
    ch_refund: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"htlc");
    h.update(chain_id32);
    h.update(coin_id);
    h.update(&timeout_epoch.to_le_bytes());
    h.update(ch_claim);
    h.update(ch_refund);
    *h.finalize().as_bytes()
}

/// Derive a compact view tag (1 byte) for receiver-side filtering from the shared secret.
pub fn view_tag(shared_secret: &[u8]) -> u8 {
    let mut h = Hasher::new();
    h.update(b"vt");
    h.update(&lp(shared_secret.len()));
    h.update(shared_secret);
    h.finalize().as_bytes()[0]
}

/// Derive the next lock secret while binding an additional note for replay protection.
pub fn derive_next_lock_secret(
    shared: &[u8],
    kyber_ct_bytes: &[u8],
    amount_le: u64,
    coin_id: &[u8; 32],
    chain_id32: &[u8; 32],
    note_s: &[u8],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"numilock.locksecret|mlkem768");
    h.update(&lp(shared.len()));
    h.update(shared);
    h.update(&lp(kyber_ct_bytes.len()));
    h.update(kyber_ct_bytes);
    h.update(&amount_le.to_le_bytes());
    h.update(coin_id);
    h.update(chain_id32);
    h.update(&lp(note_s.len()));
    h.update(note_s);
    *h.finalize().as_bytes()
}
/// Deterministically derive an address-style commitment identifier from receiver commitment fields.
pub fn commitment_id(
    one_time_pk: &[u8],
    kyber_ct: &[u8],
    next_lock_hash: &[u8; 32],
    coin_id: &[u8; 32],
    amount_le: u64,
    chain_id32: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"numilock.commitment_id");
    h.update(one_time_pk);
    h.update(kyber_ct);
    h.update(next_lock_hash);
    h.update(coin_id);
    h.update(&amount_le.to_le_bytes());
    h.update(chain_id32);
    *h.finalize().as_bytes()
}

/// Build a receiver commitment from shared secret, Kyber ciphertext, and context.
///
/// This creates a commitment hash that binds the shared secret, ciphertext, receiver
/// address binding, amount, coin, chain, and note together.
pub fn build_receiver_commitment(
    shared: &[u8],
    kyber_ct: &[u8],
    receiver_addr_binding: &[u8; 32],
    amount_le: u64,
    coin_id: &[u8; 32],
    chain_id32: &[u8; 32],
    note: &[u8],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"numilock.receiver_commitment");
    h.update(&lp(shared.len()));
    h.update(shared);
    h.update(&lp(kyber_ct.len()));
    h.update(kyber_ct);
    h.update(receiver_addr_binding);
    h.update(&amount_le.to_le_bytes());
    h.update(coin_id);
    h.update(chain_id32);
    h.update(&lp(note.len()));
    h.update(note);
    *h.finalize().as_bytes()
}
