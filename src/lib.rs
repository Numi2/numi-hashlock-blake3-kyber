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
pub mod wallet;

pub use constants::*;
pub use hashing::*;
pub use hashlock::*;
pub use spend::*;
pub use stealth::*;
pub use wallet::*;

// src/lib.rs
/// Receiver‑ratcheted, signatureless hashlocks helpers.

/// Domain strings
pub const DST_H: &str    = "numilock/hash.v2";
pub const DST_PRF: &str  = "numilock/ratchet.prf.v1";
pub const DST_INV: &str  = "numilock/invoice.v1";
pub const DST_BIND: &str = "numilock/bind.v1";

/// 32‑byte hashlock value H(S) or H(S⁺).
pub type LockHash = [u8; 32];

/// Simple output model carrying a lock hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutput {
    pub lock_hash: LockHash,
    pub amount: u64,
}

/// Spend witness carrying revealed S and the declared next lock h⁺.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendWitness {
    pub unlock_preimage: [u8; 32], // S
    pub next_lock_hash: LockHash,  // h⁺ = H(S⁺)
}

/// Covenant errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CovenantError {
    WrongCurrentLock,   // invoice_hash(S) != current input lock
    MissingNext,        // zero outputs with next_lock_hash
    DuplicateNext,      // more than one output with next_lock_hash
}

/// 4‑byte little‑endian length prefix.
fn lp(x: usize) -> [u8; 4] {
    (x as u32).to_le_bytes()
}

fn push_field(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&lp(field.len()));
    buf.extend_from_slice(field);
}

/// Bind context into a fixed 32‑byte value.
/// Input order is fixed and length‑prefixed.
pub fn bind_context(chain_id: &[u8], coin_id: &[u8], note: Option<&[u8]>) -> [u8; 32] {
    let note_flag = if note.is_some() { [1u8] } else { [0u8] };
    let note_bytes = note.unwrap_or(&[]);

    let mut buf = Vec::with_capacity(
        4 + chain_id.len()
            + 4 + coin_id.len()
            + 4 + note_flag.len()
            + 4 + note_bytes.len(),
    );
    push_field(&mut buf, chain_id);
    push_field(&mut buf, coin_id);
    push_field(&mut buf, &note_flag);
    push_field(&mut buf, note_bytes);
    blake3::derive_key(DST_BIND, &buf)
}

/// H for invoice/lock hashing with domain separation:
/// h = H(L(DST_INV)||DST_INV||S)
pub fn invoice_hash(s: &[u8; 32]) -> LockHash {
    let mut buf = Vec::with_capacity(4 + DST_INV.len() + 32);
    buf.extend_from_slice(&lp(DST_INV.as_bytes().len()));
    buf.extend_from_slice(DST_INV.as_bytes());
    buf.extend_from_slice(s);
    blake3::derive_key(DST_H, &buf)
}

/// Internal: derive a keyed PRF key from K_receiver.
fn prf_key(k_receiver: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(DST_PRF, k_receiver)
}

/// PRF(K, input) → 32 bytes using BLAKE3 keyed mode with a derived key.
fn prf(k_receiver: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let k = prf_key(k_receiver);
    let mut h = blake3::Hasher::new_keyed(&k);
    h.update(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Derive the receiver‑only next secret S⁺ from K_receiver and revealed S.
/// S⁺ = PRF(K_receiver,  L(S)||S||Bind(chain_id, coin_id, note))
pub fn derive_next_secret(
    k_receiver: &[u8; 32],
    s: &[u8; 32],
    chain_id: &[u8],
    coin_id: &[u8],
    note: Option<&[u8]>,
) -> [u8; 32] {
    let bind = bind_context(chain_id, coin_id, note);
    let mut input = Vec::with_capacity(4 + 32 + 32);
    input.extend_from_slice(&lp(s.len()));
    input.extend_from_slice(s);
    input.extend_from_slice(&bind);
    prf(k_receiver, &input)
}

/// Compute the next lock hash h⁺ = H(L(DST_INV)||DST_INV||S⁺).
pub fn next_lock_hash(s_plus: &[u8; 32]) -> LockHash {
    invoice_hash(s_plus)
}

/// Covenant: verify the spend reveals S for the current input lock,
/// and exactly one output equals next_lock_hash.
/// Returns Ok(()) if valid, CovenantError otherwise.
pub fn check_covenant(
    current_lock_hash: &LockHash,
    outputs: &[TxOutput],
    witness: &SpendWitness,
) -> Result<(), CovenantError> {
    // Check current lock matches invoice_hash(S)
    if &invoice_hash(&witness.unlock_preimage) != current_lock_hash {
        return Err(CovenantError::WrongCurrentLock);
    }
    // Enforce exactly one output equals next_lock_hash
    let count = outputs.iter().filter(|o| o.lock_hash == witness.next_lock_hash).count();
    match count {
        1 => Ok(()),
        0 => Err(CovenantError::MissingNext),
        _ => Err(CovenantError::DuplicateNext),
    }
}

/// Utility: hex encode for logging/tests without extra deps.
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rhtlc_happy_path_and_covenant() {
        // Deterministic fixtures
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() { *b = i as u8; }

        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() { *b = (0xF0u8 ^ (i as u8)); }

        let chain_id = b"chain-A";
        let coin_id  = [0xABu8; 32];
        let note     = Some(b"invoice-123".as_ref());

        // Current lock under S
        let h = invoice_hash(&s);

        // Receiver derives S⁺ and h⁺
        let s_plus = derive_next_secret(&k, &s, chain_id, &coin_id, note);
        let h_plus = next_lock_hash(&s_plus);

        // Build tx with exactly one output = h⁺
        let outputs = vec![
            TxOutput { lock_hash: h_plus, amount: 10 },
            TxOutput { lock_hash: invoice_hash(&[0u8; 32]), amount: 1 },
        ];
        let wit = SpendWitness { unlock_preimage: s, next_lock_hash: h_plus };

        // Covenant passes
        assert_eq!(check_covenant(&h, &outputs, &wit), Ok(()));

        // Debug prints (visible with `cargo test -- --nocapture`)
        eprintln!("S      = {}", to_hex(&s));
        eprintln!("h      = {}", to_hex(&h));
        eprintln!("S_plus = {}", to_hex(&s_plus));
        eprintln!("h_plus = {}", to_hex(&h_plus));
    }

    #[test]
    fn rhtlc_covenant_missing_and_duplicate() {
        let k = [7u8; 32];
        let s = [3u8; 32];
        let h = invoice_hash(&s);
        let s_plus = derive_next_secret(&k, &s, b"A", &[1u8; 32], None);
        let h_plus = next_lock_hash(&s_plus);

        // Missing next
        let outputs_missing = vec![
            TxOutput { lock_hash: invoice_hash(&[9u8; 32]), amount: 1 },
        ];
        let wit = SpendWitness { unlock_preimage: s, next_lock_hash: h_plus };
        assert_eq!(check_covenant(&h, &outputs_missing, &wit), Err(CovenantError::MissingNext));

        // Duplicate next
        let outputs_dupe = vec![
            TxOutput { lock_hash: h_plus, amount: 1 },
            TxOutput { lock_hash: h_plus, amount: 2 },
        ];
        assert_eq!(check_covenant(&h, &outputs_dupe, &wit), Err(CovenantError::DuplicateNext));

        // Wrong current lock (tamper with S)
        let wrong_h = invoice_hash(&[0u8; 32]);
        assert_eq!(check_covenant(&wrong_h, &outputs_dupe, &wit), Err(CovenantError::WrongCurrentLock));
    }

    #[test]
    fn bind_context_distinguishes_note_presence() {
        let chain = b"chain-ctx";
        let coin = b"coin-ctx";

        let ctx_none = bind_context(chain, coin, None);
        let ctx_empty = bind_context(chain, coin, Some(b""));

        assert_ne!(ctx_none, ctx_empty);
    }
}