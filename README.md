# Numilock

**Numilock is a Rust library for post-quantum private receiver designation and ratcheted hashlocked redemption.** It combines ML-KEM-768 (Kyber) for asymmetric delivery of a shared secret to one intended receiver, BLAKE3 for domain-separated hashing and key derivation, and hashlocks so that knowledge of a derived secret acts as redemption authority.

Calling it a complete “private payments” stack would overstate the scope. This crate is a **narrow but real** primitive: *how do you designate a receiver privately and non-interactively in a post-quantum way, so only that receiver can recover the redeeming secret?* NIST frames KEMs as shared-secret generators, typically used inside larger constructions (e.g. KEM/DEM), not as a drop-in replacement for all authorization or privacy machinery.

### What this is (first principles)

1. **KEM (ML-KEM-768)** — Standardized post-quantum key encapsulation: 1184-byte public keys, 1088-byte ciphertexts, 32-byte shared secret. It privately delivers shared material to the holder of a given public key.
2. **BLAKE3** — Fast general-purpose hash with keyed and derive-key modes; the BLAKE3 paper targets 128-bit security for its stated goals. Here it derives locks, tags, nullifier-like values, and follow-on secrets from that root material with strict domain separation.
3. **Hashlock** — Whoever can show knowledge of the preimage (or a protocol-defined witness) can satisfy the lock. That is **bearer** redemption authority, not proof of long-term identity, ownership, or consent.

Together: **post-quantum asymmetric delivery of bearer redemption secrets** — a good fit for private claim tickets, vouchers, sealed credits, and similar one-time rights when the surrounding system defines the rest.

### Strong fits

- **Private claim tickets** — Vouchers, refund or payout claims, withdrawal tickets, one-time settlement rights: a public commitment exists, but only the intended receiver recovers the secret needed to redeem.
- **Receiver-private delivery inside a larger protocol** — If spend authorization, covenants, or ZK ownership live elsewhere, a KEM-derived secret is a reasonable way to deliver note metadata or redemption material to the next party.
- **Ratcheted one-use capability chains** — Forward-only redemption, staged payouts, or controlled forwarding **when** the execution environment enforces the required output templates or state transitions. This is a sequencing tool inside a defined state machine, not a full payment channel by itself.

### What this does *not* solve by itself

- **General money authorization** — Hashlocks prove knowledge of a secret, not durable ownership, identity of the spender, or non-repudiation. NIST’s guidance: authentication and integrity often need additional elements (e.g. signatures). If you omit signatures, you must replace those properties another way.
- **Sender privacy, amount privacy, or graph privacy** — ML-KEM, BLAKE3, and a plain hashlock do not hide which coin is spent, the amount, or the transaction graph. That requires other commitments, proofs, anonymity sets, or shielded layers.
- **Open mempools, naively** — A bearer secret revealed before inclusion can be raced or replayed unless the transaction format or environment binds the reveal. That is a protocol-layer concern, not a flaw in ML-KEM or BLAKE3.
- **Cost and scanning** — Large KEM payloads (1088-byte ciphertexts, 1184-byte public keys) add weight if every output carries them. Short view tags imply false positives (e.g. 1 byte → 1/256); validation work per candidate can make scanning costly at scale.

### Receiver-ratcheted hashlocks (R-HTLC)

The receiver can steer a chain of locks: invoice with `h = H(S)`, sender funds `h`, on claim the receiver reveals `S` and commits to `h⁺ = H(S⁺)`, with derivation tied to a private ratchet key. Useful where the environment enforces the next-output rules; **not** a claim that this alone replaces signatures or full channel security on a public chain.

**Why it can matter**: conditional forwarding, receiver-controlled sequencing, one-time secrets per hop — **when** your layer binds execution correctly.

## Technical Components

### Cryptographic Building Blocks

| Primitive | Purpose | Quantum Resistance |
|-----------|---------|-------------------|
| **Kyber768 (ML-KEM)** | Key encapsulation for shared secrets | Quantum-safe (lattice-based) |
| **BLAKE3** | Hashing for locks, nullifiers, commitments | Grover speedup only (still 128-bit security) |
| **Domain Separation** | Prevent hash collisions across different uses | N/A (defense in depth) |

### Module Breakdown

Each module handles one specific responsibility:

#### `constants`
Defines fixed sizes and domain separation strings.
- `KYBER768_CT_BYTES = 1088` (ciphertext size)
- `KYBER768_PK_BYTES = 1184` (public key size)
- `OTP_PK_BYTES = 32` (one-time address size)
- Domain strings like `"numilock/hash"`, `"numilock/invoice"`

#### `hashing`
Provides domain-separated BLAKE3 hashing.
- `numihash()`: Standard hash with domain `"numilock"`
- Prevents accidental hash collisions with other protocols

#### `kem`
Kyber key encapsulation and one-time address derivation.
- `encapsulate_for_receiver()`: Generate shared secret for receiver's public key
- `decapsulate_for_receiver()`: Receiver recovers shared secret with private key
- `derive_one_time_pk()`: Deterministic one-time address from shared secret
- `recover_shared_and_view_tag()`: Recover shared secret and 1-byte view tag
- `recover_shared_and_view_tag16()`: Recover shared secret and 2-byte view tag (lower collision rate)
- `view_tag()`: 1-byte filter to quickly check "is this payment for me?"

#### `hashlock`
All hash-based lock and commitment derivations.
- `compute_preimage()`: Create unlock secret bound to chain, coin, amount, shared secret
- `lock_hash_from_preimage()`: Hash preimage to lock hash
- `nullifier_from_preimage()`: Hash preimage to nullifier (prevents double-spends)
- `commitment_hash_from_preimage()`: Hash for HTLC paths
- `htlc_lock_hash()`: Composite lock with timeout and claim/refund paths
- `view_tag()`: Quick filter for receiver scanning (1 byte)
- `view_tag16()`: Optional 2-byte filter for lower collision rates
- `derive_next_lock_secret()`: Derive next lock in chain
- `commitment_id()`: Unique identifier for receiver commitments
- `build_receiver_commitment()`: Full commitment binding all payment details

#### `spend`
Structures representing actual spends on a blockchain.
- `KemOutput`: The recipient's encrypted output (one-time key + ciphertext + amount)
- `Spend`: Complete spend record (coin being spent, Merkle proof, commitment, nullifier, recipient)
- `Spend::create_hashlock()`: Basic hashlock spend
- `Spend::create_hashlock_with_next_lock()`: R-HTLC spend with explicit next lock
- `Spend::create_htlc_hashlock()`: HTLC with timeout and bidirectional paths

#### `wallet`
Receiver wallet implementing the ratchet mechanism.
- `RatchetWallet`: Holds the private ratchet key (32 bytes)
- `Invoice`: A lock hash and its secret
- `issue_invoice()`: Create new invoice with random secret
- `ratchet_forward()`: Derive next secret and lock after revealing current secret
- Automatically binds chain ID, coin ID, and optional note to prevent replay

## Example: Basic hashlocked output (claim-style flow)

```rust
use numilock::{
    constants::KYBER768_PK_BYTES,
    kem::{encapsulate_for_receiver, derive_one_time_pk},
    hashlock::{compute_preimage, view_tag},
    spend::{Spend, KemOutput},
};

// Setup
let receiver_pk = [0u8; KYBER768_PK_BYTES]; // Receiver's permanent Kyber public key
let chain_id = [0u8; 32];  // Which blockchain
let coin_id = [1u8; 32];   // Which coin Alice is spending
let amount = 1000u64;      // Amount in base units
let note = b"invoice-42";  // Optional invoice/payment reference

// Step 1: Alice generates shared secret for Bob's key
let (shared_secret, kyber_ciphertext) = encapsulate_for_receiver(&receiver_pk)?;

// Step 2: Alice derives a one-time address for this payment
let one_time_pk = derive_one_time_pk(
    shared_secret.as_slice(),
    &kyber_ciphertext,
    &coin_id,
    &chain_id,
);

// Step 3: Alice creates the locked output
let kem_output = KemOutput {
    one_time_pk,
    kyber_ct: kyber_ciphertext,
    amount_le: amount,
    view_tag: Some(view_tag(shared_secret.as_slice())), // For quick scanning (or use view_tag16 for 2 bytes)
};

// Step 4: Alice creates the unlock preimage (proves she can spend)
let unlock_preimage = compute_preimage(
    &chain_id,
    &coin_id,
    amount,
    shared_secret.as_slice(),
    note,
);

// Step 5: Alice builds the complete spend
let anchor_root = [0u8; 32];  // Merkle root of coin set
let proof = vec![];           // Merkle proof that coin_id is in anchor_root
let spend = Spend::create_hashlock(
    coin_id,
    anchor_root,
    proof,
    unlock_preimage,
    kem_output,
    &chain_id,
)?;

// Result: spend.nullifier prevents double-spending
//         spend.commitment binds the kem_output
//         spend.to contains encrypted details only Bob can decrypt
```

## Example: Receiver-ratcheted lock chain

```rust
use numilock::wallet::RatchetWallet;

// Bob creates a wallet with a random ratchet key
let bob_wallet = RatchetWallet::random();

// Bob issues an invoice for Alice
let invoice = bob_wallet.issue_invoice();
let payment_hash = invoice.lock_hash(); // Send this to Alice

// ... Alice creates a payment locked to payment_hash ...

// When Alice reveals the payment on-chain, Bob claims it
// and immediately ratchets to a new lock
let chain_id = [0u8; 32];
let coin_id = [1u8; 32];
let next = bob_wallet.ratchet_forward(
    invoice.secret(),  // The secret Alice revealed
    &chain_id,
    &coin_id,
    Some(b"hop-1"),    // Optional note for replay protection
);

// Bob creates a new output in the same transaction with next_lock_hash
let next_lock_hash = next.next_invoice().lock_hash();

// Only Bob can derive this next_lock_hash because only Bob knows the ratchet key
// Alice cannot predict or control where the payment goes next
```



## Testing and Validation

Run the full test suite:

```bash
cargo test --all
```

Run the example:

```bash
cargo run --example quickstart
```

All cryptographic derivations are deterministic. Given the same inputs, you will always get the same outputs. This makes testing straightforward and debugging tractable.

## Dependencies

| Crate | Purpose | Version |
|-------|---------|---------|
| `pqcrypto-kyber` | Kyber768 (ML-KEM) implementation | Latest |
| `blake3` | Fast, secure hashing | Latest |
| `serde` | Serialization for `Spend` and outputs | Latest |
| `zeroize` | Clear secrets from memory | Latest |
| `subtle` | Constant-time comparisons | Latest |
| `anyhow` | Error handling | Latest |

## Security hardening and recent fixes

- Critical/High
  - Missing input validation in spend constructors: Fixed. Constructors now reject zero amounts, all-zero keys, and invalid HTLC params.
  - Information leakage in KEM error messages: Fixed. Errors are sanitized and avoid leaking internal details.
  - View tag collisions with 1-byte tag: Mitigated. Added `view_tag16()` and `recover_shared_and_view_tag16()`. The 1-byte tag remains for backward compatibility.
  - Weak key validation (all-zero ratchet keys): Fixed. `RatchetWallet::new` now returns `Result` and rejects all-zero keys; `random()` enforces this invariant.

- Medium
  - Integer truncation in length-prefixing: Fixed. All `lp()` helpers now use checked `u32` conversion to prevent silent truncation.
  - Performance (unnecessary Vec allocations): Improved. Switched to streaming BLAKE3 for domain-separated hashes on hot paths.
  - Inconsistent domain separation patterns: Partially addressed. Streaming derive-key is standardized in new/updated code; full alignment across all domains is scheduled for a future revision to preserve backward compatibility.
