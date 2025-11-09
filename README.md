# Numilock (under development)

Numilock is a Kyber KEM + BLAKE3 hashlock lib for Rust.

 Numilock uses lattice-based cryptography (Kyber/ML-KEM-768) while BLAKE3’s wide-pipe construction ensures only a quadratic speedup is available to quantum adversaries. Together they preserve confidentiality, binding, and unlinkability guarantees even as quantum capabilities scale.


## Core Concepts Explained

### 1. One Basic Problem: Private Payments

When Alice wants to pay Bob:
- **Problem A**: If Bob publishes a static address, everyone can see all payments to that address
- **Problem B**: If Alice reveals which coin she's spending, everyone can trace her transaction history
- **Problem C**: Quantum computers will eventually break traditional public-key cryptography

### 2. The Solution: One-Time Addresses + Hashlocks

**One-Time Addresses**: Each payment goes to a unique address that only the receiver can detect.
- Bob publishes one permanent key
- Alice generates a unique address for this specific payment using Kyber KEM (Key Encapsulation Mechanism)
- Only Bob can decrypt and claim the payment
- Outside observers cannot link this payment to Bob's other payments

**Hashlocks**: Lock coins with a hash. To unlock, reveal the preimage.
- Lock = `H(secret)`
- Unlock = reveal `secret`, prove `H(secret)` matches
- No signatures required (signatures are expensive and traceable)

**Why This Matters**:
- No addresses are reused (privacy)
- No signatures to verify (faster, simpler)
- Post-quantum secure (Kyber for key exchange, BLAKE3 for hashing)
- Unlinkable (cannot connect payments to same receiver)

### 3. Receiver-Ratcheted Hashlocks (R-HTLC)

This is the advanced feature. The receiver can enforce that payments automatically forward to a new lock they control.

**How It Works**:
1. Receiver issues invoice with lock hash `h = H(S)`
2. Sender creates output locked to `h`
3. When receiver claims by revealing `S`, they also commit to next lock `h⁺ = H(S⁺)`
4. Protocol enforces: if you reveal `S`, you must create an output with `h⁺`
5. Only the receiver knows how to derive `S⁺` from `S` (using their private ratchet key)

**Why This Matters**:
- Payments can be conditionally forwarded
- Receiver maintains control over the chain of payments
- Enables payment channels without signatures
- Replay protection (each secret is used once)

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
- `view_tag()`: 1-byte filter to quickly check "is this payment for me?"

#### `hashlock`
All hash-based lock and commitment derivations.
- `compute_preimage()`: Create unlock secret bound to chain, coin, amount, shared secret
- `lock_hash_from_preimage()`: Hash preimage to lock hash
- `nullifier_from_preimage()`: Hash preimage to nullifier (prevents double-spends)
- `commitment_hash_from_preimage()`: Hash for HTLC paths
- `htlc_lock_hash()`: Composite lock with timeout and claim/refund paths
- `view_tag()`: Quick filter for receiver scanning
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

## Example: Basic Payment Flow

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
    view_tag: Some(view_tag(shared_secret.as_slice())), // For quick scanning
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

## Example: Receiver-Ratcheted Payment Channel

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
