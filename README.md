# Numilock (under development)

Numilock is a  Kyber KEM + BLAKE3 hashlock toolkit for Rust. It provides deterministic one-time address derivation, receiver
commitments, hashlock derivations, and spend constructors without any dependency on a specific node or networking stack.

By coupling the NIST-selected ML-KEM (Kyber) primitive for key encapsulation with domain-separated BLAKE3 hashing, Numilock keeps both shared-secret establishment and downstream commitments post-quantum safe. The lattice-based KEM resists known quantum attacks on public-key transport, while BLAKE3’s wide-pipe construction ensures only a quadratic speedup is available to quantum adversaries. Together they preserve confidentiality, binding, and unlinkability guarantees even as quantum capabilities scale.

## Features

- Kyber768 encapsulation helpers with deterministic one-time address bytes
- BLAKE3-based lock, nullifier, and commitment derivations with strict domain
  separation
- Receiver commitment helpers and canonical commitment identifiers
- Hashlock and HTLC-aware spend builders suitable for signatureless transfers
- Receiver ratchet wallet primitives for immediate relock R-HTLC flows
- View-tag generation and receiver-side filtering utilities

## Crate Layout

| Module       | Purpose                                                            |
| ------------ | ------------------------------------------------------------------ |
| `stealth`    | Kyber encapsulation helpers, deterministic one-time address derivation, stealth output utilities |
| `hashlock`   | BLAKE3 derivations for locks, nullifiers, and HTLC composites      |
| `spend`      | Serializable spend structures and constructors                     |
| `hashing`    | Keyed BLAKE3 hashing helpers                                       |
| `constants`  | Exported primitive sizes and shared address alias                  |
| `wallet`     | Receiver ratchet wallet utilities for signatureless R-HTLCs        |

## Quick Start

```rust
use numilock::{
    build_receiver_commitment, commitment_id_v1, compute_preimage_v1,
    encapsulate_for_receiver, derive_one_time_pk, view_tag,
    lock_hash_from_preimage, spend::{Spend, StealthOutput},
};

let chain_id = [0u8; 32];
let coin_id = [1u8; 32];
let receiver_pk = [0u8; 1184]; // KYBER768_PK_BYTES - replace with actual receiver's public key
let anchor_root = [0u8; 32];
let proof = vec![]; // Merkle proof for coin inclusion

// Encapsulate shared secret for the receiver
let (shared, kyber_ct) = encapsulate_for_receiver(&receiver_pk)?;

// Derive one-time public key for the receiver
let one_time_pk = derive_one_time_pk(shared.as_slice(), &kyber_ct, &coin_id, &chain_id);

// Build receiver commitment
let receiver_addr_binding = [2u8; 32];
let amount = 1u64;
let note = b"invoice-123";
let commitment = build_receiver_commitment(
    shared.as_slice(),
    &kyber_ct,
    &receiver_addr_binding,
    amount,
    &coin_id,
    &chain_id,
    note,
);

// Compute unlock preimage
let unlock_preimage = compute_preimage_v1(&chain_id, &coin_id, amount, shared.as_slice(), note);

// Create stealth output
let stealth_output = StealthOutput {
    one_time_pk,
    kyber_ct,
    amount_le: amount,
    view_tag: Some(view_tag(shared.as_slice())),
};

// (Optional) host chain verifies the membership proof before accepting the spend.
// verify_coin_membership(&anchor_root, &proof, &coin_id)?;

// Create hashlock spend
let spend = Spend::create_hashlock(
    coin_id,
    anchor_root,
    proof,
    unlock_preimage,
    stealth_output,
    &chain_id,
)?; // ready for serialization or gossiping
```

## Receiver-Ratcheted Wallet

```rust
use numilock::wallet::RatchetWallet;

let wallet = RatchetWallet::random();

// Receiver invoices a payer
let invoice = wallet.issue_invoice();
let payment_hash = invoice.lock_hash(); // share with payer

// Later, when the invoice is claimed on-chain, reveal S and immediately ratchet
let chain_id = [0u8; 32];
let coin_id = [1u8; 32];
let step = wallet.ratchet_forward(invoice.secret(), &chain_id, &coin_id, None);

// Create the relock output in the same transaction
let next_lock_hash = step.next_invoice().lock_hash();

// Forward the new invoice hash to the next hop (keep the secret private)
let forwarded_invoice = step.into_invoice();
```

## License

Dual-licensed under either of:
- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

You may choose either license.




# Security Policy

## Threat Model and Assumptions
- Cryptographic primitives are provided by `pqcrypto-kyber` (ML-KEM-768) and `blake3`.
- Hash domains are explicitly separated and length-prefixed to avoid cross-domain collisions.
- The `view_tag` is a single byte intended only for receiver-side filtering and is not a security boundary.
- `Spend.commitment` currently hashes only the Kyber ciphertext. Applications may prefer a stronger commitment (e.g., commit to the full `StealthOutput` or use `commitment_id_v1`) depending on on-ledger requirements.

## Responsible Disclosure
If you find a security issue, please email the maintainers or open a private advisory. Avoid filing public issues for vulnerabilities until a fix is available.

## Support and Guarantees
This project is provided “as is” without any warranties. It has not undergone an external audit. Use at your own risk and add defense-in-depth appropriate for your deployment.

## Hardening Recommendations
- Perform independent cryptographic review before production use.
- Use constant-time comparisons where appropriate and minimize side-channels.
- Add protocol-level replay protections suitable for your environment.
- Consider binding commitments to all fields you require immutability for on-chain.


