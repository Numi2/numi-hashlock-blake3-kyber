use numilock::{
    constants::KYBER768_PK_BYTES,
    hashing::blake3_hash,
    hashlock::{compute_preimage_v1, view_tag},
    spend::{Spend, StealthOutput},
    stealth::{decapsulate_for_receiver, derive_one_time_pk, encapsulate_for_receiver},
};
use pqcrypto_kyber::kyber768::keypair;
use pqcrypto_traits::kem::{PublicKey, SecretKey};

fn verify_coin_membership(
    anchor_root: &[u8; 32],
    proof: &[([u8; 32], bool)],
    coin_id: &[u8; 32],
) -> anyhow::Result<()> {
    println!(
        "stub: verifying coin {} against anchor {} ({} proof elements)",
        hex::encode(coin_id),
        hex::encode(anchor_root),
        proof.len()
    );
    // TODO: Integrate actual Merkle proof verification.
    Ok(())
}

fn main() -> anyhow::Result<()> {
    // Simulate receiver keypair
    let (pk, sk) = keypair();
    let mut receiver_pk = [0u8; KYBER768_PK_BYTES];
    receiver_pk.copy_from_slice(pk.as_bytes());

    // Sender context
    let chain_id = [0u8; 32];
    let coin_id = blake3_hash(b"example-coin");
    let amount = 42u64;
    let note = b"demo-payment";
    let anchor_root = blake3_hash(b"anchor-root");
    let proof: Vec<([u8; 32], bool)> = Vec::new();

    // Host chain should verify the proof before accepting the spend.
    verify_coin_membership(&anchor_root, &proof, &coin_id)?;

    // Sender: encapsulate shared secret for receiver
    let (shared, kyber_ct) = encapsulate_for_receiver(&receiver_pk)?;

    // Receiver: decapsulate to recover shared secret (sanity check)
    let mut sk_bytes = [0u8; pqcrypto_kyber::ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES];
    sk_bytes.copy_from_slice(sk.as_bytes());
    let shared_rx = decapsulate_for_receiver(&sk_bytes, &kyber_ct)?;
    assert_eq!(shared.as_slice(), shared_rx.as_slice());

    // Derive one-time address bytes
    let one_time_pk = derive_one_time_pk(shared.as_slice(), &kyber_ct, &coin_id, &chain_id);

    // Optional view tag for receiver filtering
    let vt = view_tag(shared.as_slice());

    // Build stealth output
    let to = StealthOutput {
        one_time_pk,
        kyber_ct,
        amount_le: amount,
        view_tag: Some(vt),
    };

    // Compute unlock preimage and create spend
    let unlock_preimage = compute_preimage_v1(&chain_id, &coin_id, amount, shared.as_slice(), note);
    let spend =
        Spend::create_hashlock(coin_id, anchor_root, proof, unlock_preimage, to, &chain_id)?;

    // Print a compact summary
    println!("nullifier: {}", hex::encode(spend.nullifier));
    println!("commitment: {}", hex::encode(spend.commitment));
    println!("view_tag: {}", vt);
    Ok(())
}
