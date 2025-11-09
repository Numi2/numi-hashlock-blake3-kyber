use numilock::{
    constants::KYBER768_PK_BYTES,
    hashlock::{compute_preimage, view_tag},
    kem::{decapsulate_for_receiver, derive_one_time_pk, encapsulate_for_receiver},
    spend::{Spend, KemOutput},
};
use pqcrypto_kyber::kyber768::keypair;
use pqcrypto_traits::kem::{PublicKey, SecretKey};

#[test]
fn encapsulate_then_decapsulate_matches() {
    let (pk, sk) = keypair();
    let mut receiver_pk = [0u8; KYBER768_PK_BYTES];
    receiver_pk.copy_from_slice(pk.as_bytes());

    let (shared, kyber_ct) = encapsulate_for_receiver(&receiver_pk).expect("encapsulate");
    let mut sk_bytes = [0u8; pqcrypto_kyber::ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES];
    sk_bytes.copy_from_slice(sk.as_bytes());
    let shared_rx = decapsulate_for_receiver(&sk_bytes, &kyber_ct).expect("decapsulate");
    assert_eq!(shared.as_slice(), shared_rx.as_slice());
}

#[test]
fn build_spend_and_verify_nullifier() {
    let (pk, sk) = keypair();
    let mut receiver_pk = [0u8; KYBER768_PK_BYTES];
    receiver_pk.copy_from_slice(pk.as_bytes());

    let chain_id = [7u8; 32];
    let coin_id = [9u8; 32];
    let amount = 5u64;
    let note = b"test-note";
    let anchor_root = [3u8; 32];
    let proof: Vec<([u8; 32], bool)> = Vec::new();

    let (shared, kyber_ct) = encapsulate_for_receiver(&receiver_pk).expect("encapsulate");

    // sanity: decapsulate
    let mut sk_bytes = [0u8; pqcrypto_kyber::ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES];
    sk_bytes.copy_from_slice(sk.as_bytes());
    let shared_rx = decapsulate_for_receiver(&sk_bytes, &kyber_ct).expect("decapsulate");
    assert_eq!(shared.as_slice(), shared_rx.as_slice());

    let one_time_pk = derive_one_time_pk(shared.as_slice(), &kyber_ct, &coin_id, &chain_id);
    let vt = view_tag(shared.as_slice());

    let to = KemOutput {
        one_time_pk,
        kyber_ct,
        amount_le: amount,
        view_tag: Some(vt),
    };
    let unlock_preimage = compute_preimage(&chain_id, &coin_id, amount, shared.as_slice(), note);
    let spend = Spend::create_hashlock(coin_id, anchor_root, proof, unlock_preimage, to, &chain_id)
        .expect("create spend");

    let expected_nf = spend.expected_nullifier(&chain_id).expect("expected nf");
    assert_eq!(expected_nf, spend.nullifier);
}
