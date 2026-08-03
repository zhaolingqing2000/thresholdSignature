#![cfg(feature = "concrete-ibe")]

use threshold_signature::crypto::ibe_backend::{
    trace_signer_indexes, ConcreteIbeBackend, ConcreteIbeRandomness, IbeBackendError,
};

#[test]
fn correct_identity_recovers_signer_index() {
    let (pk, sk) = ConcreteIbeBackend::setup();
    let d = [9u8; 32];
    let usk = ConcreteIbeBackend::extract(&pk, &sk, b"message", &d).unwrap();
    let ct = ConcreteIbeBackend::encrypt(&pk, b"message", &d, 7).unwrap();
    assert_eq!(
        ConcreteIbeBackend::decrypt(&pk, &usk, b"message", &d, &ct).unwrap(),
        7
    );
}

#[test]
fn different_identity_fails() {
    let (pk, sk) = ConcreteIbeBackend::setup();
    let d = [9u8; 32];
    let other_d = [10u8; 32];
    let usk = ConcreteIbeBackend::extract(&pk, &sk, b"message", &other_d).unwrap();
    let ct = ConcreteIbeBackend::encrypt(&pk, b"message", &d, 7).unwrap();
    assert!(ConcreteIbeBackend::decrypt(&pk, &usk, b"message", &d, &ct).is_err());
    let usk = ConcreteIbeBackend::extract(&pk, &sk, b"message", &d).unwrap();
    assert!(ConcreteIbeBackend::decrypt(&pk, &usk, b"changed", &d, &ct).is_err());
}

#[test]
fn modified_ciphertext_is_rejected() {
    let (pk, sk) = ConcreteIbeBackend::setup();
    let d = [9u8; 32];
    let usk = ConcreteIbeBackend::extract(&pk, &sk, b"message", &d).unwrap();
    let mut ct = ConcreteIbeBackend::encrypt(&pk, b"message", &d, 7).unwrap();
    ct.aead_ciphertext[0] ^= 1;
    assert!(ConcreteIbeBackend::decrypt(&pk, &usk, b"message", &d, &ct).is_err());
}

#[test]
fn duplicate_and_out_of_range_signers_are_rejected() {
    let (pk, sk) = ConcreteIbeBackend::setup();
    let d = [9u8; 32];
    let usk = ConcreteIbeBackend::extract(&pk, &sk, b"message", &d).unwrap();
    let ct1 = ConcreteIbeBackend::encrypt(&pk, b"message", &d, 1).unwrap();
    let ct2 = ConcreteIbeBackend::encrypt(&pk, b"message", &d, 1).unwrap();
    assert!(matches!(
        trace_signer_indexes(&pk, &usk, b"message", &d, &[ct1, ct2], 8),
        Err(IbeBackendError::DuplicateSigner)
    ));
    let ct = ConcreteIbeBackend::encrypt(&pk, b"message", &d, 9).unwrap();
    assert!(matches!(
        trace_signer_indexes(&pk, &usk, b"message", &d, &[ct], 8),
        Err(IbeBackendError::SignerOutOfRange)
    ));
}

#[test]
fn serialization_roundtrip_preserves_ciphertext() {
    let (pk, _) = ConcreteIbeBackend::setup();
    let d = [9u8; 32];
    let ct = ConcreteIbeBackend::encrypt(&pk, b"message", &d, 7).unwrap();
    let encoded = serde_json::to_vec(&ct).unwrap();
    let decoded = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(ct, decoded);
}

#[test]
fn deterministic_encrypt_with_randomness_is_reproducible() {
    let (pk, sk) = ConcreteIbeBackend::setup();
    let d = [9u8; 32];
    let randomness = ConcreteIbeRandomness { xi: vec![42u8; 64] };
    let ct1 =
        ConcreteIbeBackend::encrypt_with_randomness(&pk, b"message", &d, 7, &randomness).unwrap();
    let ct2 =
        ConcreteIbeBackend::encrypt_with_randomness(&pk, b"message", &d, 7, &randomness).unwrap();
    assert_eq!(ct1, ct2);
    let usk = ConcreteIbeBackend::extract(&pk, &sk, b"message", &d).unwrap();
    assert_eq!(
        ConcreteIbeBackend::decrypt(&pk, &usk, b"message", &d, &ct1).unwrap(),
        7
    );

    let changed = ConcreteIbeRandomness { xi: vec![43u8; 64] };
    let ct3 =
        ConcreteIbeBackend::encrypt_with_randomness(&pk, b"message", &d, 7, &changed).unwrap();
    assert_ne!(ct1, ct3);
}
