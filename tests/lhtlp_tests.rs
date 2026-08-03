#![cfg(feature = "concrete-lhtlp")]

use openssl::bn::BigNum;
use threshold_signature::crypto::lhtlp::LhtlpBackend;

fn small_backend(delta: u64) -> LhtlpBackend {
    LhtlpBackend::setup(512, delta).expect("setup")
}

fn bn(v: u32) -> BigNum {
    BigNum::from_u32(v).unwrap()
}

#[test]
fn psolve_pgen_recovers_plaintext() {
    let backend = small_backend(8);
    let puzzle = backend.pgen(&bn(42)).unwrap();
    let (opened, squarings) = backend.psolve(&puzzle).unwrap();
    assert_eq!(BigNum::from_slice(&opened).unwrap(), bn(42));
    assert_eq!(squarings, 8);
}

#[test]
fn homomorphic_evaluation_opens_to_sum() {
    let backend = small_backend(6);
    let puzzles = [backend.pgen(&bn(7)).unwrap(), backend.pgen(&bn(9)).unwrap()];
    let aggregate = backend.peval(&puzzles).unwrap();
    let (opened, _) = backend.psolve(&aggregate).unwrap();
    assert_eq!(BigNum::from_slice(&opened).unwrap(), bn(16));
}

#[test]
fn deterministic_pgen_replays_from_witness_randomness() {
    let backend = small_backend(6);
    let scalar = bn(21);
    let randomness = bn(37);
    let p1 = backend.pgen_with_randomness(&scalar, &randomness).unwrap();
    let p2 = backend
        .pgen_with_randomness_bytes(&scalar.to_vec(), &randomness.to_vec())
        .unwrap();
    assert_eq!(p1, p2);
    let (opened, _) = backend.psolve(&p1).unwrap();
    assert_eq!(BigNum::from_slice(&opened).unwrap(), scalar);
}

#[test]
fn serialization_roundtrip_is_canonical() {
    let backend = small_backend(4);
    let puzzle = backend.pgen(&bn(11)).unwrap();
    let encoded = backend.encode_puzzle(&puzzle).unwrap();
    let decoded = backend.decode_puzzle_bytes(&encoded).unwrap();
    assert_eq!(puzzle, decoded);
}

#[test]
fn malformed_puzzle_is_rejected() {
    let backend = small_backend(4);
    let mut puzzle = backend.pgen(&bn(11)).unwrap();
    puzzle.u[0] ^= 0x80;
    assert!(backend.psolve(&puzzle).is_err());
}

#[test]
fn changed_delta_changes_opening() {
    let backend = small_backend(4);
    let mut params = backend.params().clone();
    let puzzle = backend.pgen(&bn(17)).unwrap();
    params.delta += 1;
    let changed = LhtlpBackend::from_params(params).unwrap();
    assert!(changed.psolve(&puzzle).is_err());
}
