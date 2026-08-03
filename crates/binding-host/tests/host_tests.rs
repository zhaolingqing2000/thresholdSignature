use binding_core::{
    BindingPublicParams, BindingStatement, BindingTranscript, BindingWitness, CanonicalBytes,
    PROTOCOL_VERSION,
};
use binding_host::{backend_manifest, NizkBackendError, Sp1NizkSetup};

fn sample() -> (BindingPublicParams, BindingStatement, BindingWitness) {
    let n = 33u128;
    let n_squared = n * n;
    let g_t = 4u128;
    let h_t = 16u128;
    let (t_z, z, r_z) = small_lhtlp_puzzle(n, n_squared, g_t, h_t, 5, 7);
    let (t_tau, tau, r_tau) = small_lhtlp_puzzle(n, n_squared, g_t, h_t, 3, 11);
    let pp = BindingPublicParams {
        pp_digest: vec![1u8; 64],
        ell_max: 8,
        threshold: 2,
        gargos_n: 1,
        protocol_version: PROTOCOL_VERSION.to_vec(),
        g: [0u8; 32],
        h: [0u8; 32],
        v: [0u8; 32],
        public_key: [0u8; 32],
        g_c: [0u8; 32],
        h_c: [0u8; 32],
        g_n: [0u8; 32],
        registered_signers: Vec::new(),
        ibe_public_key: CanonicalBytes { bytes: vec![1] },
        lhtlp_delta: 1,
        lhtlp_n: CanonicalBytes {
            bytes: fixed_u128(n, 384),
        },
        lhtlp_n_squared: CanonicalBytes {
            bytes: fixed_u128(n_squared, 768),
        },
        lhtlp_g_t: CanonicalBytes {
            bytes: fixed_u128(g_t, 384),
        },
        lhtlp_h_t: CanonicalBytes {
            bytes: fixed_u128(h_t, 384),
        },
    };
    let statement = BindingStatement {
        d: [2u8; 32],
        m: b"message".to_vec(),
        hat_a: [3u8; 32],
        ell: 1,
        signer_index: 1,
        x_i: [3u8; 32],
        n_i: [3u8; 32],
        c_i: [4u8; 32],
        t_i_z: CanonicalBytes { bytes: t_z },
        t_i_tau: CanonicalBytes { bytes: t_tau },
        e_i: CanonicalBytes { bytes: vec![7] },
        nu_i: [8u8; 32],
    };
    let witness = BindingWitness {
        signer_set: vec![1],
        signer_index: 1,
        transcript: BindingTranscript {
            m: b"message".to_vec(),
            signer_set: vec![1],
            mu_vector: Vec::new(),
            entries: Vec::new(),
            a_hat: [3u8; 32],
        },
        a_i: [1u8; 32],
        s_i: [2u8; 32],
        r_i: [3u8; 32],
        u_i: [4u8; 32],
        z_i: [5u8; 32],
        tau_i: [6u8; 32],
        eta_i: [7u8; 32],
        legacy_transcript: CanonicalBytes { bytes: vec![9] },
        secret_relation: CanonicalBytes { bytes: tau },
        response_relation: CanonicalBytes { bytes: z },
        lhtlp_randomness_z: CanonicalBytes { bytes: r_z },
        lhtlp_randomness_tau: CanonicalBytes { bytes: r_tau },
        ibe_randomness: CanonicalBytes { bytes: vec![14] },
        nullifier_randomness: CanonicalBytes { bytes: vec![15] },
    };
    (pp, statement, witness)
}

fn fixed_u128(value: u128, width: usize) -> Vec<u8> {
    let mut out = vec![0u8; width];
    let bytes = value.to_be_bytes();
    let take = width.min(bytes.len());
    out[width - take..].copy_from_slice(&bytes[bytes.len() - take..]);
    out
}

fn small_lhtlp_puzzle(
    n: u128,
    n_squared: u128,
    g_t: u128,
    h_t: u128,
    s: u128,
    r: u128,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let u = mod_pow(g_t, r, n);
    let v_lhs = mod_pow(h_t, r * n, n_squared);
    let v_rhs = mod_pow(1 + n, s, n_squared);
    let v = (v_lhs * v_rhs) % n_squared;
    let mut puzzle = fixed_u128(u, 384);
    puzzle.extend_from_slice(&fixed_u128(v, 768));
    (puzzle, fixed_u128(s, 1), fixed_u128(r, 1))
}

fn mod_pow(mut base: u128, mut exp: u128, modulus: u128) -> u128 {
    let mut acc = 1u128;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = (acc * base) % modulus;
        }
        base = (base * base) % modulus;
        exp >>= 1;
    }
    acc
}

#[test]
fn mock_backend_is_forbidden_by_setup() {
    if cfg!(feature = "mock-nizk") {
        assert_eq!(
            Sp1NizkSetup::setup(),
            Err(NizkBackendError::MockBackendForbidden)
        );
    }
}

#[test]
fn full_relation_unavailable_prevents_proving() {
    if cfg!(all(feature = "sp1-nizk", not(feature = "mock-nizk"))) {
        let (pp, statement, mut witness) = sample();
        let setup = Sp1NizkSetup::setup().unwrap();
        let err = setup
            .prover()
            .prove(&pp, &statement, &mut witness)
            .unwrap_err();
        assert!(matches!(err, NizkBackendError::FullRelationUnavailable(_)));
        assert!(witness.ibe_randomness.bytes.iter().all(|b| *b == 0));
    }
}

#[test]
fn manifest_never_claims_concrete_proof_before_full_relation() {
    assert!(backend_manifest().contains("INVALID BENCHMARK"));
}
