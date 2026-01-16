// src/commitment.rs
//
// Verifiable combining layer (Pedersen commitments, homomorphic aggregation)
//
// Paper-faithful interface separation:
// - CommitmentMsg: public commitment C_i sent to combiner/verifiers
// - CommitmentOpening: local opening r_i kept by signer (or escrowed as the protocol dictates)
// - Combiner can aggregate commitments and (optionally) provide aggregate opening r = Σ r_i
// - Anyone can verify aggregate correctness: C ?= g*z + h*r

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CommitmentMsg {
    pub i: u32,
    pub c_i: [u8; 32], // compressed RistrettoPoint
}

#[derive(Clone, Debug)]
pub struct CommitmentOpening {
    pub i: u32,
    pub r_i: Scalar,
}

/// Deterministically derive a secondary generator h from g (prototype-grade).
/// This MUST be domain-separated from all other hashes in the system.
pub fn derive_h_from_g(g: &RistrettoPoint) -> RistrettoPoint {
    let mut h = Sha256::new();
    h.update(b"VC::derive_h_from_g");
    h.update(g.compress().as_bytes());
    let digest = h.finalize();

    // Map 32-byte digest to 64-byte "uniform" input for from_uniform_bytes.
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&digest);
    // second half is another hash for cheap expansion
    let digest2 = Sha256::digest(&digest);
    wide[32..].copy_from_slice(&digest2);

    RistrettoPoint::from_uniform_bytes(&wide)
}

fn random_scalar() -> Scalar {
    // sample 64 bytes and reduce mod ℓ
    let buf: [u8; 64] = rand::random();
    Scalar::from_bytes_mod_order_wide(&buf)
}

/// Commit to share z_i: C_i = g*z_i + h*r_i.
/// Returns (public message, local opening).
pub fn commit_z(
    i: u32,
    g: &RistrettoPoint,
    h: &RistrettoPoint,
    z_i: &Scalar,
) -> (CommitmentMsg, CommitmentOpening) {
    let r_i = random_scalar();
    let c_point = g * (*z_i) + h * r_i;

    (
        CommitmentMsg {
            i,
            c_i: c_point.compress().to_bytes(),
        },
        CommitmentOpening { i, r_i },
    )
}

/// Aggregate public commitments: C = Σ C_i.
pub fn aggregate_commitments(coms: &[CommitmentMsg]) -> [u8; 32] {
    let mut c_sum = RistrettoPoint::identity();

    for c in coms {
        let cp = CompressedRistretto(c.c_i)
            .decompress()
            .expect("bad commitment point");
        c_sum += cp;
    }

    c_sum.compress().to_bytes()
}

/// Aggregate openings (if the protocol reveals/provides them): r = Σ r_i.
/// NOTE: whether r is public, escrowed, or proven via ZK depends on the paper.
/// This function just computes the sum given openings.
pub fn aggregate_openings(ops: &[CommitmentOpening]) -> [u8; 32] {
    let mut r_sum = Scalar::ZERO;
    for o in ops {
        r_sum += o.r_i;
    }
    r_sum.to_bytes()
}

/// Verify aggregate commitment against final z:
/// check C == g*z + h*r.
pub fn verify_aggregate(
    g: &RistrettoPoint,
    h: &RistrettoPoint,
    c_agg_bytes: &[u8; 32],
    z: &Scalar,
    r_agg_bytes: &[u8; 32],
) -> bool {
    let c_agg = CompressedRistretto(*c_agg_bytes)
        .decompress()
        .expect("bad agg commitment");
    let r_agg = Scalar::from_bytes_mod_order(*r_agg_bytes);

    let expected = g * (*z) + h * r_agg;
    c_agg == expected
}
