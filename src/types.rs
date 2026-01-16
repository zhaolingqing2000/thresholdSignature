use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct Params {
    pub n: usize,
    pub t: usize,
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
    pub v: RistrettoPoint,
}

#[derive(Clone, Debug)]
pub struct SecretKeyShare {
    pub s: Scalar,
    pub r: Scalar,
    pub u: Scalar,
}

#[derive(Clone, Debug)]
pub struct PublicKeyShare {
    pub pk_i: RistrettoPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentMessage {
    pub i: u32,
    pub mu_i: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpeningMessage {
    pub i: u32,
    pub a_i: [u8; 32],      // NOT sent; stored in state only (keep layout simple)
    pub a_point: [u8; 32],  // Ai compressed
    pub rho_i: [u8; 32],
    pub b_point: [u8; 32],  // Bi compressed
    pub proof: super::nizk::Proof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialSignature {
    pub i: u32,
    pub z_i: [u8; 32], // Scalar bytes
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub A_hat: RistrettoPoint,
    pub z: Scalar,
}

/// Local signer state across rounds
#[derive(Clone, Debug)]
pub struct SignerState {
    pub i: u32,
    pub a_i: Scalar,
    pub rho_i: [u8; 32],
    pub b_i: RistrettoPoint,

    // after Sig2
    pub a_i_point: RistrettoPoint,
    pub mu_vec: Vec<(u32, [u8; 32])>,
    pub g0: RistrettoPoint,
    pub g1: RistrettoPoint,
}

// =============================
// TiMTAPS-style extensions types
// =============================

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TimedShare {
    pub i: u32,
    pub timed: crate::timed::TimedCiphertext,
}

/// Public verifiable combining commitment message (C_i only).
/// Opening r_i must NOT be carried in public messages (paper-faithful separation).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VerifiableCommitmentMsg {
    pub i: u32,
    pub c_i: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct TracingBundle {
    pub trace_ct: crate::tracing::TraceCiphertext,
}
