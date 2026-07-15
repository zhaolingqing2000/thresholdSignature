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

    /// A_i = g^{a_i} g0^{r_i} g1^{u_i}
    pub a_point: [u8; 32],

    /// opening of commitment
    pub rho_i: [u8; 32],

    /// B_i = g^{a_i} F0(rho_i)^{r_i} F1(rho_i)^{u_i}
    pub b_point: [u8; 32],

    pub pi_open: crate::nizk::Proof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessMessage {
    pub i: u32,

    /// W_i = g^{z_i}
    pub w_point: [u8; 32],

    pub pi_wit: crate::nizk::WitnessProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialSignature {
    pub i: u32,
    pub z_i: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub a_hat: RistrettoPoint,
    pub z: Scalar,
}

#[derive(Clone, Debug)]
pub struct TranscriptEntry {
    pub i: u32,
    pub mu_i: [u8; 32],
    pub rho_i: [u8; 32],
    pub b_i: RistrettoPoint,
    pub a_i: RistrettoPoint,
    pub w_i: RistrettoPoint,
    pub pi_open: crate::nizk::Proof,
    pub pi_wit: crate::nizk::WitnessProof,
}

#[derive(Clone, Debug)]
pub struct AggTranscript {
    pub sid: [u8; 32],
    pub signer_set: Vec<u32>,
    pub message: Vec<u8>,
    pub mu: Vec<(u32, [u8; 32])>,
    pub entries: Vec<TranscriptEntry>,
    pub signature: Option<Signature>,
    pub aggregate_witness: Option<RistrettoPoint>,
}

/// signer state across protocol rounds
#[derive(Clone, Debug)]
pub struct SignerState {
    pub i: u32,

    pub a_i: Scalar,
    pub rho_i: [u8; 32],
    pub b_i: RistrettoPoint,

    // filled after Sig2
    pub a_i_point: RistrettoPoint,
    pub mu_vec: Vec<(u32, [u8; 32])>,
    pub g0: RistrettoPoint,
    pub g1: RistrettoPoint,
}

//
// =============================
// Timed disclosure (TiMTAPS)
// =============================
//

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimedShare {
    pub i: u32,
    pub timed: crate::timed::TimedCiphertext,
}

//
// =============================
// Verifiable combining commitment
// =============================
//

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiableCommitmentMsg {
    pub i: u32,

    /// commitment value C_i
    pub c_i: [u8; 32],
}

//
// =============================
// Tracing
// =============================
//

#[derive(Clone, Debug)]
pub struct TracingBundle {
    pub trace_ct: crate::tracing::TraceCiphertext,
}

pub struct ExperimentConfig {
    pub n: usize,
    pub t: usize,
    pub enable_vc: bool,
    pub enable_timed: bool,
    pub enable_tracing: bool,
    pub timed_t: u64,
    pub tracing_n: usize,
    pub tracing_t: usize,
    pub msg: Vec<u8>,
    pub timed_aad: Vec<u8>,
    pub trace_label: Vec<u8>,
}
