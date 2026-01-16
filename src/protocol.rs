use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::hash::{enc_point, enc_scalar, g0, g1, hcom, hsig};
use crate::nizk::{sig_prove, sig_verify, Proof};
use crate::shamir::lagrange_coeff;
use crate::types::{
    CommitmentMessage, OpeningMessage, Params, PartialSignature, PublicKeyShare, SecretKeyShare,
    Signature, SignerState,
};

fn dec_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
}

fn dec_scalar(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

/// Helper: normalize mu vector as Vec<(id, mu)> sorted by id.
fn normalize_mu_vec(mut mu: Vec<(u32, [u8; 32])>) -> Vec<(u32, [u8; 32])> {
    mu.sort_by_key(|(i, _)| *i);
    mu
}

/// Sig1: commitment phase.
/// - sample rho_i (32 bytes) and a_i (scalar)
/// - compute B_i = g*a_i + F0(rho_i)*r(i) + F1(rho_i)*u(i)
/// - mu_i = Hcom(i, rho_i, B_i)
pub fn sig1(par: &Params, i: u32, sk_i: &SecretKeyShare) -> (CommitmentMessage, SignerState) {
    let a_i = crate::randutil::random_scalar();

    let rho_i: [u8; 32] = rand::random();


    let h0 = crate::hash::f0(&rho_i);
    let h1 = crate::hash::f1(&rho_i);
    let b_i = par.g * a_i + h0 * sk_i.r + h1 * sk_i.u;

    let mu_i = hcom(i, &rho_i, &b_i);

    let st = SignerState {
        i,
        a_i,
        rho_i,
        b_i,
        a_i_point: RistrettoPoint::identity(),
        mu_vec: Vec::new(),
        g0: RistrettoPoint::identity(),
        g1: RistrettoPoint::identity(),
    };

    (CommitmentMessage { i, mu_i }, st)
}

/// Sig2: opening phase.
/// - compute G0,G1 from (m, mu_vec)
/// - compute A_i = g*a_i + G0*r(i) + G1*u(i)
/// - proof π_i binds (pk_i, A_i, B_i, rho_i, G0, G1)
pub fn sig2(
    par: &Params,
    message: &[u8],
    i: u32,
    mu_vec: &[(u32, [u8; 32])],
    pk_i: &PublicKeyShare,
    sk_i: &SecretKeyShare,
    st: &SignerState,
) -> (OpeningMessage, SignerState) {
    let mu_vec = normalize_mu_vec(mu_vec.to_vec());
    let g0p = g0(message, &mu_vec);
    let g1p = g1(message, &mu_vec);

    let a_i_point = par.g * st.a_i + g0p * sk_i.r + g1p * sk_i.u;

    let proof: Proof = sig_prove(
        par,
        &pk_i.pk_i,
        &a_i_point,
        &st.b_i,
        &g0p,
        &g1p,
        &st.rho_i,
        &st.a_i,
        sk_i,
    );

    let msg = OpeningMessage {
        i,
        // kept only for debugging symmetry; not required by protocol
        a_i: enc_scalar(&st.a_i),
        a_point: enc_point(&a_i_point),
        rho_i: st.rho_i,
        b_point: enc_point(&st.b_i),
        proof,
    };

    let st2 = SignerState {
        i,
        a_i: st.a_i,
        rho_i: st.rho_i,
        b_i: st.b_i,
        a_i_point,
        mu_vec,
        g0: g0p,
        g1: g1p,
    };

    (msg, st2)
}

/// Sig3: share-signing phase (practical).
/// Checks:
/// 1) commitment correctness: mu_j == Hcom(j, rho_j, B_j)
/// 2) NIZK verifies for each signer j
/// Then compute:
/// - A_hat = Σ_j L_{j,SS} * A_j
/// - c = Hsig(A_hat, pk_joint, m)
/// - z_i = L_{i,SS} * (a_i + c*s(i))
pub fn sig3_with_pk(
    par: &Params,
    message: &[u8],
    ss: &[u32],
    i: u32,
    pk_joint: &RistrettoPoint,
    pk_shares: &[(u32, RistrettoPoint)],
    sk_i: &SecretKeyShare,
    st: &SignerState,
    commitments: &[(u32, [u8; 32])],
    openings: &[OpeningMessage],
) -> Option<PartialSignature> {
    let mu_vec = normalize_mu_vec(commitments.to_vec());
    let g0p = g0(message, &mu_vec);
    let g1p = g1(message, &mu_vec);

    // verify each opening
    for om in openings {
        let bj = dec_point(&om.b_point)?;
        let muj_expected = hcom(om.i, &om.rho_i, &bj);

        let muj = mu_vec
            .iter()
            .find(|(id, _)| *id == om.i)
            .map(|x| x.1)?;
        if muj != muj_expected {
            return None;
        }

        let aj = dec_point(&om.a_point)?;
        let pkj = pk_shares
            .iter()
            .find(|(id, _)| *id == om.i)
            .map(|x| x.1)?;

        let ok = sig_verify(par, &pkj, &aj, &bj, &g0p, &g1p, &om.rho_i, &om.proof);
        if !ok {
            return None;
        }
    }

    // A_hat = Σ_j L_{j,SS} * A_j
    let mut a_hat = RistrettoPoint::identity();
    for om in openings {
        let aj = dec_point(&om.a_point)?;
        let lj = lagrange_coeff(om.i, ss);
        a_hat += aj * lj;
    }

    let c = hsig(&a_hat, pk_joint, message);

    let li = lagrange_coeff(i, ss);
    let z_i = li * (st.a_i + c * sk_i.s);

    Some(PartialSignature {
        i,
        z_i: enc_scalar(&z_i),
    })
}

/// Combine:
/// - A_hat from openings
/// - z = Σ z_i
pub fn combine(ss: &[u32], openings: &[OpeningMessage], sigshares: &[PartialSignature]) -> Option<Signature> {
    let mut a_hat = RistrettoPoint::identity();
    for om in openings {
        let aj = dec_point(&om.a_point)?;
        let lj = lagrange_coeff(om.i, ss);
        a_hat += aj * lj;
    }

    let mut z = Scalar::ZERO;
    for ps in sigshares {
        z += dec_scalar(&ps.z_i);
    }

    Some(Signature { A_hat: a_hat, z })
}

/// Verify Schnorr:
/// check g*z == A_hat + pk*c, where c = Hsig(A_hat, pk, m)
pub fn verify(par: &Params, pk_joint: &RistrettoPoint, message: &[u8], sig: &Signature) -> bool {
    let c = hsig(&sig.A_hat, pk_joint, message);
    let left = par.g * sig.z;
    let right = sig.A_hat + (*pk_joint) * c;
    left == right
}
