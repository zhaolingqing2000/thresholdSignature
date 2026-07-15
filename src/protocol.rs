use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::hash::{enc_point, enc_scalar, g0, g1, hbind, hsig, hsig_bound};
use crate::nizk::{sig_prove, sig_verify, witness_prove, witness_verify};
use crate::shamir::lagrange_coeff;
use crate::types::{
    AggTranscript, CommitmentMessage, OpeningMessage, Params, PartialSignature, PublicKeyShare,
    SecretKeyShare, Signature, SignerState, TranscriptEntry, WitnessMessage,
};

fn dec_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
}

fn dec_scalar(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

fn normalize_signer_set(mut signer_set: Vec<u32>) -> Vec<u32> {
    signer_set.sort_unstable();
    signer_set
}

fn normalize_mu_vec(mut mu: Vec<(u32, [u8; 32])>) -> Vec<(u32, [u8; 32])> {
    mu.sort_by_key(|(i, _)| *i);
    mu
}

fn pk_for(pk_shares: &[PublicKeyShare], i: u32) -> Option<RistrettoPoint> {
    pk_shares.get(i as usize - 1).map(|pk| pk.pk_i)
}

fn recompute_a_hat(signer_set: &[u32], entries: &[TranscriptEntry]) -> RistrettoPoint {
    let mut a_hat = RistrettoPoint::identity();
    for entry in entries {
        let li = lagrange_coeff(entry.i, signer_set);
        a_hat += entry.a_i * li;
    }
    a_hat
}

/// Fig.2 lines 3-8: signer commitment and Hbind posting.
pub fn sig1(
    par: &Params,
    sid: &[u8; 32],
    signer_set: &[u32],
    message: &[u8],
    i: u32,
    sk_i: &SecretKeyShare,
) -> (CommitmentMessage, SignerState) {
    let a_i = crate::randutil::random_scalar();
    let rho_i: [u8; 32] = rand::random();

    let h0 = crate::hash::f0(&rho_i);
    let h1 = crate::hash::f1(&rho_i);
    let b_i = par.g * a_i + h0 * sk_i.r + h1 * sk_i.u;
    let mu_i = hbind(sid, signer_set, message, i, &rho_i, &b_i);

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

/// Fig.2 lines 10-14: open B_i, compute A_i, and generate pi_open.
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
    let pi_open = sig_prove(
        par, &pk_i.pk_i, &a_i_point, &st.b_i, &g0p, &g1p, &st.rho_i, &st.a_i, sk_i,
    );

    let msg = OpeningMessage {
        i,
        a_point: enc_point(&a_i_point),
        rho_i: st.rho_i,
        b_point: enc_point(&st.b_i),
        pi_open,
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

/// Fig.2 lines 15-22: compute z_i, W_i = g^{z_i}, and pi_wit.
#[allow(clippy::too_many_arguments)]
pub fn sig3_with_pk(
    par: &Params,
    sid: &[u8; 32],
    message: &[u8],
    signer_set: &[u32],
    i: u32,
    pk_joint: &RistrettoPoint,
    pk_shares: &[PublicKeyShare],
    sk_i: &SecretKeyShare,
    st: &SignerState,
    openings: &[OpeningMessage],
) -> Option<(PartialSignature, WitnessMessage)> {
    let mut a_hat = RistrettoPoint::identity();
    for om in openings {
        let aj = dec_point(&om.a_point)?;
        let lj = lagrange_coeff(om.i, signer_set);
        a_hat += aj * lj;
    }
    let c = hsig_bound(sid, signer_set, &a_hat, pk_joint, message);
    let li = lagrange_coeff(i, signer_set);
    let z_i = li * (st.a_i + c * sk_i.s);
    let w_i = par.g * z_i;

    let pk_i = pk_for(pk_shares, i)?;
    let pi_wit = witness_prove(
        par,
        &pk_i,
        &st.a_i_point,
        &st.b_i,
        &w_i,
        &st.g0,
        &st.g1,
        &st.rho_i,
        &c,
        &li,
        &st.a_i,
        sk_i,
    );

    Some((
        PartialSignature {
            i,
            z_i: enc_scalar(&z_i),
        },
        WitnessMessage {
            i,
            w_point: enc_point(&w_i),
            pi_wit,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
fn sig3_with_precomputed(
    par: &Params,
    i: u32,
    pk_i: &RistrettoPoint,
    sk_i: &SecretKeyShare,
    st: &SignerState,
    c: &Scalar,
    lagrange: &Scalar,
) -> (PartialSignature, WitnessMessage) {
    let z_i = (*lagrange) * (st.a_i + (*c) * sk_i.s);
    let w_i = par.g * z_i;
    let pi_wit = witness_prove(
        par,
        pk_i,
        &st.a_i_point,
        &st.b_i,
        &w_i,
        &st.g0,
        &st.g1,
        &st.rho_i,
        c,
        lagrange,
        &st.a_i,
        sk_i,
    );

    (
        PartialSignature {
            i,
            z_i: enc_scalar(&z_i),
        },
        WitnessMessage {
            i,
            w_point: enc_point(&w_i),
            pi_wit,
        },
    )
}

/// Fig.2: run signing and transcript-level aggregation witness generation.
pub fn gargos_sign_and_bind(
    par: &Params,
    message: &[u8],
    signer_set: &[u32],
    pk_joint: &RistrettoPoint,
    pk_shares: &[PublicKeyShare],
    sk_shares: &[SecretKeyShare],
) -> Option<(AggTranscript, Vec<PartialSignature>)> {
    let signer_set = normalize_signer_set(signer_set.to_vec());
    let sid: [u8; 32] = rand::random();

    let mut commits = Vec::with_capacity(signer_set.len());
    let mut states = Vec::with_capacity(signer_set.len());
    for &i in &signer_set {
        let sk_i = sk_shares.get(i as usize - 1)?;
        let (commit, state) = sig1(par, &sid, &signer_set, message, i, sk_i);
        commits.push((commit.i, commit.mu_i));
        states.push(state);
    }
    let mu = normalize_mu_vec(commits);

    let mut openings = Vec::with_capacity(signer_set.len());
    let mut states2 = Vec::with_capacity(signer_set.len());
    for (idx, &i) in signer_set.iter().enumerate() {
        let pk_i = pk_shares.get(i as usize - 1)?;
        let sk_i = sk_shares.get(i as usize - 1)?;
        let (opening, state) = sig2(par, message, i, &mu, pk_i, sk_i, &states[idx]);
        openings.push(opening);
        states2.push(state);
    }

    let mut a_hat = RistrettoPoint::identity();
    let mut lagranges = Vec::with_capacity(signer_set.len());
    for opening in &openings {
        let li = lagrange_coeff(opening.i, &signer_set);
        let a_i = dec_point(&opening.a_point)?;
        a_hat += a_i * li;
        lagranges.push((opening.i, li));
    }
    let c = hsig_bound(&sid, &signer_set, &a_hat, pk_joint, message);

    let mut partials = Vec::with_capacity(signer_set.len());
    let mut witnesses = Vec::with_capacity(signer_set.len());
    for (idx, &i) in signer_set.iter().enumerate() {
        let pk_i = pk_for(pk_shares, i)?;
        let sk_i = sk_shares.get(i as usize - 1)?;
        let li = lagranges
            .iter()
            .find(|(id, _)| *id == i)
            .map(|(_, li)| *li)?;
        let (partial, witness) = sig3_with_precomputed(par, i, &pk_i, sk_i, &states2[idx], &c, &li);
        partials.push(partial);
        witnesses.push(witness);
    }

    let mut entries = Vec::with_capacity(signer_set.len());
    for (opening, witness) in openings.into_iter().zip(witnesses.into_iter()) {
        let mu_i = mu.iter().find(|(id, _)| *id == opening.i)?.1;
        entries.push(TranscriptEntry {
            i: opening.i,
            mu_i,
            rho_i: opening.rho_i,
            b_i: dec_point(&opening.b_point)?,
            a_i: dec_point(&opening.a_point)?,
            w_i: dec_point(&witness.w_point)?,
            pi_open: opening.pi_open,
            pi_wit: witness.pi_wit,
        });
    }

    Some((
        AggTranscript {
            sid,
            signer_set,
            message: message.to_vec(),
            mu,
            entries,
            signature: None,
            aggregate_witness: None,
        },
        partials,
    ))
}

/// Fig.3: aggregate response shares, verify local witnesses, and post sigma,Y.
pub fn aggregate_and_verify(
    par: &Params,
    pk_joint: &RistrettoPoint,
    pk_shares: &[PublicKeyShare],
    mut transcript: AggTranscript,
    partials: &[PartialSignature],
) -> Option<AggTranscript> {
    let g0p = g0(&transcript.message, &transcript.mu);
    let g1p = g1(&transcript.message, &transcript.mu);
    let a_hat = recompute_a_hat(&transcript.signer_set, &transcript.entries);
    let c = hsig_bound(
        &transcript.sid,
        &transcript.signer_set,
        &a_hat,
        pk_joint,
        &transcript.message,
    );

    for entry in &transcript.entries {
        let expected_mu = hbind(
            &transcript.sid,
            &transcript.signer_set,
            &transcript.message,
            entry.i,
            &entry.rho_i,
            &entry.b_i,
        );
        if expected_mu != entry.mu_i {
            return None;
        }

        let pk_i = pk_for(pk_shares, entry.i)?;
        if !sig_verify(
            par,
            &pk_i,
            &entry.a_i,
            &entry.b_i,
            &g0p,
            &g1p,
            &entry.rho_i,
            &entry.pi_open,
        ) {
            return None;
        }

        let li = lagrange_coeff(entry.i, &transcript.signer_set);
        if !witness_verify(
            par,
            &pk_i,
            &entry.a_i,
            &entry.b_i,
            &entry.w_i,
            &g0p,
            &g1p,
            &entry.rho_i,
            &c,
            &li,
            &entry.pi_wit,
        ) {
            return None;
        }

        let z_i = partials
            .iter()
            .find(|p| p.i == entry.i)
            .map(|p| dec_scalar(&p.z_i))?;
        if par.g * z_i != entry.w_i {
            return None;
        }
    }

    let mut z = Scalar::ZERO;
    for partial in partials {
        z += dec_scalar(&partial.z_i);
    }

    let mut y = RistrettoPoint::identity();
    for entry in &transcript.entries {
        y += entry.w_i;
    }

    if par.g * z != y {
        return None;
    }
    if par.g * z != a_hat + (*pk_joint) * c {
        return None;
    }

    transcript.signature = Some(Signature { a_hat, z });
    transcript.aggregate_witness = Some(y);
    Some(transcript)
}

/// Fig.4: public verification of final Schnorr validity and witness aggregation.
pub fn verify_aggregate_transcript(
    par: &Params,
    pk_joint: &RistrettoPoint,
    pk_shares: &[PublicKeyShare],
    message: &[u8],
    transcript: &AggTranscript,
) -> bool {
    if transcript.message != message {
        return false;
    }

    let sig = match &transcript.signature {
        Some(sig) => sig,
        None => return false,
    };
    let y = match transcript.aggregate_witness {
        Some(y) => y,
        None => return false,
    };

    let a_hat = recompute_a_hat(&transcript.signer_set, &transcript.entries);
    if sig.a_hat != a_hat {
        return false;
    }

    let c = hsig_bound(
        &transcript.sid,
        &transcript.signer_set,
        &sig.a_hat,
        pk_joint,
        message,
    );
    let g0p = g0(message, &transcript.mu);
    let g1p = g1(message, &transcript.mu);

    for entry in &transcript.entries {
        let expected_mu = hbind(
            &transcript.sid,
            &transcript.signer_set,
            message,
            entry.i,
            &entry.rho_i,
            &entry.b_i,
        );
        if expected_mu != entry.mu_i {
            return false;
        }

        let pk_i = match pk_for(pk_shares, entry.i) {
            Some(pk) => pk,
            None => return false,
        };
        if !sig_verify(
            par,
            &pk_i,
            &entry.a_i,
            &entry.b_i,
            &g0p,
            &g1p,
            &entry.rho_i,
            &entry.pi_open,
        ) {
            return false;
        }

        let li = lagrange_coeff(entry.i, &transcript.signer_set);
        if !witness_verify(
            par,
            &pk_i,
            &entry.a_i,
            &entry.b_i,
            &entry.w_i,
            &g0p,
            &g1p,
            &entry.rho_i,
            &c,
            &li,
            &entry.pi_wit,
        ) {
            return false;
        }
    }

    let mut y_prime = RistrettoPoint::identity();
    for entry in &transcript.entries {
        y_prime += entry.w_i;
    }
    if y != y_prime {
        return false;
    }

    let left = par.g * sig.z;
    left == y && left == sig.a_hat + (*pk_joint) * c
}

pub fn combine(
    signer_set: &[u32],
    openings: &[OpeningMessage],
    partials: &[PartialSignature],
) -> Option<Signature> {
    let mut a_hat = RistrettoPoint::identity();
    for opening in openings {
        let a_i = dec_point(&opening.a_point)?;
        let li = lagrange_coeff(opening.i, signer_set);
        a_hat += a_i * li;
    }

    let mut z = Scalar::ZERO;
    for partial in partials {
        z += dec_scalar(&partial.z_i);
    }

    Some(Signature { a_hat, z })
}

pub fn verify(par: &Params, pk_joint: &RistrettoPoint, message: &[u8], sig: &Signature) -> bool {
    let c = hsig(&sig.a_hat, pk_joint, message);
    par.g * sig.z == sig.a_hat + (*pk_joint) * c
}
