#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]

extern crate alloc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use alloc::vec::Vec;
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Encoding, U3072, U6144};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ibe::kem::cgw_fo::CGWFO;
use ibe::kem::IBKEM;
use ibe::{Compress, Derive};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub const PROTOCOL_VERSION: &[u8] = b"GARGOS-BINDING-SP1-v1";
pub const STATEMENT_DIGEST_LABEL: &[u8] = b"GARGOS-BINDING-STATEMENT-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingPublicParams {
    pub pp_digest: Vec<u8>,
    pub ell_max: u32,
    pub threshold: u32,
    pub gargos_n: u32,
    pub protocol_version: Vec<u8>,
    pub g: [u8; 32],
    pub h: [u8; 32],
    pub v: [u8; 32],
    pub public_key: [u8; 32],
    pub g_c: [u8; 32],
    pub h_c: [u8; 32],
    pub g_n: [u8; 32],
    pub registered_signers: Vec<RegisteredSigner>,
    pub ibe_public_key: CanonicalBytes,
    pub lhtlp_delta: u64,
    pub lhtlp_n: CanonicalBytes,
    pub lhtlp_n_squared: CanonicalBytes,
    pub lhtlp_g_t: CanonicalBytes,
    pub lhtlp_h_t: CanonicalBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingStatement {
    pub d: [u8; 32],
    pub m: Vec<u8>,
    pub hat_a: [u8; 32],
    pub ell: u32,
    pub signer_index: u32,
    pub x_i: [u8; 32],
    pub n_i: [u8; 32],
    pub c_i: [u8; 32],
    pub t_i_z: CanonicalBytes,
    pub t_i_tau: CanonicalBytes,
    pub e_i: CanonicalBytes,
    pub nu_i: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingWitness {
    pub signer_set: Vec<u32>,
    pub signer_index: u32,
    pub transcript: BindingTranscript,
    pub a_i: [u8; 32],
    pub s_i: [u8; 32],
    pub r_i: [u8; 32],
    pub u_i: [u8; 32],
    pub z_i: [u8; 32],
    pub tau_i: [u8; 32],
    pub eta_i: [u8; 32],
    pub legacy_transcript: CanonicalBytes,
    pub secret_relation: CanonicalBytes,
    pub response_relation: CanonicalBytes,
    pub lhtlp_randomness_z: CanonicalBytes,
    pub lhtlp_randomness_tau: CanonicalBytes,
    pub ibe_randomness: CanonicalBytes,
    pub nullifier_randomness: CanonicalBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalBytes {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredSigner {
    pub index: u32,
    pub x_i: [u8; 32],
    pub n_i: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingTranscript {
    pub m: Vec<u8>,
    pub signer_set: Vec<u32>,
    pub mu_vector: Vec<TranscriptMu>,
    pub entries: Vec<BindingTranscriptEntry>,
    pub a_hat: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptMu {
    pub i: u32,
    pub mu_i: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingTranscriptEntry {
    pub i: u32,
    pub mu_i: [u8; 32],
    pub rho_i: [u8; 32],
    pub b_i: [u8; 32],
    pub a_i: [u8; 32],
    pub x_i: [u8; 32],
    pub pi_gar: BindingGargosProof,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingGargosProof {
    pub xa: [u8; 32],
    pub xb: [u8; 32],
    pub xpk: [u8; 32],
    pub za: [u8; 32],
    pub zs: [u8; 32],
    pub zr: [u8; 32],
    pub zu: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingStage {
    StatementDigest,
    CommitmentAndNullifier,
    FullRelation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingError {
    InvalidProtocolVersion,
    InvalidPublicParameterDigest,
    EmptyMessage,
    EmptyOpaqueField,
    InvalidLhtlpParameter,
    InvalidLhtlpPuzzle,
    InvalidLhtlpWitness,
    LhtlpEquationMismatch,
    EllOutOfRange,
    SignerSetNotSorted,
    SignerSetLengthMismatch,
    SignerIndexMissing,
    DuplicateSignerIndex,
    InvalidRegisteredSigner,
    InvalidPointEncoding,
    InvalidScalarEncoding,
    TranscriptMismatch,
    CommitmentHashMismatch,
    GargosProofRejected,
    AggregateNonceMismatch,
    ResponseEquationMismatch,
    CommitmentEquationMismatch,
    IbeCiphertextMismatch,
    NullifierMismatch,
    FullRelationNotImplemented(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CycleBreakdown {
    pub parsing_cycles: u64,
    pub transcript_cycles: u64,
    pub gargos_cycles: u64,
    pub commitment_cycles: u64,
    pub ibe_cycles: u64,
    pub lhtlp_cycles: u64,
    pub total_cycles: u64,
}

impl CycleBreakdown {
    pub const fn stage_a_only() -> Self {
        Self {
            parsing_cycles: 0,
            transcript_cycles: 0,
            gargos_cycles: 0,
            commitment_cycles: 0,
            ibe_cycles: 0,
            lhtlp_cycles: 0,
            total_cycles: 0,
        }
    }
}

pub fn verify_binding_relation(
    pp: &BindingPublicParams,
    statement: &BindingStatement,
    witness: &BindingWitness,
    stage: BindingStage,
) -> Result<[u8; 64], BindingError> {
    validate_statement(pp, statement)?;
    validate_witness_shape(statement, witness)?;
    match stage {
        BindingStage::StatementDigest | BindingStage::CommitmentAndNullifier => {
            Ok(statement_digest(pp, statement))
        }
        BindingStage::FullRelation => {
            verify_full_binding_relation(pp, statement, witness)?;
            verify_lhtlp_pgen(
                pp,
                &statement.t_i_z.bytes,
                &witness.response_relation.bytes,
                &witness.lhtlp_randomness_z.bytes,
            )?;
            verify_lhtlp_pgen(
                pp,
                &statement.t_i_tau.bytes,
                &witness.secret_relation.bytes,
                &witness.lhtlp_randomness_tau.bytes,
            )?;
            verify_ibe_ciphertext(pp, statement, witness)?;
            Ok(statement_digest(pp, statement))
        }
    }
}

pub fn canonical_encode_statement(pp: &BindingPublicParams, x: &BindingStatement) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, b"pp_digest", &pp.pp_digest);
    put_u32(&mut out, b"ell_max", pp.ell_max);
    put_u32(&mut out, b"threshold", pp.threshold);
    put_u32(&mut out, b"gargos_n", pp.gargos_n);
    put_bytes(&mut out, b"protocol_version", &pp.protocol_version);
    put_bytes(&mut out, b"g", &pp.g);
    put_bytes(&mut out, b"h", &pp.h);
    put_bytes(&mut out, b"v", &pp.v);
    put_bytes(&mut out, b"public_key", &pp.public_key);
    put_bytes(&mut out, b"g_C", &pp.g_c);
    put_bytes(&mut out, b"h_C", &pp.h_c);
    put_bytes(&mut out, b"g_N", &pp.g_n);
    put_u32(
        &mut out,
        b"registered_len",
        pp.registered_signers.len() as u32,
    );
    for signer in &pp.registered_signers {
        put_u32(&mut out, b"registered_index", signer.index);
        put_bytes(&mut out, b"registered_X", &signer.x_i);
        put_bytes(&mut out, b"registered_N", &signer.n_i);
    }
    put_bytes(&mut out, b"ibe_public_key", &pp.ibe_public_key.bytes);
    put_u64(&mut out, b"lhtlp_delta", pp.lhtlp_delta);
    put_bytes(&mut out, b"lhtlp_N", &pp.lhtlp_n.bytes);
    put_bytes(&mut out, b"lhtlp_N_squared", &pp.lhtlp_n_squared.bytes);
    put_bytes(&mut out, b"lhtlp_g_T", &pp.lhtlp_g_t.bytes);
    put_bytes(&mut out, b"lhtlp_h_T", &pp.lhtlp_h_t.bytes);
    put_bytes(&mut out, b"d", &x.d);
    put_bytes(&mut out, b"m", &x.m);
    put_bytes(&mut out, b"hat_A", &x.hat_a);
    put_u32(&mut out, b"ell", x.ell);
    put_u32(&mut out, b"signer_index", x.signer_index);
    put_bytes(&mut out, b"X_i", &x.x_i);
    put_bytes(&mut out, b"N_i", &x.n_i);
    put_bytes(&mut out, b"C_i", &x.c_i);
    put_bytes(&mut out, b"T_i_z", &x.t_i_z.bytes);
    put_bytes(&mut out, b"T_i_tau", &x.t_i_tau.bytes);
    put_bytes(&mut out, b"E_i", &x.e_i.bytes);
    put_bytes(&mut out, b"nu_i", &x.nu_i);
    out
}

pub fn statement_digest(pp: &BindingPublicParams, x: &BindingStatement) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(STATEMENT_DIGEST_LABEL);
    h.update(canonical_encode_statement(pp, x));
    let out = h.finalize();
    let mut digest = [0u8; 64];
    digest.copy_from_slice(&out);
    digest
}

fn validate_statement(
    pp: &BindingPublicParams,
    statement: &BindingStatement,
) -> Result<(), BindingError> {
    if pp.protocol_version != PROTOCOL_VERSION {
        return Err(BindingError::InvalidProtocolVersion);
    }
    if pp.pp_digest.len() != 64 {
        return Err(BindingError::InvalidPublicParameterDigest);
    }
    if pp.threshold == 0
        || pp.gargos_n == 0
        || pp.threshold > pp.ell_max
        || pp.ell_max > pp.gargos_n
        || pp.registered_signers.len() != pp.gargos_n as usize
    {
        return Err(BindingError::InvalidRegisteredSigner);
    }
    let mut prev = 0;
    for signer in &pp.registered_signers {
        if signer.index == 0 || signer.index <= prev || signer.index > pp.gargos_n {
            return Err(BindingError::InvalidRegisteredSigner);
        }
        dec_point(&signer.x_i)?;
        dec_point(&signer.n_i)?;
        prev = signer.index;
    }
    dec_point(&pp.g)?;
    dec_point(&pp.h)?;
    dec_point(&pp.v)?;
    dec_point(&pp.public_key)?;
    dec_point(&pp.g_c)?;
    dec_point(&pp.h_c)?;
    dec_point(&pp.g_n)?;
    require_nonempty(&pp.ibe_public_key)?;
    validate_lhtlp_params(pp)?;
    if statement.m.is_empty() {
        return Err(BindingError::EmptyMessage);
    }
    if statement.ell == 0 || statement.ell > pp.ell_max {
        return Err(BindingError::EllOutOfRange);
    }
    dec_point(&statement.hat_a)?;
    dec_point(&statement.x_i)?;
    dec_point(&statement.n_i)?;
    dec_point(&statement.c_i)?;
    require_nonempty(&statement.t_i_z)?;
    require_nonempty(&statement.t_i_tau)?;
    require_nonempty(&statement.e_i)?;
    Ok(())
}

fn validate_witness_shape(
    statement: &BindingStatement,
    witness: &BindingWitness,
) -> Result<(), BindingError> {
    if witness.signer_set.len() != statement.ell as usize {
        return Err(BindingError::SignerSetLengthMismatch);
    }
    let mut prev = None;
    let mut found = false;
    for &idx in &witness.signer_set {
        if idx == witness.signer_index {
            found = true;
        }
        if let Some(prev_idx) = prev {
            if idx == prev_idx {
                return Err(BindingError::DuplicateSignerIndex);
            }
            if idx < prev_idx {
                return Err(BindingError::SignerSetNotSorted);
            }
        }
        prev = Some(idx);
    }
    if !found {
        return Err(BindingError::SignerIndexMissing);
    }
    if witness.transcript.entries.is_empty() {
        return Err(BindingError::EmptyOpaqueField);
    }
    require_nonempty(&witness.legacy_transcript)?;
    require_nonempty(&witness.secret_relation)?;
    require_nonempty(&witness.response_relation)?;
    require_nonempty(&witness.lhtlp_randomness_z)?;
    require_nonempty(&witness.lhtlp_randomness_tau)?;
    require_nonempty(&witness.ibe_randomness)?;
    require_nonempty(&witness.nullifier_randomness)?;
    Ok(())
}

fn require_nonempty(bytes: &CanonicalBytes) -> Result<(), BindingError> {
    if bytes.bytes.is_empty() {
        return Err(BindingError::EmptyOpaqueField);
    }
    Ok(())
}

fn verify_full_binding_relation(
    pp: &BindingPublicParams,
    statement: &BindingStatement,
    witness: &BindingWitness,
) -> Result<(), BindingError> {
    if statement.signer_index != witness.signer_index {
        return Err(BindingError::SignerIndexMissing);
    }
    if statement.ell != witness.signer_set.len() as u32
        || witness.transcript.signer_set != witness.signer_set
        || witness.transcript.m != statement.m
        || witness.transcript.a_hat != statement.hat_a
        || witness.transcript.entries.len() != statement.ell as usize
        || witness.transcript.mu_vector.len() != statement.ell as usize
    {
        return Err(BindingError::TranscriptMismatch);
    }
    if statement.ell < pp.threshold || statement.ell > pp.ell_max {
        return Err(BindingError::EllOutOfRange);
    }

    let g = dec_point(&pp.g)?;
    let h = dec_point(&pp.h)?;
    let v = dec_point(&pp.v)?;
    let public_key = dec_point(&pp.public_key)?;
    let g_c = dec_point(&pp.g_c)?;
    let h_c = dec_point(&pp.h_c)?;
    let g_n = dec_point(&pp.g_n)?;
    let hat_a = dec_point(&statement.hat_a)?;
    let c_i = dec_point(&statement.c_i)?;
    let n_i = dec_point(&statement.n_i)?;
    let x_i_statement = dec_point(&statement.x_i)?;
    let a_i_scalar = dec_scalar(&witness.a_i)?;
    let s_i = dec_scalar(&witness.s_i)?;
    let r_i = dec_scalar(&witness.r_i)?;
    let u_i = dec_scalar(&witness.u_i)?;
    let z_i = dec_scalar(&witness.z_i)?;
    let tau_i = dec_scalar(&witness.tau_i)?;
    let eta_i = dec_scalar(&witness.eta_i)?;

    let registered = registered_signer(pp, witness.signer_index)?;
    if registered.x_i != statement.x_i || registered.n_i != statement.n_i {
        return Err(BindingError::InvalidRegisteredSigner);
    }
    if g_n * eta_i != n_i {
        return Err(BindingError::NullifierMismatch);
    }
    if h_null(&statement.d, &witness.eta_i) != statement.nu_i {
        return Err(BindingError::NullifierMismatch);
    }

    let tr_digest = h_ctx(&witness.transcript);
    if tr_digest != statement.d {
        return Err(BindingError::TranscriptMismatch);
    }
    let g0p = g0(&witness.transcript.m, &witness.transcript.mu_vector);
    let g1p = g1(&witness.transcript.m, &witness.transcript.mu_vector);

    let mut a_hat_expected = RistrettoPoint::default();
    let mut signer_entry = None;
    for (pos, entry) in witness.transcript.entries.iter().enumerate() {
        if witness.signer_set.get(pos).copied() != Some(entry.i)
            || witness
                .transcript
                .mu_vector
                .get(pos)
                .map(|mu| (mu.i, mu.mu_i))
                != Some((entry.i, entry.mu_i))
        {
            return Err(BindingError::TranscriptMismatch);
        }
        let registered = registered_signer(pp, entry.i)?;
        if registered.x_i != entry.x_i {
            return Err(BindingError::InvalidRegisteredSigner);
        }
        let b_j = dec_point(&entry.b_i)?;
        let a_j = dec_point(&entry.a_i)?;
        let x_j = dec_point(&entry.x_i)?;
        if h_com(entry.i, &entry.rho_i, &b_j) != entry.mu_i {
            return Err(BindingError::CommitmentHashMismatch);
        }
        if !sig_verify_core(
            &g,
            &h,
            &v,
            &x_j,
            &a_j,
            &b_j,
            &g0p,
            &g1p,
            &entry.rho_i,
            &entry.pi_gar,
        )? {
            return Err(BindingError::GargosProofRejected);
        }
        let li = lagrange_coeff(entry.i, &witness.signer_set);
        a_hat_expected += a_j * li;
        if entry.i == witness.signer_index {
            signer_entry = Some(entry);
        }
    }
    if a_hat_expected != hat_a {
        return Err(BindingError::AggregateNonceMismatch);
    }
    let entry = signer_entry.ok_or(BindingError::SignerIndexMissing)?;
    if entry.x_i != statement.x_i {
        return Err(BindingError::InvalidRegisteredSigner);
    }
    let a_point = dec_point(&entry.a_i)?;
    let b_point = dec_point(&entry.b_i)?;
    let x_expected = g * s_i + h * r_i + v * u_i;
    let b_expected = g * a_i_scalar + f0(&entry.rho_i) * r_i + f1(&entry.rho_i) * u_i;
    let a_expected = g * a_i_scalar + g0p * r_i + g1p * u_i;
    if x_expected != x_i_statement || b_expected != b_point || a_expected != a_point {
        return Err(BindingError::ResponseEquationMismatch);
    }
    let challenge = h_sig(&hat_a, &public_key, &statement.m);
    let li = lagrange_coeff(witness.signer_index, &witness.signer_set);
    if z_i != li * (a_i_scalar + challenge * s_i) {
        return Err(BindingError::ResponseEquationMismatch);
    }
    if c_i != g_c * z_i + h_c * tau_i {
        return Err(BindingError::CommitmentEquationMismatch);
    }
    if witness.response_relation.bytes != scalar_to_lhtlp_plaintext(&z_i)
        || witness.secret_relation.bytes != scalar_to_lhtlp_plaintext(&tau_i)
    {
        return Err(BindingError::InvalidLhtlpWitness);
    }
    Ok(())
}

fn registered_signer(
    pp: &BindingPublicParams,
    index: u32,
) -> Result<&RegisteredSigner, BindingError> {
    if index == 0 || index > pp.gargos_n {
        return Err(BindingError::InvalidRegisteredSigner);
    }
    pp.registered_signers
        .iter()
        .find(|signer| signer.index == index)
        .ok_or(BindingError::InvalidRegisteredSigner)
}

fn dec_point(bytes: &[u8; 32]) -> Result<RistrettoPoint, BindingError> {
    CompressedRistretto(*bytes)
        .decompress()
        .ok_or(BindingError::InvalidPointEncoding)
}

fn dec_scalar(bytes: &[u8; 32]) -> Result<Scalar, BindingError> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
        .ok_or(BindingError::InvalidScalarEncoding)
}

fn enc_point(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

fn enc_scalar(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes()
}

fn hash_32(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(domain);
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out[..32]);
    r
}

fn hash_64(domain: &[u8], data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(domain);
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}

fn hash_to_point(domain: &[u8], data: &[u8]) -> RistrettoPoint {
    RistrettoPoint::from_uniform_bytes(&hash_64(domain, data))
}

fn hash_to_scalar(domain: &[u8], data: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&hash_64(domain, data))
}

fn encode_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn h_com(i: u32, rho: &[u8; 32], b: &RistrettoPoint) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&i.to_le_bytes());
    buf.extend_from_slice(rho);
    buf.extend_from_slice(&enc_point(b));
    hash_32(b"Gargos::Hcom", &buf)
}

fn f0(rho: &[u8; 32]) -> RistrettoPoint {
    hash_to_point(b"Gargos::F0", rho)
}

fn f1(rho: &[u8; 32]) -> RistrettoPoint {
    hash_to_point(b"Gargos::F1", rho)
}

fn g0(message: &[u8], mu_vec: &[TranscriptMu]) -> RistrettoPoint {
    let mut buf = Vec::new();
    encode_len_prefixed(&mut buf, message);
    buf.extend_from_slice(&(mu_vec.len() as u64).to_le_bytes());
    for mu in mu_vec {
        buf.extend_from_slice(&mu.i.to_le_bytes());
        buf.extend_from_slice(&mu.mu_i);
    }
    hash_to_point(b"Gargos::G0", &buf)
}

fn g1(message: &[u8], mu_vec: &[TranscriptMu]) -> RistrettoPoint {
    let mut buf = Vec::new();
    encode_len_prefixed(&mut buf, message);
    buf.extend_from_slice(&(mu_vec.len() as u64).to_le_bytes());
    for mu in mu_vec {
        buf.extend_from_slice(&mu.i.to_le_bytes());
        buf.extend_from_slice(&mu.mu_i);
    }
    hash_to_point(b"Gargos::G1", &buf)
}

fn h_sig(a_hat: &RistrettoPoint, pk: &RistrettoPoint, message: &[u8]) -> Scalar {
    let mut buf = Vec::new();
    buf.extend_from_slice(&enc_point(a_hat));
    buf.extend_from_slice(&enc_point(pk));
    encode_len_prefixed(&mut buf, message);
    hash_to_scalar(b"Gargos::Hsig", &buf)
}

fn h_fs(
    xa: &RistrettoPoint,
    xb: &RistrettoPoint,
    xpk: &RistrettoPoint,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
    pk: &RistrettoPoint,
    g0p: &RistrettoPoint,
    g1p: &RistrettoPoint,
    rho: &[u8; 32],
) -> Scalar {
    let mut buf = Vec::new();
    buf.extend_from_slice(&enc_point(xa));
    buf.extend_from_slice(&enc_point(xb));
    buf.extend_from_slice(&enc_point(xpk));
    buf.extend_from_slice(&enc_point(a));
    buf.extend_from_slice(&enc_point(b));
    buf.extend_from_slice(&enc_point(pk));
    buf.extend_from_slice(&enc_point(g0p));
    buf.extend_from_slice(&enc_point(g1p));
    buf.extend_from_slice(rho);
    hash_to_scalar(b"Gargos::HFS", &buf)
}

fn sig_verify_core(
    g: &RistrettoPoint,
    h: &RistrettoPoint,
    v: &RistrettoPoint,
    pk_i: &RistrettoPoint,
    a_i_point: &RistrettoPoint,
    b_i: &RistrettoPoint,
    g0p: &RistrettoPoint,
    g1p: &RistrettoPoint,
    rho: &[u8; 32],
    proof: &BindingGargosProof,
) -> Result<bool, BindingError> {
    let xa = dec_point(&proof.xa)?;
    let xb = dec_point(&proof.xb)?;
    let xpk = dec_point(&proof.xpk)?;
    let za = dec_scalar(&proof.za)?;
    let zs = dec_scalar(&proof.zs)?;
    let zr = dec_scalar(&proof.zr)?;
    let zu = dec_scalar(&proof.zu)?;
    let h0 = f0(rho);
    let h1 = f1(rho);
    let e = h_fs(&xa, &xb, &xpk, a_i_point, b_i, pk_i, g0p, g1p, rho);
    let left1 = (*g) * za + (*g0p) * zr + (*g1p) * zu;
    let right1 = xa + (*a_i_point) * e;
    let left2 = (*g) * za + h0 * zr + h1 * zu;
    let right2 = xb + (*b_i) * e;
    let left3 = (*g) * zs + (*h) * zr + (*v) * zu;
    let right3 = xpk + (*pk_i) * e;
    Ok(left1 == right1 && left2 == right2 && left3 == right3)
}

fn lagrange_coeff(i: u32, signer_set: &[u32]) -> Scalar {
    let i_s = Scalar::from(i as u64);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &k in signer_set {
        if k == i {
            continue;
        }
        let k_s = Scalar::from(k as u64);
        num *= k_s;
        den *= k_s - i_s;
    }
    num * den.invert()
}

fn h_ctx(transcript: &BindingTranscript) -> [u8; 32] {
    hash_32(b"H_ctx", &canonical_gargos_transcript_bytes(transcript))
}

fn h_null(d: &[u8; 32], eta: &[u8; 32]) -> [u8; 32] {
    hash_32(b"H_null", &[d.as_slice(), eta.as_slice()].concat())
}

fn canonical_gargos_transcript_bytes(tr: &BindingTranscript) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_bytes_le(&mut buf, b"GargosTranscript/v1");
    encode_bytes_le(&mut buf, &tr.m);
    buf.extend_from_slice(&(tr.signer_set.len() as u64).to_le_bytes());
    for id in &tr.signer_set {
        buf.extend_from_slice(&id.to_le_bytes());
    }
    buf.extend_from_slice(&(tr.mu_vector.len() as u64).to_le_bytes());
    for mu in &tr.mu_vector {
        buf.extend_from_slice(&mu.i.to_le_bytes());
        buf.extend_from_slice(&mu.mu_i);
    }
    buf.extend_from_slice(&(tr.entries.len() as u64).to_le_bytes());
    for e in &tr.entries {
        buf.extend_from_slice(&e.i.to_le_bytes());
        buf.extend_from_slice(&e.mu_i);
        buf.extend_from_slice(&e.rho_i);
        buf.extend_from_slice(&e.b_i);
        buf.extend_from_slice(&e.a_i);
        buf.extend_from_slice(&e.x_i);
        buf.extend_from_slice(&e.pi_gar.xa);
        buf.extend_from_slice(&e.pi_gar.xb);
        buf.extend_from_slice(&e.pi_gar.xpk);
        buf.extend_from_slice(&e.pi_gar.za);
        buf.extend_from_slice(&e.pi_gar.zs);
        buf.extend_from_slice(&e.pi_gar.zr);
        buf.extend_from_slice(&e.pi_gar.zu);
    }
    buf.extend_from_slice(&tr.a_hat);
    buf
}

fn encode_bytes_le(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn scalar_to_lhtlp_plaintext(value: &Scalar) -> Vec<u8> {
    let mut bytes = enc_scalar(value);
    bytes.reverse();
    bytes.to_vec()
}

fn verify_ibe_ciphertext(
    pp: &BindingPublicParams,
    statement: &BindingStatement,
    witness: &BindingWitness,
) -> Result<(), BindingError> {
    let expected = deterministic_ibe_encrypt(
        &pp.ibe_public_key.bytes,
        &statement.m,
        &statement.d,
        witness.signer_index,
        &witness.ibe_randomness.bytes,
    )?;
    if expected != statement.e_i.bytes {
        return Err(BindingError::IbeCiphertextMismatch);
    }
    Ok(())
}

fn deterministic_ibe_encrypt(
    pk_bytes: &[u8],
    message: &[u8],
    descriptor: &[u8; 32],
    signer_index: u32,
    xi: &[u8],
) -> Result<Vec<u8>, BindingError> {
    if xi.len() != 64 || pk_bytes.len() != CGWFO::PK_BYTES {
        return Err(BindingError::IbeCiphertextMismatch);
    }
    let pk_fixed: [u8; CGWFO::PK_BYTES] = pk_bytes
        .try_into()
        .map_err(|_| BindingError::IbeCiphertextMismatch)?;
    let pk = Option::from(<CGWFO as IBKEM>::Pk::from_bytes(&pk_fixed))
        .ok_or(BindingError::IbeCiphertextMismatch)?;
    let id_digest = ibe_identity_digest(message, descriptor);
    let id = <CGWFO as IBKEM>::Id::derive(&id_digest);
    let seed = deterministic_seed(b"GARGOS-TRACE-CGWFO-RNG-v1", xi, &id_digest);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (kem_ct, shared) = CGWFO::encaps(&pk, &id, &mut rng);
    let nonce = deterministic_nonce(xi, &id_digest, signer_index);
    let cipher =
        Aes256Gcm::new_from_slice(&shared.0).map_err(|_| BindingError::IbeCiphertextMismatch)?;
    let aead_ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            signer_index.to_be_bytes().as_ref(),
        )
        .map_err(|_| BindingError::IbeCiphertextMismatch)?;
    let mut out = Vec::new();
    encode_bytes_le(&mut out, &id_digest);
    encode_bytes_le(&mut out, kem_ct.to_bytes().as_ref());
    out.extend_from_slice(&nonce);
    encode_bytes_le(&mut out, &aead_ciphertext);
    Ok(out)
}

fn deterministic_seed(domain: &[u8], xi: &[u8], id_digest: &[u8; 64]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(domain);
    h.update(xi);
    h.update(id_digest);
    let out = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[..32]);
    seed
}

fn deterministic_nonce(xi: &[u8], id_digest: &[u8; 64], signer_index: u32) -> [u8; 12] {
    let mut h = Sha512::new();
    h.update(b"GARGOS-TRACE-AEAD-NONCE-v1");
    h.update(xi);
    h.update(id_digest);
    h.update(signer_index.to_be_bytes());
    let out = h.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&out[..12]);
    nonce
}

fn ibe_identity_digest(message: &[u8], descriptor: &[u8; 32]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"GARGOS-TRACE-ID-v1");
    h.update((message.len() as u64).to_be_bytes());
    h.update(message);
    h.update(descriptor);
    let out = h.finalize();
    let mut id = [0u8; 64];
    id.copy_from_slice(&out);
    id
}

fn put_u32(out: &mut Vec<u8>, label: &[u8], value: u32) {
    put_bytes(out, b"field", label);
    out.extend_from_slice(&4u32.to_be_bytes());
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, label: &[u8], value: u64) {
    put_bytes(out, b"field", label);
    out.extend_from_slice(&8u32.to_be_bytes());
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, label: &[u8], bytes: &[u8]) {
    out.extend_from_slice(&(label.len() as u32).to_be_bytes());
    out.extend_from_slice(label);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

const LHTLP_FUNCTIONAL_N_BYTES: usize = 64;
const LHTLP_FUNCTIONAL_N_SQUARED_BYTES: usize = 128;
const LHTLP_SECURITY_N_BYTES: usize = 384;
const LHTLP_SECURITY_N_SQUARED_BYTES: usize = 768;

fn validate_lhtlp_params(pp: &BindingPublicParams) -> Result<(), BindingError> {
    if pp.lhtlp_delta == 0
        || !valid_lhtlp_widths(pp.lhtlp_n.bytes.len(), pp.lhtlp_n_squared.bytes.len())
        || pp.lhtlp_g_t.bytes.len() != pp.lhtlp_n.bytes.len()
        || pp.lhtlp_h_t.bytes.len() != pp.lhtlp_n.bytes.len()
    {
        return Err(BindingError::InvalidLhtlpParameter);
    }
    let n_width = pp.lhtlp_n.bytes.len();
    let n = u3072_from_short_exact(&pp.lhtlp_n.bytes)?;
    let n_squared = u6144_from_short_exact(&pp.lhtlp_n_squared.bytes)?;
    let g_t = u3072_from_short_exact(&pp.lhtlp_g_t.bytes)?;
    let h_t = u3072_from_short_exact(&pp.lhtlp_h_t.bytes)?;
    if n <= U3072::ONE || pp.lhtlp_n.bytes[n_width - 1] & 1 == 0 {
        return Err(BindingError::InvalidLhtlpParameter);
    }
    if n.mul(&n) != n_squared {
        return Err(BindingError::InvalidLhtlpParameter);
    }
    if g_t <= U3072::ONE || g_t >= n || h_t <= U3072::ONE || h_t >= n {
        return Err(BindingError::InvalidLhtlpParameter);
    }
    Ok(())
}

fn verify_lhtlp_pgen(
    pp: &BindingPublicParams,
    puzzle: &[u8],
    scalar: &[u8],
    randomness: &[u8],
) -> Result<(), BindingError> {
    let n_width = pp.lhtlp_n.bytes.len();
    let n_squared_width = pp.lhtlp_n_squared.bytes.len();
    if !valid_lhtlp_widths(n_width, n_squared_width) || puzzle.len() != n_width + n_squared_width {
        return Err(BindingError::InvalidLhtlpPuzzle);
    }
    let n = u3072_from_short_exact(&pp.lhtlp_n.bytes)?;
    let n_squared = u6144_from_short_exact(&pp.lhtlp_n_squared.bytes)?;
    let g_t = u3072_from_short_exact(&pp.lhtlp_g_t.bytes)?;
    let h_t = u3072_from_short_exact(&pp.lhtlp_h_t.bytes)?;
    let u = u3072_from_short_exact(&puzzle[..n_width])?;
    let v = u6144_from_short_exact(&puzzle[n_width..])?;
    let s = u3072_from_short(scalar)?;
    let r = u3072_from_short(randomness)?;
    if s >= n || r <= U3072::ONE || r >= n || u <= U3072::ONE || u >= n {
        return Err(BindingError::InvalidLhtlpWitness);
    }
    if v <= U6144::ONE || v >= n_squared {
        return Err(BindingError::InvalidLhtlpPuzzle);
    }

    let params_n = DynResidueParams::new(&n);
    let params_n_squared = DynResidueParams::new(&n_squared);

    let expected_u = DynResidue::new(&g_t, params_n).pow(&r).retrieve();

    let r_n: U6144 = r.mul(&n);
    let h_t_wide = U3072::ZERO.concat(&h_t);
    let n_wide = U3072::ZERO.concat(&n);
    let one_plus_n = n_wide.wrapping_add(&U6144::ONE);
    let s_wide = U3072::ZERO.concat(&s);
    let lhs = DynResidue::new(&h_t_wide, params_n_squared).pow(&r_n);
    let rhs = DynResidue::new(&one_plus_n, params_n_squared).pow(&s_wide);
    let expected_v = (lhs * rhs).retrieve();

    if expected_u != u || expected_v != v {
        return Err(BindingError::LhtlpEquationMismatch);
    }
    Ok(())
}

fn valid_lhtlp_widths(n_width: usize, n_squared_width: usize) -> bool {
    (n_width == LHTLP_FUNCTIONAL_N_BYTES && n_squared_width == LHTLP_FUNCTIONAL_N_SQUARED_BYTES)
        || (n_width == LHTLP_SECURITY_N_BYTES && n_squared_width == LHTLP_SECURITY_N_SQUARED_BYTES)
}

fn u3072_from_short_exact(bytes: &[u8]) -> Result<U3072, BindingError> {
    if bytes.is_empty() || bytes.len() > LHTLP_SECURITY_N_BYTES {
        return Err(BindingError::InvalidLhtlpParameter);
    }
    let mut fixed = [0u8; LHTLP_SECURITY_N_BYTES];
    fixed[LHTLP_SECURITY_N_BYTES - bytes.len()..].copy_from_slice(bytes);
    Ok(U3072::from_be_bytes(fixed))
}

fn u6144_from_short_exact(bytes: &[u8]) -> Result<U6144, BindingError> {
    if bytes.is_empty() || bytes.len() > LHTLP_SECURITY_N_SQUARED_BYTES {
        return Err(BindingError::InvalidLhtlpParameter);
    }
    let mut fixed = [0u8; LHTLP_SECURITY_N_SQUARED_BYTES];
    fixed[LHTLP_SECURITY_N_SQUARED_BYTES - bytes.len()..].copy_from_slice(bytes);
    Ok(U6144::from_be_bytes(fixed))
}

fn u3072_from_short(bytes: &[u8]) -> Result<U3072, BindingError> {
    if bytes.is_empty() || bytes.len() > LHTLP_SECURITY_N_BYTES {
        return Err(BindingError::InvalidLhtlpWitness);
    }
    let mut fixed = [0u8; LHTLP_SECURITY_N_BYTES];
    fixed[LHTLP_SECURITY_N_BYTES - bytes.len()..].copy_from_slice(bytes);
    Ok(U3072::from_be_bytes(fixed))
}

#[cfg(feature = "std")]
pub fn concrete_functional_smoke_instance(
) -> (BindingPublicParams, BindingStatement, BindingWitness) {
    concrete_functional_instance(2)
}

#[cfg(feature = "std")]
pub fn concrete_functional_instance(
    ell: usize,
) -> (BindingPublicParams, BindingStatement, BindingWitness) {
    concrete_functional_instance_for_signer(ell, 1)
}

#[cfg(feature = "std")]
pub fn concrete_functional_instance_for_signer(
    ell: usize,
    signer_index: u32,
) -> (BindingPublicParams, BindingStatement, BindingWitness) {
    assert!(matches!(ell, 2 | 4 | 8));
    assert!(signer_index >= 1 && signer_index <= ell as u32);
    let g = hash_to_point(b"test", b"g");
    let h = hash_to_point(b"test", b"h");
    let v = hash_to_point(b"test", b"v");
    let g_c = hash_to_point(b"test", b"g_c");
    let h_c = hash_to_point(b"test", b"h_c");
    let g_n = hash_to_point(b"test", b"g_n");
    let message = b"message".to_vec();
    let signer_set: Vec<u32> = (1..=ell as u32).collect();
    let secrets: Vec<_> = (1..=ell as u64)
        .map(|i| {
            (
                Scalar::from(10 * i + 1),
                Scalar::from(10 * i + 2),
                Scalar::from(10 * i + 3),
                Scalar::from(10 * i + 4),
                Scalar::from(10 * i + 5),
            )
        })
        .collect();
    let registered_signers: Vec<RegisteredSigner> = secrets
        .iter()
        .enumerate()
        .map(|(idx, (_, s, r, u, eta))| RegisteredSigner {
            index: idx as u32 + 1,
            x_i: enc_point(&(g * (*s) + h * (*r) + v * (*u))),
            n_i: enc_point(&(g_n * (*eta))),
        })
        .collect();
    let mut first = Vec::new();
    for (idx, (a, _s, r, u, _eta)) in secrets.iter().enumerate() {
        let i = idx as u32 + 1;
        let rho_i = [i as u8; 32];
        let b_i = g * (*a) + f0(&rho_i) * (*r) + f1(&rho_i) * (*u);
        let mu_i = h_com(i, &rho_i, &b_i);
        first.push((i, *a, rho_i, b_i, mu_i));
    }
    let mu_vector: Vec<TranscriptMu> = first
        .iter()
        .map(|(i, _, _, _, mu_i)| TranscriptMu { i: *i, mu_i: *mu_i })
        .collect();
    let g0p = g0(&message, &mu_vector);
    let g1p = g1(&message, &mu_vector);
    let mut entries = Vec::new();
    for (i, a, rho_i, b_i, mu_i) in first {
        let (_a, s, r, u, _eta) = secrets[(i - 1) as usize];
        let x_i = g * s + h * r + v * u;
        let a_i = g * a + g0p * r + g1p * u;
        let pi_gar = sig_prove_functional(
            &g, &h, &v, &x_i, &a_i, &b_i, &g0p, &g1p, &rho_i, &a, &s, &r, &u,
        );
        entries.push(BindingTranscriptEntry {
            i,
            mu_i,
            rho_i,
            b_i: enc_point(&b_i),
            a_i: enc_point(&a_i),
            x_i: enc_point(&x_i),
            pi_gar,
        });
    }
    let mut a_hat = RistrettoPoint::default();
    for entry in &entries {
        a_hat += dec_point(&entry.a_i).unwrap() * lagrange_coeff(entry.i, &signer_set);
    }
    let transcript = BindingTranscript {
        m: message.clone(),
        signer_set: signer_set.clone(),
        mu_vector,
        entries,
        a_hat: enc_point(&a_hat),
    };
    let d = h_ctx(&transcript);
    let public_key = g * Scalar::from(99u64);
    let c = h_sig(&a_hat, &public_key, &message);
    let (a_i, s_i, r_i, u_i, eta_i) = secrets[(signer_index - 1) as usize];
    let li = lagrange_coeff(signer_index, &signer_set);
    let z_i = li * (a_i + c * s_i);
    let tau_i = Scalar::from(77u64);
    let c_i = g_c * z_i + h_c * tau_i;
    let n_i = g_n * eta_i;
    let (lhtlp_n, lhtlp_n_squared, lhtlp_g_t, lhtlp_h_t) = functional_lhtlp_params();
    let z_plain = scalar_to_lhtlp_plaintext(&z_i);
    let tau_plain = scalar_to_lhtlp_plaintext(&tau_i);
    let r_z = fixed_u128_functional(17, LHTLP_FUNCTIONAL_N_BYTES);
    let r_tau = fixed_u128_functional(19, LHTLP_FUNCTIONAL_N_BYTES);
    let t_z = functional_lhtlp_puzzle(
        &lhtlp_n,
        &lhtlp_n_squared,
        &lhtlp_g_t,
        &lhtlp_h_t,
        &z_plain,
        &r_z,
    );
    let t_tau = functional_lhtlp_puzzle(
        &lhtlp_n,
        &lhtlp_n_squared,
        &lhtlp_g_t,
        &lhtlp_h_t,
        &tau_plain,
        &r_tau,
    );
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let (ibe_pk, _ibe_sk) = CGWFO::setup(&mut rng);
    let xi = vec![9u8; 64];
    let e_i =
        deterministic_ibe_encrypt(ibe_pk.to_bytes().as_ref(), &message, &d, signer_index, &xi)
            .unwrap();
    let pp = BindingPublicParams {
        pp_digest: vec![1u8; 64],
        ell_max: ell as u32,
        threshold: ell as u32 - 1,
        gargos_n: ell as u32,
        protocol_version: PROTOCOL_VERSION.to_vec(),
        g: enc_point(&g),
        h: enc_point(&h),
        v: enc_point(&v),
        public_key: enc_point(&public_key),
        g_c: enc_point(&g_c),
        h_c: enc_point(&h_c),
        g_n: enc_point(&g_n),
        registered_signers,
        ibe_public_key: CanonicalBytes {
            bytes: ibe_pk.to_bytes().as_ref().to_vec(),
        },
        lhtlp_delta: 64,
        lhtlp_n: CanonicalBytes { bytes: lhtlp_n },
        lhtlp_n_squared: CanonicalBytes {
            bytes: lhtlp_n_squared,
        },
        lhtlp_g_t: CanonicalBytes { bytes: lhtlp_g_t },
        lhtlp_h_t: CanonicalBytes { bytes: lhtlp_h_t },
    };
    let statement = BindingStatement {
        d,
        m: message,
        hat_a: enc_point(&a_hat),
        ell: ell as u32,
        signer_index,
        x_i: enc_point(&(g * s_i + h * r_i + v * u_i)),
        n_i: enc_point(&n_i),
        c_i: enc_point(&c_i),
        t_i_z: CanonicalBytes { bytes: t_z },
        t_i_tau: CanonicalBytes { bytes: t_tau },
        e_i: CanonicalBytes { bytes: e_i },
        nu_i: h_null(&d, &enc_scalar(&eta_i)),
    };
    let witness = BindingWitness {
        signer_set,
        signer_index,
        transcript: transcript.clone(),
        a_i: enc_scalar(&a_i),
        s_i: enc_scalar(&s_i),
        r_i: enc_scalar(&r_i),
        u_i: enc_scalar(&u_i),
        z_i: enc_scalar(&z_i),
        tau_i: enc_scalar(&tau_i),
        eta_i: enc_scalar(&eta_i),
        legacy_transcript: CanonicalBytes {
            bytes: canonical_gargos_transcript_bytes(&transcript),
        },
        secret_relation: CanonicalBytes { bytes: tau_plain },
        response_relation: CanonicalBytes { bytes: z_plain },
        lhtlp_randomness_z: CanonicalBytes { bytes: r_z },
        lhtlp_randomness_tau: CanonicalBytes { bytes: r_tau },
        ibe_randomness: CanonicalBytes { bytes: xi },
        nullifier_randomness: CanonicalBytes {
            bytes: enc_scalar(&eta_i).to_vec(),
        },
    };
    (pp, statement, witness)
}

#[cfg(feature = "std")]
fn fixed_u128_functional(value: u128, width: usize) -> Vec<u8> {
    let mut out = vec![0u8; width];
    let bytes = value.to_be_bytes();
    let take = width.min(bytes.len());
    out[width - take..].copy_from_slice(&bytes[bytes.len() - take..]);
    out
}

#[cfg(feature = "std")]
fn functional_lhtlp_params() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut n = vec![0u8; LHTLP_FUNCTIONAL_N_BYTES];
    n[8] = 1;
    n[LHTLP_FUNCTIONAL_N_BYTES - 1] = 147;
    let n_u = u3072_from_short_exact(&n).unwrap();
    let n_squared_full = n_u.mul(&n_u).to_be_bytes();
    let n_squared = n_squared_full
        [LHTLP_SECURITY_N_SQUARED_BYTES - LHTLP_FUNCTIONAL_N_SQUARED_BYTES..]
        .to_vec();
    (
        n,
        n_squared,
        fixed_u128_functional(4, LHTLP_FUNCTIONAL_N_BYTES),
        fixed_u128_functional(16, LHTLP_FUNCTIONAL_N_BYTES),
    )
}

#[cfg(feature = "std")]
fn functional_lhtlp_puzzle(
    n: &[u8],
    n_squared: &[u8],
    g_t: &[u8],
    h_t: &[u8],
    scalar: &[u8],
    randomness: &[u8],
) -> Vec<u8> {
    let n_u = u3072_from_short_exact(n).unwrap();
    let n_squared_u = u6144_from_short_exact(n_squared).unwrap();
    let g_t_u = u3072_from_short_exact(g_t).unwrap();
    let h_t_u = u3072_from_short_exact(h_t).unwrap();
    let s = u3072_from_short(scalar).unwrap();
    let r = u3072_from_short_exact(randomness).unwrap();
    let params_n = DynResidueParams::new(&n_u);
    let params_n_squared = DynResidueParams::new(&n_squared_u);
    let u = DynResidue::new(&g_t_u, params_n).pow(&r).retrieve();
    let r_n: U6144 = r.mul(&n_u);
    let h_t_wide = U3072::ZERO.concat(&h_t_u);
    let n_wide = U3072::ZERO.concat(&n_u);
    let one_plus_n = n_wide.wrapping_add(&U6144::ONE);
    let s_wide = U3072::ZERO.concat(&s);
    let lhs = DynResidue::new(&h_t_wide, params_n_squared).pow(&r_n);
    let rhs = DynResidue::new(&one_plus_n, params_n_squared).pow(&s_wide);
    let v = (lhs * rhs).retrieve();
    let u_bytes = u.to_be_bytes();
    let v_bytes = v.to_be_bytes();
    [
        u_bytes[LHTLP_SECURITY_N_BYTES - n.len()..].to_vec(),
        v_bytes[LHTLP_SECURITY_N_SQUARED_BYTES - n_squared.len()..].to_vec(),
    ]
    .concat()
}

#[cfg(feature = "std")]
#[allow(clippy::too_many_arguments)]
fn sig_prove_functional(
    g: &RistrettoPoint,
    h: &RistrettoPoint,
    v: &RistrettoPoint,
    pk_i: &RistrettoPoint,
    a_i_point: &RistrettoPoint,
    b_i: &RistrettoPoint,
    g0p: &RistrettoPoint,
    g1p: &RistrettoPoint,
    rho: &[u8; 32],
    a: &Scalar,
    s: &Scalar,
    r: &Scalar,
    u: &Scalar,
) -> BindingGargosProof {
    let a_hat = Scalar::from(101u64);
    let s_hat = Scalar::from(102u64);
    let r_hat = Scalar::from(103u64);
    let u_hat = Scalar::from(104u64);
    let xa = (*g) * a_hat + (*g0p) * r_hat + (*g1p) * u_hat;
    let xb = (*g) * a_hat + f0(rho) * r_hat + f1(rho) * u_hat;
    let xpk = (*g) * s_hat + (*h) * r_hat + (*v) * u_hat;
    let e = h_fs(&xa, &xb, &xpk, a_i_point, b_i, pk_i, g0p, g1p, rho);
    BindingGargosProof {
        xa: enc_point(&xa),
        xb: enc_point(&xb),
        xpk: enc_point(&xpk),
        za: enc_scalar(&(a_hat + (*a) * e)),
        zs: enc_scalar(&(s_hat + (*s) * e)),
        zr: enc_scalar(&(r_hat + (*r) * e)),
        zu: enc_scalar(&(u_hat + (*u) * e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (BindingPublicParams, BindingStatement, BindingWitness) {
        concrete_functional_smoke_instance()
    }

    #[test]
    fn digest_is_stable_and_field_sensitive() {
        let (pp, statement, witness) = sample();
        let d1 =
            verify_binding_relation(&pp, &statement, &witness, BindingStage::FullRelation).unwrap();
        let d2 = statement_digest(&pp, &statement);
        assert_eq!(d1, d2);

        let mut changed = statement.clone();
        changed.m[0] ^= 1;
        assert_ne!(d1, statement_digest(&pp, &changed));
    }

    #[test]
    fn signer_set_must_be_sorted() {
        let (pp, statement, mut witness) = sample();
        witness.signer_set = vec![2, 1];
        assert_eq!(
            verify_binding_relation(&pp, &statement, &witness, BindingStage::StatementDigest),
            Err(BindingError::SignerSetNotSorted)
        );
    }

    #[test]
    fn full_relation_accepts_honest_witness() {
        let (pp, statement, witness) = sample();
        verify_binding_relation(&pp, &statement, &witness, BindingStage::FullRelation).unwrap();
    }

    #[test]
    fn tampered_ibe_ciphertext_is_rejected() {
        let (pp, mut statement, witness) = sample();
        statement.e_i.bytes[0] ^= 1;
        assert_eq!(
            verify_binding_relation(&pp, &statement, &witness, BindingStage::FullRelation),
            Err(BindingError::IbeCiphertextMismatch)
        );
    }

    #[test]
    fn tampered_gargos_proof_is_rejected() {
        let (pp, mut statement, mut witness) = sample();
        witness.transcript.entries[0].pi_gar.za[0] ^= 1;
        statement.d = h_ctx(&witness.transcript);
        statement.nu_i = h_null(&statement.d, &witness.eta_i);
        statement.e_i.bytes = deterministic_ibe_encrypt(
            &pp.ibe_public_key.bytes,
            &statement.m,
            &statement.d,
            statement.signer_index,
            &witness.ibe_randomness.bytes,
        )
        .unwrap();
        assert_eq!(
            verify_binding_relation(&pp, &statement, &witness, BindingStage::FullRelation),
            Err(BindingError::GargosProofRejected)
        );
    }

    #[test]
    fn tampered_response_is_rejected() {
        let (pp, statement, mut witness) = sample();
        witness.z_i[0] ^= 1;
        assert_eq!(
            verify_binding_relation(&pp, &statement, &witness, BindingStage::FullRelation),
            Err(BindingError::ResponseEquationMismatch)
        );
    }

    #[test]
    fn tampered_lhtlp_puzzle_is_rejected() {
        let (pp, mut statement, witness) = sample();
        statement.t_i_z.bytes[10] ^= 1;
        assert_eq!(
            verify_binding_relation(&pp, &statement, &witness, BindingStage::FullRelation),
            Err(BindingError::LhtlpEquationMismatch)
        );
    }

    #[test]
    fn field_mutation_matrix_rejects() {
        macro_rules! reject {
            ($label:literal, $mutate:expr) => {{
                let (mut pp, mut statement, mut witness) = sample();
                $mutate(&mut pp, &mut statement, &mut witness);
                assert!(
                    verify_binding_relation(&pp, &statement, &witness, BindingStage::FullRelation)
                        .is_err(),
                    "{} was accepted",
                    $label
                );
            }};
        }

        reject!("d", |_, statement: &mut BindingStatement, _| {
            statement.d[0] ^= 1;
        });
        reject!("m", |_, statement: &mut BindingStatement, _| {
            statement.m[0] ^= 1;
        });
        reject!("hat_A", |_, statement: &mut BindingStatement, _| {
            statement.hat_a[0] ^= 1;
        });
        reject!("ell", |_, statement: &mut BindingStatement, _| {
            statement.ell = 1;
        });
        reject!("S order", |_, _, witness: &mut BindingWitness| {
            witness.signer_set.swap(0, 1);
        });
        reject!("signer index", |_, statement: &mut BindingStatement, _| {
            statement.signer_index = 2;
        });
        reject!("registered X_j", |pp: &mut BindingPublicParams, _, _| {
            pp.registered_signers[0].x_i[0] ^= 1;
        });
        reject!("registered N_i", |pp: &mut BindingPublicParams, _, _| {
            pp.registered_signers[0].n_i[0] ^= 1;
        });
        reject!("mu_j", |_, _, witness: &mut BindingWitness| {
            witness.transcript.entries[0].mu_i[0] ^= 1;
        });
        reject!("A_j", |_, _, witness: &mut BindingWitness| {
            witness.transcript.entries[0].a_i[0] ^= 1;
        });
        reject!("B_j", |_, _, witness: &mut BindingWitness| {
            witness.transcript.entries[0].b_i[0] ^= 1;
        });
        reject!("rho_j", |_, _, witness: &mut BindingWitness| {
            witness.transcript.entries[0].rho_i[0] ^= 1;
        });
        reject!("pi_j", |_, _, witness: &mut BindingWitness| {
            witness.transcript.entries[0].pi_gar.xa[0] ^= 1;
        });
        reject!("a_i", |_, _, witness: &mut BindingWitness| {
            witness.a_i[0] ^= 1;
        });
        reject!("s_i", |_, _, witness: &mut BindingWitness| {
            witness.s_i[0] ^= 1;
        });
        reject!("r_i", |_, _, witness: &mut BindingWitness| {
            witness.r_i[0] ^= 1;
        });
        reject!("u_i", |_, _, witness: &mut BindingWitness| {
            witness.u_i[0] ^= 1;
        });
        reject!("z_i", |_, _, witness: &mut BindingWitness| {
            witness.z_i[0] ^= 1;
        });
        reject!("tau_i", |_, _, witness: &mut BindingWitness| {
            witness.tau_i[0] ^= 1;
        });
        reject!("omega_z", |_, _, witness: &mut BindingWitness| {
            witness.lhtlp_randomness_z.bytes[63] ^= 1;
        });
        reject!("omega_tau", |_, _, witness: &mut BindingWitness| {
            witness.lhtlp_randomness_tau.bytes[63] ^= 1;
        });
        reject!("xi_i", |_, _, witness: &mut BindingWitness| {
            witness.ibe_randomness.bytes[0] ^= 1;
        });
        reject!("eta_i", |_, _, witness: &mut BindingWitness| {
            witness.eta_i[0] ^= 1;
        });
        reject!("C_i", |_, statement: &mut BindingStatement, _| {
            statement.c_i[0] ^= 1;
        });
        reject!("T_i_z", |_, statement: &mut BindingStatement, _| {
            statement.t_i_z.bytes[0] ^= 1;
        });
        reject!("T_i_tau", |_, statement: &mut BindingStatement, _| {
            statement.t_i_tau.bytes[0] ^= 1;
        });
        reject!("E_i", |_, statement: &mut BindingStatement, _| {
            statement.e_i.bytes[0] ^= 1;
        });
        reject!("nu_i", |_, statement: &mut BindingStatement, _| {
            statement.nu_i[0] ^= 1;
        });
    }
}
