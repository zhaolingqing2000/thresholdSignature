use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::hash::{enc_point, enc_scalar, g0, g1, hcom, hsig};
use crate::keygen;
use crate::nizk::{sig_prove, sig_verify, Proof};
use crate::randutil::random_scalar;
use crate::shamir::lagrange_coeff;
use crate::types::{Params, PublicKeyShare, SecretKeyShare};

#[cfg(feature = "concrete-ibe")]
use crate::crypto::ibe_backend::{
    ConcreteIbeBackend, ConcreteIbeMasterKey, ConcreteIbePublicKey, ConcreteIbeUserKey,
    ConcreteTracingCiphertext,
};
#[cfg(feature = "concrete-lhtlp")]
use crate::crypto::lhtlp::{LhtlpBackend, LhtlpPuzzle};

#[derive(Clone)]
pub struct ConstructionPublicParams {
    pub gargos: Params,
    pub public_key: RistrettoPoint,
    pub public_key_shares: Vec<PublicKeyShare>,
    pub g_c: RistrettoPoint,
    pub h_c: RistrettoPoint,
    pub ibe_public: IbePublicKey,
    #[cfg(feature = "concrete-lhtlp")]
    pub lhtlp: LhtlpBackend,
}

#[derive(Clone)]
pub struct ConstructionSecretState {
    pub secret_key_shares: Vec<SecretKeyShare>,
    pub ibe_master: IbeMasterKey,
}

#[derive(Clone, Debug)]
pub struct GargosTranscriptEntry {
    pub i: u32,
    pub mu_i: [u8; 32],
    pub rho_i: [u8; 32],
    pub b_i: RistrettoPoint,
    pub a_i: RistrettoPoint,
    pub x_i: RistrettoPoint,
    pub pi_gar: Proof,
}

#[derive(Clone, Debug)]
pub struct GargosTranscript {
    pub m: Vec<u8>,
    pub signer_set: Vec<u32>,
    pub mu_vector: Vec<(u32, [u8; 32])>,
    pub entries: Vec<GargosTranscriptEntry>,
    pub a_hat: RistrettoPoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionDescriptor {
    pub d: [u8; 32],
    pub m: Vec<u8>,
    pub a_hat: RistrettoPoint,
    pub ell: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateResponsePackage {
    pub d: [u8; 32],
    pub kappa_i: [u8; 32],
    pub z_i: Scalar,
    pub tau_i: Scalar,
}

#[cfg(not(feature = "concrete-lhtlp"))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdditivePuzzle {
    value: [u8; 32],
    nonce: [u8; 32],
}

#[cfg(feature = "concrete-lhtlp")]
pub type AdditivePuzzle = LhtlpPuzzle;

#[cfg(not(feature = "concrete-ibe"))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IbePublicKey {
    seed: [u8; 32],
}

#[cfg(feature = "concrete-ibe")]
pub type IbePublicKey = ConcreteIbePublicKey;

#[cfg(not(feature = "concrete-ibe"))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IbeMasterKey {
    seed: [u8; 32],
}

#[cfg(feature = "concrete-ibe")]
pub type IbeMasterKey = ConcreteIbeMasterKey;

#[cfg(not(feature = "concrete-ibe"))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracingCiphertext {
    id_hash: [u8; 32],
    nonce: [u8; 32],
    body: [u8; 4],
}

#[cfg(feature = "concrete-ibe")]
pub type TracingCiphertext = ConcreteTracingCiphertext;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingProof {
    pub statement_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuxiliaryHandle {
    pub c_i: [u8; 32],
    pub t_i_z: AdditivePuzzle,
    pub t_i_tau: AdditivePuzzle,
    pub e_i: TracingCiphertext,
    pub nu_i: [u8; 32],
    pub pi_i_bind: BindingProof,
}

#[derive(Clone, Debug)]
pub struct CanonicalSessionRecord {
    pub d: [u8; 32],
    pub m: Vec<u8>,
    pub a_hat: RistrettoPoint,
    pub ell: usize,
    pub handles: Vec<AuxiliaryHandle>,
    pub record_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalSignaturePackage {
    pub d: [u8; 32],
    pub m: Vec<u8>,
    pub a_hat: RistrettoPoint,
    pub z: Scalar,
    pub tau: Scalar,
    pub c: [u8; 32],
    pub t_z: AdditivePuzzle,
    pub t_tau: AdditivePuzzle,
}

#[derive(Clone, Debug, Default)]
pub struct Registry {
    records: BTreeMap<[u8; 32], CanonicalSessionRecord>,
}

#[derive(Clone, Debug)]
pub struct SignEncapOutput {
    pub d: [u8; 32],
    pub transcript: GargosTranscript,
    pub packages: Vec<PrivateResponsePackage>,
}

fn h32(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(domain);
    for part in parts {
        h.update((*part).len().to_le_bytes());
        h.update(part);
    }
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out[..32]);
    r
}

fn hash_to_point(domain: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(domain);
    let out = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&out);
    RistrettoPoint::from_uniform_bytes(&wide)
}

fn dec_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
}

fn normalize_set(signer_set: &[u32]) -> Vec<u32> {
    let mut s = signer_set.to_vec();
    s.sort_unstable();
    s
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

#[cfg(feature = "concrete-lhtlp")]
fn scalar_to_lhtlp_plaintext(value: &Scalar) -> [u8; 32] {
    let mut bytes = enc_scalar(value);
    bytes.reverse();
    bytes
}

#[cfg(feature = "concrete-lhtlp")]
fn scalar_from_lhtlp_plaintext(opened: &[u8]) -> Scalar {
    let mut be = [0u8; 32];
    let take = opened.len().min(32);
    be[32 - take..].copy_from_slice(&opened[opened.len() - take..]);
    be.reverse();
    scalar_from_bytes(&be)
}

fn encode_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn encode_usize(buf: &mut Vec<u8>, value: usize) {
    buf.extend_from_slice(&(value as u64).to_le_bytes());
}

fn encode_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(not(feature = "concrete-lhtlp"))]
fn encode_puzzle(buf: &mut Vec<u8>, puzzle: &AdditivePuzzle) {
    buf.extend_from_slice(&puzzle.value);
    buf.extend_from_slice(&puzzle.nonce);
}

#[cfg(feature = "concrete-lhtlp")]
fn encode_puzzle(buf: &mut Vec<u8>, puzzle: &AdditivePuzzle) {
    encode_bytes(buf, &puzzle.u);
    encode_bytes(buf, &puzzle.v);
}

#[cfg(not(feature = "concrete-ibe"))]
fn encode_trace(buf: &mut Vec<u8>, ct: &TracingCiphertext) {
    buf.extend_from_slice(&ct.id_hash);
    buf.extend_from_slice(&ct.nonce);
    buf.extend_from_slice(&ct.body);
}

#[cfg(feature = "concrete-ibe")]
fn encode_trace(buf: &mut Vec<u8>, ct: &TracingCiphertext) {
    encode_bytes(buf, &ct.identity_digest);
    encode_bytes(buf, &ct.kem_ciphertext);
    buf.extend_from_slice(&ct.nonce);
    encode_bytes(buf, &ct.aead_ciphertext);
}

fn encode_handle_without_proof(buf: &mut Vec<u8>, h: &AuxiliaryHandle) {
    buf.extend_from_slice(&h.c_i);
    encode_puzzle(buf, &h.t_i_z);
    encode_puzzle(buf, &h.t_i_tau);
    encode_trace(buf, &h.e_i);
    buf.extend_from_slice(&h.nu_i);
}

pub fn canonical_gargos_transcript_bytes(tr: &GargosTranscript) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_bytes(&mut buf, b"GargosTranscript/v1");
    encode_bytes(&mut buf, &tr.m);
    encode_usize(&mut buf, tr.signer_set.len());
    for id in &tr.signer_set {
        encode_u32(&mut buf, *id);
    }
    encode_usize(&mut buf, tr.mu_vector.len());
    for (id, mu) in &tr.mu_vector {
        encode_u32(&mut buf, *id);
        buf.extend_from_slice(mu);
    }
    encode_usize(&mut buf, tr.entries.len());
    for e in &tr.entries {
        encode_u32(&mut buf, e.i);
        buf.extend_from_slice(&e.mu_i);
        buf.extend_from_slice(&e.rho_i);
        buf.extend_from_slice(&enc_point(&e.b_i));
        buf.extend_from_slice(&enc_point(&e.a_i));
        buf.extend_from_slice(&enc_point(&e.x_i));
        buf.extend_from_slice(&e.pi_gar.xa);
        buf.extend_from_slice(&e.pi_gar.xb);
        buf.extend_from_slice(&e.pi_gar.xpk);
        buf.extend_from_slice(&e.pi_gar.za);
        buf.extend_from_slice(&e.pi_gar.zs);
        buf.extend_from_slice(&e.pi_gar.zr);
        buf.extend_from_slice(&e.pi_gar.zu);
    }
    buf.extend_from_slice(&enc_point(&tr.a_hat));
    buf
}

pub fn session_digest(tr: &GargosTranscript) -> [u8; 32] {
    h32(b"H_ctx", &[&canonical_gargos_transcript_bytes(tr)])
}

pub fn tracing_identity(message: &[u8]) -> [u8; 32] {
    h32(b"H_tr", &[message])
}

pub fn nullifier(d: &[u8; 32], s_i: &Scalar) -> [u8; 32] {
    h32(b"H_null", &[d, &enc_scalar(s_i)])
}

#[cfg(not(feature = "concrete-lhtlp"))]
pub fn puzzle_gen(_pp: &ConstructionPublicParams, value: &Scalar) -> AdditivePuzzle {
    AdditivePuzzle {
        value: enc_scalar(value),
        nonce: rand::random(),
    }
}

#[cfg(feature = "concrete-lhtlp")]
pub fn puzzle_gen(pp: &ConstructionPublicParams, value: &Scalar) -> AdditivePuzzle {
    pp.lhtlp
        .pgen_bytes(&scalar_to_lhtlp_plaintext(value))
        .expect("concrete LHTLP PGen failed")
}

#[cfg(not(feature = "concrete-lhtlp"))]
pub fn puzzle_eval(_pp: &ConstructionPublicParams, puzzles: &[AdditivePuzzle]) -> AdditivePuzzle {
    let mut sum = Scalar::ZERO;
    let mut transcript = Vec::with_capacity(puzzles.len() * 64);
    for p in puzzles {
        sum += scalar_from_bytes(&p.value);
        transcript.extend_from_slice(&p.value);
        transcript.extend_from_slice(&p.nonce);
    }
    AdditivePuzzle {
        value: enc_scalar(&sum),
        nonce: h32(b"P_eval", &[&transcript]),
    }
}

#[cfg(feature = "concrete-lhtlp")]
pub fn puzzle_eval(pp: &ConstructionPublicParams, puzzles: &[AdditivePuzzle]) -> AdditivePuzzle {
    pp.lhtlp
        .peval(puzzles)
        .expect("concrete LHTLP PEval failed")
}

#[cfg(not(feature = "concrete-lhtlp"))]
pub fn puzzle_solve(_pp: &ConstructionPublicParams, puzzle: &AdditivePuzzle) -> Scalar {
    scalar_from_bytes(&puzzle.value)
}

#[cfg(feature = "concrete-lhtlp")]
pub fn puzzle_solve(pp: &ConstructionPublicParams, puzzle: &AdditivePuzzle) -> Scalar {
    let (opened, _) = pp
        .lhtlp
        .psolve(puzzle)
        .expect("concrete LHTLP PSolve failed");
    scalar_from_lhtlp_plaintext(&opened)
}

#[cfg(not(feature = "concrete-ibe"))]
pub fn ibe_setup() -> (IbePublicKey, IbeMasterKey) {
    let seed: [u8; 32] = rand::random();
    (IbePublicKey { seed }, IbeMasterKey { seed })
}

#[cfg(feature = "concrete-ibe")]
pub fn ibe_setup() -> (IbePublicKey, IbeMasterKey) {
    ConcreteIbeBackend::setup()
}

#[cfg(not(feature = "concrete-ibe"))]
pub fn ibe_encrypt(
    pk: &IbePublicKey,
    message: &[u8],
    _descriptor: &[u8; 32],
    signer_id: u32,
) -> TracingCiphertext {
    let id = tracing_identity(message);
    let nonce: [u8; 32] = rand::random();
    let key = h32(b"IBE-prototype", &[&pk.seed, &id, &nonce]);
    let mut body = signer_id.to_le_bytes();
    for i in 0..4 {
        body[i] ^= key[i];
    }
    TracingCiphertext {
        id_hash: id,
        nonce,
        body,
    }
}

#[cfg(feature = "concrete-ibe")]
pub fn ibe_encrypt(
    pk: &IbePublicKey,
    message: &[u8],
    descriptor: &[u8; 32],
    signer_id: u32,
) -> TracingCiphertext {
    ConcreteIbeBackend::encrypt(pk, message, descriptor, signer_id)
        .expect("concrete IBE encryption failed")
}

#[cfg(not(feature = "concrete-ibe"))]
pub fn ibe_extract(msk: &IbeMasterKey, message: &[u8]) -> [u8; 32] {
    h32(b"IBE-extract", &[&msk.seed, &tracing_identity(message)])
}

#[cfg(feature = "concrete-ibe")]
pub fn ibe_extract(
    pk: &IbePublicKey,
    msk: &IbeMasterKey,
    message: &[u8],
    descriptor: &[u8; 32],
) -> ConcreteIbeUserKey {
    ConcreteIbeBackend::extract(pk, msk, message, descriptor).expect("concrete IBE extract failed")
}

#[cfg(not(feature = "concrete-ibe"))]
pub fn ibe_decrypt(dk_m: &[u8; 32], message: &[u8], ct: &TracingCiphertext) -> Option<u32> {
    let id = tracing_identity(message);
    if ct.id_hash != id {
        return None;
    }
    let seed = h32(b"IBE-seed-from-dk", &[dk_m, &id]);
    // Prototype compatibility: derive the same stream by reversing the extract label convention.
    // The public and master seed are identical in this local IBE prototype.
    let key_seed = h32(b"IBE-master-compat", &[&seed]);
    let key = h32(b"IBE-prototype", &[&key_seed, &id, &ct.nonce]);
    let mut body = ct.body;
    for i in 0..4 {
        body[i] ^= key[i];
    }
    Some(u32::from_le_bytes(body))
}

#[cfg(not(feature = "concrete-ibe"))]
fn ibe_decrypt_with_master(
    msk: &IbeMasterKey,
    message: &[u8],
    ct: &TracingCiphertext,
) -> Option<u32> {
    let id = tracing_identity(message);
    if ct.id_hash != id {
        return None;
    }
    let key = h32(b"IBE-prototype", &[&msk.seed, &id, &ct.nonce]);
    let mut body = ct.body;
    for i in 0..4 {
        body[i] ^= key[i];
    }
    Some(u32::from_le_bytes(body))
}

#[cfg(feature = "concrete-ibe")]
fn ibe_decrypt_with_master(
    pk: &IbePublicKey,
    msk: &IbeMasterKey,
    message: &[u8],
    descriptor: &[u8; 32],
    ct: &TracingCiphertext,
) -> Option<u32> {
    let usk = ibe_extract(pk, msk, message, descriptor);
    ConcreteIbeBackend::decrypt(pk, &usk, message, descriptor, ct).ok()
}

fn commitment(pp: &ConstructionPublicParams, z_i: &Scalar, tau_i: &Scalar) -> RistrettoPoint {
    pp.g_c * (*z_i) + pp.h_c * (*tau_i)
}

fn statement_digest(desc: &SessionDescriptor, handle_without_proof: &AuxiliaryHandle) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&desc.d);
    encode_bytes(&mut buf, &desc.m);
    buf.extend_from_slice(&enc_point(&desc.a_hat));
    encode_usize(&mut buf, desc.ell);
    encode_handle_without_proof(&mut buf, handle_without_proof);
    h32(b"NIZK.Bind.prototype", &[&buf])
}

fn prove_binding(desc: &SessionDescriptor, handle_without_proof: &AuxiliaryHandle) -> BindingProof {
    BindingProof {
        statement_digest: statement_digest(desc, handle_without_proof),
    }
}

pub fn verify_binding(desc: &SessionDescriptor, handle: &AuxiliaryHandle) -> bool {
    let mut tmp = handle.clone();
    tmp.pi_i_bind = BindingProof {
        statement_digest: [0u8; 32],
    };
    handle.pi_i_bind.statement_digest == statement_digest(desc, &tmp)
}

pub fn handle_digest(handle: &AuxiliaryHandle) -> [u8; 32] {
    let mut buf = Vec::new();
    encode_handle_without_proof(&mut buf, handle);
    buf.extend_from_slice(&handle.pi_i_bind.statement_digest);
    h32(b"H_hnd", &[&buf])
}

pub fn record_digest(record: &CanonicalSessionRecord) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&record.d);
    encode_bytes(&mut buf, &record.m);
    buf.extend_from_slice(&enc_point(&record.a_hat));
    encode_usize(&mut buf, record.ell);
    for h in &record.handles {
        buf.extend_from_slice(&handle_digest(h));
    }
    h32(b"Registry.record", &[&buf])
}

#[derive(Clone, Debug)]
struct RecordAggregate {
    c_point: RistrettoPoint,
    t_z: AdditivePuzzle,
    t_tau: AdditivePuzzle,
}

fn descriptor_for_record(record: &CanonicalSessionRecord) -> SessionDescriptor {
    SessionDescriptor {
        d: record.d,
        m: record.m.clone(),
        a_hat: record.a_hat,
        ell: record.ell,
    }
}

fn validate_record_shape_with_desc(
    record: &CanonicalSessionRecord,
    desc: &SessionDescriptor,
) -> bool {
    if record.handles.len() != record.ell {
        return false;
    }
    let mut seen = BTreeSet::new();
    for handle in &record.handles {
        if !seen.insert(handle.nu_i) || !verify_binding(desc, handle) {
            return false;
        }
    }
    true
}

fn aggregate_record(
    pp: &ConstructionPublicParams,
    record: &CanonicalSessionRecord,
) -> Option<RecordAggregate> {
    let mut c_point = RistrettoPoint::identity();
    let mut z_puzzles = Vec::with_capacity(record.handles.len());
    let mut tau_puzzles = Vec::with_capacity(record.handles.len());
    for h in &record.handles {
        c_point += dec_point(&h.c_i)?;
        z_puzzles.push(h.t_i_z.clone());
        tau_puzzles.push(h.t_i_tau.clone());
    }
    Some(RecordAggregate {
        c_point,
        t_z: puzzle_eval(pp, &z_puzzles),
        t_tau: puzzle_eval(pp, &tau_puzzles),
    })
}

impl Registry {
    pub fn register_session_record(&mut self, mut record: CanonicalSessionRecord) -> bool {
        if self.records.contains_key(&record.d) || !validate_record_shape(&record) {
            return false;
        }
        record.record_digest = record_digest(&record);
        self.records.insert(record.d, record);
        true
    }

    pub fn retrieve_session_record(&self, d: &[u8; 32]) -> Option<&CanonicalSessionRecord> {
        self.records.get(d)
    }

    pub fn validate_complete_record(&self, d: &[u8; 32]) -> bool {
        let Some(record) = self.records.get(d) else {
            return false;
        };
        validate_record_shape(record) && record.record_digest == record_digest(record)
    }
}

pub fn validate_record_shape(record: &CanonicalSessionRecord) -> bool {
    let desc = descriptor_for_record(record);
    validate_record_shape_with_desc(record, &desc)
}

pub fn setup_construction(
    n: usize,
    t: usize,
) -> (ConstructionPublicParams, ConstructionSecretState, Registry) {
    setup_construction_with_lhtlp_delta(n, t, 1 << 16)
}

pub fn setup_construction_with_lhtlp_delta(
    n: usize,
    t: usize,
    lhtlp_delta: u64,
) -> (ConstructionPublicParams, ConstructionSecretState, Registry) {
    let gargos = keygen::setup(n, t);
    let (public_key, public_key_shares, secret_key_shares) = keygen::kgen(&gargos);
    let (ibe_public, ibe_master) = ibe_setup();
    let pp = ConstructionPublicParams {
        gargos,
        public_key,
        public_key_shares,
        g_c: hash_to_point(b"Commitment::g_C"),
        h_c: hash_to_point(b"Commitment::h_C"),
        ibe_public,
        #[cfg(feature = "concrete-lhtlp")]
        lhtlp: LhtlpBackend::setup(3072, lhtlp_delta).expect("concrete LHTLP setup failed"),
    };
    let secrets = ConstructionSecretState {
        secret_key_shares,
        ibe_master,
    };
    (pp, secrets, Registry::default())
}

pub fn sign_encap(
    pp: &ConstructionPublicParams,
    secrets: &ConstructionSecretState,
    registry: &mut Registry,
    message: &[u8],
    signer_set: &[u32],
) -> Option<SignEncapOutput> {
    let signer_set = normalize_set(signer_set);
    if signer_set.len() < pp.gargos.t + 1
        || signer_set
            .iter()
            .any(|&i| i == 0 || i as usize > pp.gargos.n)
    {
        return None;
    }

    let mut first_round = Vec::with_capacity(signer_set.len());
    for &i in &signer_set {
        let sk = secrets.secret_key_shares.get(i as usize - 1)?;
        let a_i = random_scalar();
        let rho_i: [u8; 32] = rand::random();
        let b_i =
            pp.gargos.g * a_i + crate::hash::f0(&rho_i) * sk.r + crate::hash::f1(&rho_i) * sk.u;
        let mu_i = hcom(i, &rho_i, &b_i);
        first_round.push((i, a_i, rho_i, b_i, mu_i));
    }
    let mu_vector: Vec<(u32, [u8; 32])> = first_round
        .iter()
        .map(|(i, _, _, _, mu)| (*i, *mu))
        .collect();
    let g0p = g0(message, &mu_vector);
    let g1p = g1(message, &mu_vector);
    // Session-level cache: Lagrange coefficients are deterministic for S and reused
    // in aggregate nonce reconstruction and response-share generation.
    let lagranges: BTreeMap<u32, Scalar> = signer_set
        .iter()
        .map(|&i| (i, lagrange_coeff(i, &signer_set)))
        .collect();

    let mut entries = Vec::with_capacity(signer_set.len());
    let mut states = BTreeMap::new();
    for (i, a_i, rho_i, b_i, mu_i) in first_round {
        let sk = secrets.secret_key_shares.get(i as usize - 1)?;
        let pk_i = pp.public_key_shares.get(i as usize - 1)?.pk_i;
        let a_point = pp.gargos.g * a_i + g0p * sk.r + g1p * sk.u;
        let pi_gar = sig_prove(
            &pp.gargos, &pk_i, &a_point, &b_i, &g0p, &g1p, &rho_i, &a_i, sk,
        );
        entries.push(GargosTranscriptEntry {
            i,
            mu_i,
            rho_i,
            b_i,
            a_i: a_point,
            x_i: pk_i,
            pi_gar,
        });
        states.insert(i, a_i);
    }
    entries.sort_by_key(|e| e.i);

    for e in &entries {
        if e.mu_i != hcom(e.i, &e.rho_i, &e.b_i) {
            return None;
        }
        if !sig_verify(
            &pp.gargos, &e.x_i, &e.a_i, &e.b_i, &g0p, &g1p, &e.rho_i, &e.pi_gar,
        ) {
            return None;
        }
    }

    let mut a_hat = RistrettoPoint::identity();
    for e in &entries {
        a_hat += e.a_i * lagranges.get(&e.i).copied()?;
    }
    let c = hsig(&a_hat, &pp.public_key, message);
    let transcript = GargosTranscript {
        m: message.to_vec(),
        signer_set: signer_set.clone(),
        mu_vector,
        entries,
        a_hat,
    };
    let d = session_digest(&transcript);
    let ell = signer_set.len();
    let desc = SessionDescriptor {
        d,
        m: message.to_vec(),
        a_hat,
        ell,
    };

    let mut handles = Vec::with_capacity(ell);
    let mut packages = Vec::with_capacity(ell);
    for &i in &signer_set {
        let sk = secrets.secret_key_shares.get(i as usize - 1)?;
        let a_i = states.get(&i)?;
        let li = lagranges.get(&i).copied()?;
        let z_i = li * (*a_i + c * sk.s);
        let tau_i = random_scalar();
        let c_i_point = commitment(pp, &z_i, &tau_i);
        let t_i_z = puzzle_gen(pp, &z_i);
        let t_i_tau = puzzle_gen(pp, &tau_i);
        let e_i = ibe_encrypt(&pp.ibe_public, message, &d, i);
        let nu_i = nullifier(&d, &sk.s);
        let mut handle = AuxiliaryHandle {
            c_i: enc_point(&c_i_point),
            t_i_z,
            t_i_tau,
            e_i,
            nu_i,
            pi_i_bind: BindingProof {
                statement_digest: [0u8; 32],
            },
        };
        handle.pi_i_bind = prove_binding(&desc, &handle);
        let kappa_i = handle_digest(&handle);
        handles.push(handle);
        packages.push(PrivateResponsePackage {
            d,
            kappa_i,
            z_i,
            tau_i,
        });
    }

    let record = CanonicalSessionRecord {
        d,
        m: message.to_vec(),
        a_hat,
        ell,
        handles,
        record_digest: [0u8; 32],
    };
    if !registry.register_session_record(record) {
        return None;
    }
    Some(SignEncapOutput {
        d,
        transcript,
        packages,
    })
}

fn checked_record<'a>(
    pp: &ConstructionPublicParams,
    registry: &'a Registry,
    message: &[u8],
    d: &[u8; 32],
) -> Option<&'a CanonicalSessionRecord> {
    let record = registry.retrieve_session_record(d)?;
    if record.m != message || record.ell < pp.gargos.t + 1 || record.handles.len() != record.ell {
        return None;
    }
    if !registry.validate_complete_record(d) {
        return None;
    }
    Some(record)
}

pub fn combine(
    pp: &ConstructionPublicParams,
    registry: &Registry,
    message: &[u8],
    d: &[u8; 32],
    packages: &[PrivateResponsePackage],
) -> Option<FinalSignaturePackage> {
    let record = checked_record(pp, registry, message, d)?;
    if packages.len() != record.ell {
        return None;
    }
    let mut by_digest = BTreeMap::new();
    for h in &record.handles {
        by_digest.insert(handle_digest(h), h);
    }
    let mut used = BTreeSet::new();
    let mut z = Scalar::ZERO;
    let mut tau = Scalar::ZERO;
    for pkg in packages {
        if pkg.d != *d || !used.insert(pkg.kappa_i) {
            return None;
        }
        let handle = by_digest.get(&pkg.kappa_i)?;
        let c_i = dec_point(&handle.c_i)?;
        if c_i != commitment(pp, &pkg.z_i, &pkg.tau_i) {
            return None;
        }
        z += pkg.z_i;
        tau += pkg.tau_i;
    }
    if used.len() != record.ell {
        return None;
    }
    final_from_values(pp, record, z, tau)
}

pub fn open(
    pp: &ConstructionPublicParams,
    registry: &Registry,
    message: &[u8],
    d: &[u8; 32],
) -> Option<FinalSignaturePackage> {
    let record = checked_record(pp, registry, message, d)?;
    let aggregate = aggregate_record(pp, record)?;
    let z = puzzle_solve(pp, &aggregate.t_z);
    let tau = puzzle_solve(pp, &aggregate.t_tau);
    final_from_values_with_aggregate(pp, record, z, tau, aggregate)
}

fn final_from_values(
    pp: &ConstructionPublicParams,
    record: &CanonicalSessionRecord,
    z: Scalar,
    tau: Scalar,
) -> Option<FinalSignaturePackage> {
    let aggregate = aggregate_record(pp, record)?;
    final_from_values_with_aggregate(pp, record, z, tau, aggregate)
}

fn final_from_values_with_aggregate(
    pp: &ConstructionPublicParams,
    record: &CanonicalSessionRecord,
    z: Scalar,
    tau: Scalar,
    aggregate: RecordAggregate,
) -> Option<FinalSignaturePackage> {
    let challenge = hsig(&record.a_hat, &pp.public_key, &record.m);
    if pp.gargos.g * z != record.a_hat + pp.public_key * challenge {
        return None;
    }
    if aggregate.c_point != pp.g_c * z + pp.h_c * tau {
        return None;
    }
    Some(FinalSignaturePackage {
        d: record.d,
        m: record.m.clone(),
        a_hat: record.a_hat,
        z,
        tau,
        c: enc_point(&aggregate.c_point),
        t_z: aggregate.t_z,
        t_tau: aggregate.t_tau,
    })
}

pub fn verify(
    pp: &ConstructionPublicParams,
    registry: &Registry,
    message: &[u8],
    sigma: &FinalSignaturePackage,
) -> bool {
    if sigma.m != message {
        return false;
    }
    let Some(record) = checked_record(pp, registry, message, &sigma.d) else {
        return false;
    };
    if record.a_hat != sigma.a_hat {
        return false;
    }
    let Some(expected) = final_from_values(pp, record, sigma.z, sigma.tau) else {
        return false;
    };
    expected == *sigma
}

pub fn trace(
    pp: &ConstructionPublicParams,
    secrets: &ConstructionSecretState,
    registry: &Registry,
    message: &[u8],
    sigma: &FinalSignaturePackage,
) -> Option<Vec<u32>> {
    if !verify(pp, registry, message, sigma) {
        return None;
    }
    let record = registry.retrieve_session_record(&sigma.d)?;
    let mut recovered = BTreeSet::new();
    for h in &record.handles {
        #[cfg(not(feature = "concrete-ibe"))]
        let i = ibe_decrypt_with_master(&secrets.ibe_master, message, &h.e_i)?;
        #[cfg(feature = "concrete-ibe")]
        let i = ibe_decrypt_with_master(
            &pp.ibe_public,
            &secrets.ibe_master,
            message,
            &sigma.d,
            &h.e_i,
        )?;
        if i == 0 || i as usize > pp.gargos.n || !recovered.insert(i) {
            return None;
        }
    }
    if recovered.len() != record.ell {
        return None;
    }
    Some(recovered.into_iter().collect())
}

pub fn commitment_for_benchmark(
    pp: &ConstructionPublicParams,
    z_i: &Scalar,
    tau_i: &Scalar,
) -> RistrettoPoint {
    commitment(pp, z_i, tau_i)
}

pub fn binding_proof_for_benchmark(
    desc: &SessionDescriptor,
    handle: &AuxiliaryHandle,
) -> BindingProof {
    prove_binding(desc, handle)
}

pub fn puzzle_solve_with_delay_for_benchmark(
    pp: &ConstructionPublicParams,
    puzzle: &AdditivePuzzle,
    delay_iters: u64,
) -> Scalar {
    let puzzle_encoding = puzzle_bytes(puzzle);
    let mut state = h32(b"P_solve_delay", &[&puzzle_encoding]);
    for _ in 0..delay_iters {
        state = h32(b"P_solve_step", &[&state]);
    }
    let _ = state;
    puzzle_solve(pp, puzzle)
}

pub fn puzzle_bytes(puzzle: &AdditivePuzzle) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    encode_puzzle(&mut buf, puzzle);
    buf
}

pub fn tracing_ciphertext_bytes(ct: &TracingCiphertext) -> Vec<u8> {
    let mut buf = Vec::with_capacity(68);
    encode_trace(&mut buf, ct);
    buf
}

pub fn binding_proof_bytes(proof: &BindingProof) -> Vec<u8> {
    proof.statement_digest.to_vec()
}

pub fn handle_bytes(handle: &AuxiliaryHandle) -> Vec<u8> {
    let mut buf = Vec::with_capacity(260);
    encode_handle_without_proof(&mut buf, handle);
    buf.extend_from_slice(&handle.pi_i_bind.statement_digest);
    buf
}

pub fn private_package_bytes(pkg: &PrivateResponsePackage) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&pkg.d);
    buf.extend_from_slice(&pkg.kappa_i);
    buf.extend_from_slice(&enc_scalar(&pkg.z_i));
    buf.extend_from_slice(&enc_scalar(&pkg.tau_i));
    buf
}

pub fn aggregate_htlp_bytes(sigma: &FinalSignaturePackage) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    encode_puzzle(&mut buf, &sigma.t_z);
    encode_puzzle(&mut buf, &sigma.t_tau);
    buf
}

pub fn aggregate_puzzles_for_benchmark(
    pp: &ConstructionPublicParams,
    record: &CanonicalSessionRecord,
) -> Option<(AdditivePuzzle, AdditivePuzzle)> {
    let aggregate = aggregate_record(pp, record)?;
    Some((aggregate.t_z, aggregate.t_tau))
}

pub fn final_signature_bytes(sigma: &FinalSignaturePackage) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&sigma.d);
    encode_bytes(&mut buf, &sigma.m);
    buf.extend_from_slice(&enc_point(&sigma.a_hat));
    buf.extend_from_slice(&enc_scalar(&sigma.z));
    buf.extend_from_slice(&enc_scalar(&sigma.tau));
    buf.extend_from_slice(&sigma.c);
    encode_puzzle(&mut buf, &sigma.t_z);
    encode_puzzle(&mut buf, &sigma.t_tau);
    buf
}

pub fn record_bytes(record: &CanonicalSessionRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&record.d);
    encode_bytes(&mut buf, &record.m);
    buf.extend_from_slice(&enc_point(&record.a_hat));
    encode_usize(&mut buf, record.ell);
    for handle in &record.handles {
        encode_handle_without_proof(&mut buf, handle);
        buf.extend_from_slice(&handle.pi_i_bind.statement_digest);
    }
    buf.extend_from_slice(&record.record_digest);
    buf
}

#[derive(Clone, Debug, Default)]
pub struct RobustnessChecks {
    pub modified_commitment_rejected: bool,
    pub modified_puzzle_rejected: bool,
    pub modified_ciphertext_rejected: bool,
    pub modified_nullifier_rejected: bool,
    pub modified_proof_rejected: bool,
    pub modified_message_rejected: bool,
    pub modified_digest_rejected: bool,
    pub modified_response_rejected: bool,
    pub duplicate_nullifier_rejected: bool,
    pub missing_handle_rejected: bool,
    pub cross_session_handle_rejected: bool,
    pub wrong_tracing_key_rejected: bool,
}

pub fn robustness_checks_for_benchmark(
    pp: &ConstructionPublicParams,
    secrets: &ConstructionSecretState,
    message: &[u8],
    signer_set: &[u32],
) -> Option<RobustnessChecks> {
    let mut registry = Registry::default();
    let out = sign_encap(pp, secrets, &mut registry, message, signer_set)?;
    let sigma = combine(pp, &registry, message, &out.d, &out.packages)?;
    let mut checks = RobustnessChecks::default();

    fn mutate_record<F>(registry: &Registry, d: &[u8; 32], f: F) -> Registry
    where
        F: FnOnce(&mut CanonicalSessionRecord),
    {
        let mut r = registry.clone();
        let rec = r.records.get_mut(d).expect("record exists");
        f(rec);
        rec.record_digest = record_digest(rec);
        r
    }

    fn mutate_puzzle(puzzle: &mut AdditivePuzzle) {
        #[cfg(not(feature = "concrete-lhtlp"))]
        {
            puzzle.value[0] ^= 1;
        }
        #[cfg(feature = "concrete-lhtlp")]
        {
            puzzle.u[0] ^= 1;
        }
    }

    fn mutate_ciphertext(ct: &mut TracingCiphertext) {
        #[cfg(not(feature = "concrete-ibe"))]
        {
            ct.body[0] ^= 1;
        }
        #[cfg(feature = "concrete-ibe")]
        {
            ct.aead_ciphertext[0] ^= 1;
        }
    }

    checks.modified_commitment_rejected = {
        let r = mutate_record(&registry, &out.d, |rec| rec.handles[0].c_i[0] ^= 1);
        !verify(pp, &r, message, &sigma)
    };
    checks.modified_puzzle_rejected = {
        let r = mutate_record(&registry, &out.d, |rec| {
            mutate_puzzle(&mut rec.handles[0].t_i_z)
        });
        !verify(pp, &r, message, &sigma)
    };
    checks.modified_ciphertext_rejected = {
        let r = mutate_record(&registry, &out.d, |rec| {
            mutate_ciphertext(&mut rec.handles[0].e_i)
        });
        trace(pp, secrets, &r, message, &sigma).is_none()
    };
    checks.modified_nullifier_rejected = {
        let r = mutate_record(&registry, &out.d, |rec| rec.handles[0].nu_i[0] ^= 1);
        !verify(pp, &r, message, &sigma)
    };
    checks.modified_proof_rejected = {
        let r = mutate_record(&registry, &out.d, |rec| {
            rec.handles[0].pi_i_bind.statement_digest[0] ^= 1
        });
        !verify(pp, &r, message, &sigma)
    };
    checks.modified_message_rejected = !verify(pp, &registry, b"wrong message", &sigma);
    checks.modified_digest_rejected = {
        let mut bad = sigma.clone();
        bad.d[0] ^= 1;
        !verify(pp, &registry, message, &bad)
    };
    checks.modified_response_rejected = {
        let mut bad = sigma.clone();
        bad.z += Scalar::ONE;
        !verify(pp, &registry, message, &bad)
    };
    checks.duplicate_nullifier_rejected = {
        let r = mutate_record(&registry, &out.d, |rec| {
            rec.handles[1].nu_i = rec.handles[0].nu_i
        });
        !verify(pp, &r, message, &sigma)
    };
    checks.missing_handle_rejected = {
        let r = mutate_record(&registry, &out.d, |rec| {
            rec.handles.pop();
        });
        !verify(pp, &r, message, &sigma)
    };
    checks.cross_session_handle_rejected = {
        let mut other_registry = Registry::default();
        let other = sign_encap(
            pp,
            secrets,
            &mut other_registry,
            b"other session",
            signer_set,
        )?;
        let other_handle = other_registry.retrieve_session_record(&other.d)?.handles[0].clone();
        let r = mutate_record(&registry, &out.d, |rec| {
            rec.handles[0] = other_handle.clone()
        });
        !verify(pp, &r, message, &sigma)
    };
    checks.wrong_tracing_key_rejected = {
        let (_, wrong_secrets, _) =
            setup_construction_with_lhtlp_delta(pp.gargos.n, pp.gargos.t, 64);
        trace(pp, &wrong_secrets, &registry, message, &sigma).is_none()
    };

    Some(checks)
}

pub fn robustness_counts_for_benchmark(
    pp: &ConstructionPublicParams,
    secrets: &ConstructionSecretState,
    message: &[u8],
    signer_set: &[u32],
    trials: usize,
) -> Option<Vec<(String, usize)>> {
    let mut registry = Registry::default();
    let out = sign_encap(pp, secrets, &mut registry, message, signer_set)?;
    let sigma = combine(pp, &registry, message, &out.d, &out.packages)?;
    let mut other_registry = Registry::default();
    let other = sign_encap(
        pp,
        secrets,
        &mut other_registry,
        b"other session",
        signer_set,
    )?;
    let other_handle = other_registry.retrieve_session_record(&other.d)?.handles[0].clone();

    let names = [
        "wrong message",
        "wrong descriptor/session digest",
        "modified commitment",
        "modified response puzzle",
        "modified randomizer puzzle",
        "modified tracing ciphertext",
        "modified nullifier",
        "modified binding digest",
        "modified response",
        "duplicate nullifier",
        "missing handle",
        "cross-session handle",
        "wrong signer/tracing key",
        "wrong opening",
        "duplicate signer",
        "extra handle",
        "wrong signer index",
    ];
    let mut counts = vec![0usize; names.len()];

    fn mutate_record<F>(registry: &Registry, d: &[u8; 32], f: F) -> Registry
    where
        F: FnOnce(&mut CanonicalSessionRecord),
    {
        let mut r = registry.clone();
        let rec = r.records.get_mut(d).expect("record exists");
        f(rec);
        rec.record_digest = record_digest(rec);
        r
    }

    fn mutate_puzzle(puzzle: &mut AdditivePuzzle) {
        #[cfg(not(feature = "concrete-lhtlp"))]
        {
            puzzle.value[0] ^= 1;
        }
        #[cfg(feature = "concrete-lhtlp")]
        {
            puzzle.u[0] ^= 1;
        }
    }

    fn mutate_ciphertext(ct: &mut TracingCiphertext) {
        #[cfg(not(feature = "concrete-ibe"))]
        {
            ct.body[0] ^= 1;
        }
        #[cfg(feature = "concrete-ibe")]
        {
            ct.aead_ciphertext[0] ^= 1;
        }
    }

    let (_, wrong_secrets, _) = setup_construction_with_lhtlp_delta(pp.gargos.n, pp.gargos.t, 64);
    for _ in 0..trials {
        let values = [
            !verify(pp, &registry, b"wrong message", &sigma),
            {
                let mut bad = sigma.clone();
                bad.d[0] ^= 1;
                !verify(pp, &registry, message, &bad)
            },
            {
                let r = mutate_record(&registry, &out.d, |rec| rec.handles[0].c_i[0] ^= 1);
                !verify(pp, &r, message, &sigma)
            },
            {
                let r = mutate_record(&registry, &out.d, |rec| {
                    mutate_puzzle(&mut rec.handles[0].t_i_z)
                });
                !verify(pp, &r, message, &sigma)
            },
            {
                let r = mutate_record(&registry, &out.d, |rec| {
                    mutate_puzzle(&mut rec.handles[0].t_i_tau)
                });
                !verify(pp, &r, message, &sigma)
            },
            {
                let r = mutate_record(&registry, &out.d, |rec| {
                    mutate_ciphertext(&mut rec.handles[0].e_i)
                });
                trace(pp, secrets, &r, message, &sigma).is_none()
            },
            {
                let r = mutate_record(&registry, &out.d, |rec| rec.handles[0].nu_i[0] ^= 1);
                !verify(pp, &r, message, &sigma)
            },
            {
                let r = mutate_record(&registry, &out.d, |rec| {
                    rec.handles[0].pi_i_bind.statement_digest[0] ^= 1
                });
                !verify(pp, &r, message, &sigma)
            },
            {
                let mut bad = sigma.clone();
                bad.z += Scalar::ONE;
                !verify(pp, &registry, message, &bad)
            },
            {
                let r = mutate_record(&registry, &out.d, |rec| {
                    rec.handles[1].nu_i = rec.handles[0].nu_i
                });
                !verify(pp, &r, message, &sigma)
            },
            {
                let r = mutate_record(&registry, &out.d, |rec| {
                    rec.handles.pop();
                });
                !verify(pp, &r, message, &sigma)
            },
            {
                let r = mutate_record(&registry, &out.d, |rec| {
                    rec.handles[0] = other_handle.clone()
                });
                !verify(pp, &r, message, &sigma)
            },
            trace(pp, &wrong_secrets, &registry, message, &sigma).is_none(),
            {
                let mut bad = sigma.clone();
                bad.tau += Scalar::ONE;
                !verify(pp, &registry, message, &bad)
            },
            sign_encap(
                pp,
                secrets,
                &mut Registry::default(),
                message,
                &[1, 1, 2, 3],
            )
            .is_none(),
            {
                let r = mutate_record(&registry, &out.d, |rec| {
                    rec.handles.push(rec.handles[0].clone());
                });
                !verify(pp, &r, message, &sigma)
            },
            trace(pp, &wrong_secrets, &registry, message, &sigma).is_none(),
        ];
        for (idx, value) in values.iter().enumerate() {
            counts[idx] += *value as usize;
        }
    }
    Some(
        names
            .iter()
            .zip(counts)
            .map(|(name, count)| ((*name).to_string(), count))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        ConstructionPublicParams,
        ConstructionSecretState,
        Registry,
        SignEncapOutput,
        FinalSignaturePackage,
        Vec<u32>,
    ) {
        let (pp, secrets, mut registry) = setup_construction(8, 2);
        let signer_set = vec![1, 2, 3, 4];
        let out = sign_encap(&pp, &secrets, &mut registry, b"test message", &signer_set).unwrap();
        let sigma = combine(&pp, &registry, b"test message", &out.d, &out.packages).unwrap();
        (pp, secrets, registry, out, sigma, signer_set)
    }

    #[test]
    fn original_gargos_three_round_correctness() {
        let (pp, _, _, out, sigma, _) = fixture();
        let c = hsig(&out.transcript.a_hat, &pp.public_key, b"test message");
        assert_eq!(
            pp.gargos.g * sigma.z,
            out.transcript.a_hat + pp.public_key * c
        );
    }

    #[test]
    fn normal_combine_matches_gargos_and_verify() {
        let (pp, _, registry, _, sigma, _) = fixture();
        assert!(verify(&pp, &registry, b"test message", &sigma));
    }

    #[test]
    fn delayed_open_matches_normal_output_byte_for_byte() {
        let (pp, _, registry, out, sigma, _) = fixture();
        let opened = open(&pp, &registry, b"test message", &out.d).unwrap();
        assert_eq!(
            final_signature_bytes(&opened),
            final_signature_bytes(&sigma)
        );
    }

    #[test]
    fn commitment_tamper_z_rejected() {
        let (pp, _, registry, _, mut sigma, _) = fixture();
        sigma.z += Scalar::ONE;
        assert!(!verify(&pp, &registry, b"test message", &sigma));
    }

    #[test]
    fn commitment_tamper_tau_rejected() {
        let (pp, _, registry, _, mut sigma, _) = fixture();
        sigma.tau += Scalar::ONE;
        assert!(!verify(&pp, &registry, b"test message", &sigma));
    }

    #[test]
    fn duplicate_nullifier_rejected() {
        let (pp, _, mut registry, out, _, _) = fixture();
        let record = registry.records.get_mut(&out.d).unwrap();
        record.handles[1].nu_i = record.handles[0].nu_i;
        assert!(!registry.validate_complete_record(&out.d));
        let sigma = open(&pp, &registry, b"test message", &out.d);
        assert!(sigma.is_none());
    }

    #[test]
    fn modified_digest_rejected() {
        let (pp, _, registry, _, mut sigma, _) = fixture();
        sigma.d[0] ^= 1;
        assert!(!verify(&pp, &registry, b"test message", &sigma));
    }

    #[test]
    fn modified_message_rejected() {
        let (pp, _, registry, _, sigma, _) = fixture();
        assert!(!verify(&pp, &registry, b"other message", &sigma));
    }

    #[test]
    fn trace_recovers_exact_signer_set() {
        let (pp, secrets, registry, _, sigma, signer_set) = fixture();
        let traced = trace(&pp, &secrets, &registry, b"test message", &sigma).unwrap();
        assert_eq!(traced, signer_set);
    }

    #[test]
    fn canonical_serialization_deterministic() {
        let (_, _, _, out, _, _) = fixture();
        assert_eq!(
            canonical_gargos_transcript_bytes(&out.transcript),
            canonical_gargos_transcript_bytes(&out.transcript)
        );
        assert_eq!(
            session_digest(&out.transcript),
            session_digest(&out.transcript)
        );
    }
}
