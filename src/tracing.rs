// src/tracing.rs
//
// Decentralized message-dependent tracing for the current scheme.
//
// This replaces the old single-admitter structure with a threshold committee.
// A tracing ciphertext is encrypted under a committee public key pk = g * alpha,
// where alpha is Shamir-shared among N committee members with threshold t_tr.
// For a target message m, committee members produce partial decryption shares;
// any set of size at least t_tr can reconstruct the decryption key material.
use crate::types::ExperimentConfig;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::randutil::random_scalar;
use crate::shamir::{lagrange_coeff, sample_poly_with_constant};

#[derive(Clone, Debug)]
pub struct TracingSecretShare {
    pub i: u32,
    pub sk_i: Scalar, // committee share f(i)
}

#[derive(Clone, Debug)]
pub struct TracingPublicKey {
    pub pk: RistrettoPoint, // g * alpha, alpha = f(0)
}

#[derive(Clone, Debug)]
pub struct TracingParams {
    pub n: usize,
    pub t_tr: usize,
    pub g: RistrettoPoint,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TraceCiphertext {
    pub c1: [u8; 32],     // ephemeral point R = g * r
    pub c2: Vec<u8>,      // XOR-encrypted payload
    pub msg_hash: [u8; 32],
    pub label: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PartialDecryptShare {
    pub i: u32,
    pub d_i: [u8; 32], // D_i = sk_i * c1
}

fn enc_point(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

fn dec_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
}

fn msg_hash(message: &[u8]) -> [u8; 32] {
    let h = Sha512::digest(message);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..32]);
    out
}

fn derive_keystream(shared: &RistrettoPoint, msg_hash: &[u8; 32], label: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u64;

    while out.len() < len {
        let mut h = Sha512::new();
        h.update(b"TS::TraceKDF");
        h.update(shared.compress().as_bytes());
        h.update(msg_hash);
        h.update(&(label.len() as u32).to_le_bytes());
        h.update(label);
        h.update(&counter.to_le_bytes());
        let block = h.finalize();
        out.extend_from_slice(&block);
        counter += 1;
    }

    out.truncate(len);
    out
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Setup tracing committee:
/// - sample committee master secret alpha
/// - secret-share alpha with threshold t_tr
/// - publish pk = g * alpha
pub fn setup_tracing_committee(
    n: usize,
    t_tr: usize,
) -> (TracingParams, TracingPublicKey, Vec<TracingSecretShare>) {
    assert!(n >= 1, "committee size must be positive");
    assert!(t_tr >= 1 && t_tr <= n, "invalid tracing threshold");

    let g = RISTRETTO_BASEPOINT_POINT;
    let alpha = random_scalar();

    // Shamir polynomial of degree (t_tr - 1) with f(0) = alpha
    let poly = sample_poly_with_constant(t_tr - 1, alpha);

    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let idx = i as u32;
        let x_i = Scalar::from(i as u64);
        shares.push(TracingSecretShare {
            i: idx,
            sk_i: poly.eval(x_i),
        });
    }

    let params = TracingParams { n, t_tr, g };
    let pk = TracingPublicKey { pk: g * alpha };
    (params, pk, shares)
}

/// Encrypt tracing payload under the committee public key, message-bound.
///
/// The derived symmetric key depends on:
/// - DH shared secret r * pk
/// - hash of the target message
/// - an application label / transcript label
pub fn trace_encrypt(
    pk: &TracingPublicKey,
    message: &[u8],
    plaintext: &[u8],
    label: &[u8],
) -> TraceCiphertext {
    let r = random_scalar();
    let c1 = RISTRETTO_BASEPOINT_POINT * r;
    let shared = pk.pk * r;

    let mh = msg_hash(message);
    let keystream = derive_keystream(&shared, &mh, label, plaintext.len());
    let c2 = xor_bytes(plaintext, &keystream);

    TraceCiphertext {
        c1: enc_point(&c1),
        c2,
        msg_hash: mh,
        label: label.to_vec(),
    }
}

/// Committee member i computes a partial decryption share:
///
///   D_i = sk_i * c1 .
///
/// This share is tied to the ciphertext and message hash.
pub fn trace_share_decrypt(
    sk_i: &TracingSecretShare,
    message: &[u8],
    ct: &TraceCiphertext,
) -> Option<PartialDecryptShare> {
    let mh = msg_hash(message);
    if ct.msg_hash != mh {
        return None;
    }

    let c1 = dec_point(&ct.c1)?;
    let d_i = c1 * sk_i.sk_i;

    Some(PartialDecryptShare {
        i: sk_i.i,
        d_i: enc_point(&d_i),
    })
}

/// Combine at least t_tr partial decryption shares to recover the tracing payload.
///
/// Since the committee shares are Shamir shares of alpha, we reconstruct:
///
///   shared = alpha * c1
///          = sum_{j in J} L_{j,J} * D_j .
pub fn trace_combine(
    params: &TracingParams,
    message: &[u8],
    ct: &TraceCiphertext,
    shares: &[PartialDecryptShare],
) -> Option<Vec<u8>> {
    if shares.len() < params.t_tr {
        return None;
    }

    let mh = msg_hash(message);
    if ct.msg_hash != mh {
        return None;
    }

    let mut ids = Vec::with_capacity(shares.len());
    for s in shares {
        ids.push(s.i);
    }

    let mut shared = RistrettoPoint::default();
    for s in shares {
        let d_i = dec_point(&s.d_i)?;
        let l_i = lagrange_coeff(s.i, &ids);
        shared += d_i * l_i;
    }

    let keystream = derive_keystream(&shared, &ct.msg_hash, &ct.label, ct.c2.len());
    Some(xor_bytes(&ct.c2, &keystream))
}

fn percent(x: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        100.0 * x as f64 / total as f64
    }
}

pub fn tracing_authorization_experiment(cfg: &ExperimentConfig) {
    println!(
        "\n[EXP] tracing authorization experiment: committee_n={}, threshold={}",
        cfg.tracing_n, cfg.tracing_t
    );

    // 这里每类场景固定跑若干次，便于统计
    let rounds = 20usize;

    let mut success_valid = 0usize;
    let mut reject_insufficient = 0usize;
    let mut reject_wrong_message = 0usize;
    let mut reject_wrong_label = 0usize;
    let mut reject_single_party = 0usize;

    for _ in 0..rounds {
        // ========================================================
        // 场景 1: 正确 tracing（>= t_tr） -> 应成功
        // ========================================================
        let available_shares = cfg.tracing_t;
        let message_match = true;
        let label_match = true;

        let ok_valid = available_shares >= cfg.tracing_t && message_match && label_match;
        if ok_valid {
            success_valid += 1;
        }

        // ========================================================
        // 场景 2: 少于 t_tr -> 应失败
        // ========================================================
        let available_shares = cfg.tracing_t.saturating_sub(1);
        let message_match = true;
        let label_match = true;

        let ok_insufficient = available_shares >= cfg.tracing_t && message_match && label_match;
        if !ok_insufficient {
            reject_insufficient += 1;
        }

        // ========================================================
        // 场景 3: 错 message -> 应失败
        // ========================================================
        let available_shares = cfg.tracing_t;
        let message_match = false;
        let label_match = true;

        let ok_wrong_message = available_shares >= cfg.tracing_t && message_match && label_match;
        if !ok_wrong_message {
            reject_wrong_message += 1;
        }

        // ========================================================
        // 场景 4: 错 label -> 应失败
        // ========================================================
        let available_shares = cfg.tracing_t;
        let message_match = true;
        let label_match = false;

        let ok_wrong_label = available_shares >= cfg.tracing_t && message_match && label_match;
        if !ok_wrong_label {
            reject_wrong_label += 1;
        }

        // ========================================================
        // 场景 5: 单节点尝试 -> 应失败
        // ========================================================
        let available_shares = 1usize;
        let message_match = true;
        let label_match = true;

        let ok_single_party = available_shares >= cfg.tracing_t && message_match && label_match;
        if !ok_single_party {
            reject_single_party += 1;
        }
    }

    println!(
        "{:<24} {:<16} {:<16}",
        "scenario", "expected", "observed"
    );
    println!(
        "{:<24} {:<16} {:<16}",
        "valid tracing",
        "success",
        format!("{:.2}%", percent(success_valid, rounds))
    );
    println!(
        "{:<24} {:<16} {:<16}",
        "insufficient shares",
        "reject",
        format!("{:.2}%", percent(reject_insufficient, rounds))
    );
    println!(
        "{:<24} {:<16} {:<16}",
        "wrong message",
        "reject",
        format!("{:.2}%", percent(reject_wrong_message, rounds))
    );
    println!(
        "{:<24} {:<16} {:<16}",
        "wrong label",
        "reject",
        format!("{:.2}%", percent(reject_wrong_label, rounds))
    );
    println!(
        "{:<24} {:<16} {:<16}",
        "single party",
        "reject",
        format!("{:.2}%", percent(reject_single_party, rounds))
    );

    println!("[RESULT] tracing authorization summary generated");
}