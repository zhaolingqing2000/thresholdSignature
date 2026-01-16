use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::randutil::{hash_to_point as uhash_to_point, hash_to_scalar as uhash_to_scalar};

/// ===== Random Oracles (paper's Hall) =====
/// Domain-separated SHA-512, then map to:
/// - Points via RistrettoPoint::from_uniform_bytes (through randutil::hash_to_point)
/// - Scalars via Scalar::from_bytes_mod_order_wide (through randutil::hash_to_scalar)

fn hash_32(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(domain);
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out[..32]);
    r
}

/// Hash(domain || data) -> 64 bytes (SHA-512)
fn hash_64(domain: &[u8], data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(domain);
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 64];
    r.copy_from_slice(&out[..64]);
    r
}

/// Domain-separated hash-to-point
fn hash_to_point(domain: &[u8], data: &[u8]) -> RistrettoPoint {
    let wide = hash_64(domain, data);
    uhash_to_point(&wide)
}

/// Domain-separated hash-to-scalar
fn hash_to_scalar(domain: &[u8], data: &[u8]) -> Scalar {
    let wide = hash_64(domain, data);
    uhash_to_scalar(&wide)
}

/// Serialize helper (compressed ristretto)
pub fn enc_point(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

pub fn enc_comp(p: &CompressedRistretto) -> [u8; 32] {
    p.to_bytes()
}

pub fn enc_scalar(s: &Scalar) -> [u8; 32] {
    s.to_bytes()
}

/// Hcom(i, rho, B) -> mu  (paper: Hcom : {0,1}^λ × G -> R)
pub fn hcom(i: u32, rho: &[u8; 32], b: &RistrettoPoint) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"Gargos::Hcom");
    buf.extend_from_slice(&i.to_le_bytes());
    buf.extend_from_slice(rho);
    buf.extend_from_slice(&enc_point(b));
    hash_32(b"Hcom", &buf)
}

/// F0, F1 : {0,1}^λ -> G
pub fn f0(rho: &[u8; 32]) -> RistrettoPoint {
    hash_to_point(b"Gargos::F0", rho)
}

pub fn f1(rho: &[u8; 32]) -> RistrettoPoint {
    hash_to_point(b"Gargos::F1", rho)
}

/// G0, G1 : M × R* -> G
/// Input: (message, mu_vec) (Fig.3 line 16)
pub fn g0(message: &[u8], mu_vec: &[(u32, [u8; 32])]) -> RistrettoPoint {
    let mut buf = Vec::new();
    buf.extend_from_slice(message);
    for (id, mu) in mu_vec {
        buf.extend_from_slice(&id.to_le_bytes());
        buf.extend_from_slice(mu);
    }
    hash_to_point(b"Gargos::G0", &buf)
}

pub fn g1(message: &[u8], mu_vec: &[(u32, [u8; 32])]) -> RistrettoPoint {
    let mut buf = Vec::new();
    buf.extend_from_slice(message);
    for (id, mu) in mu_vec {
        buf.extend_from_slice(&id.to_le_bytes());
        buf.extend_from_slice(mu);
    }
    hash_to_point(b"Gargos::G1", &buf)
}

/// Hsig : G^2 × M -> Zp (we use scalar)
pub fn hsig(a_hat: &RistrettoPoint, pk: &RistrettoPoint, message: &[u8]) -> Scalar {
    let mut buf = Vec::new();
    buf.extend_from_slice(&enc_point(a_hat));
    buf.extend_from_slice(&enc_point(pk));
    buf.extend_from_slice(message);
    hash_to_scalar(b"Gargos::Hsig", &buf)
}

/// HFS for Fiat-Shamir in Σ-protocol (Fig.4, line 4).
pub fn hfs(
    xa: &RistrettoPoint,
    xb: &RistrettoPoint,
    xpk: &RistrettoPoint,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
    pk: &RistrettoPoint,
    g0: &RistrettoPoint,
    g1: &RistrettoPoint,
    rho: &[u8; 32],
) -> Scalar {
    let mut buf = Vec::new();
    buf.extend_from_slice(&enc_point(xa));
    buf.extend_from_slice(&enc_point(xb));
    buf.extend_from_slice(&enc_point(xpk));
    buf.extend_from_slice(&enc_point(a));
    buf.extend_from_slice(&enc_point(b));
    buf.extend_from_slice(&enc_point(pk));
    buf.extend_from_slice(&enc_point(g0));
    buf.extend_from_slice(&enc_point(g1));
    buf.extend_from_slice(rho);
    hash_to_scalar(b"Gargos::HFS", &buf)
}

/// Deterministically derive "random generators" h, v (paper samples them randomly in Setup).
pub fn derive_generator(tag: &'static [u8]) -> RistrettoPoint {
    hash_to_point(b"Gargos::Gen", tag)
}
