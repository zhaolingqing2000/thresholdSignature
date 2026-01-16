use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

use crate::hash::{f0, f1, hfs};
use crate::types::{Params, SecretKeyShare};

/// Proof π := (XA, XB, Xpk, za, zs, zr, zu) as in Fig.4.:contentReference[oaicite:6]{index=6}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub xa: [u8; 32],
    pub xb: [u8; 32],
    pub xpk: [u8; 32],
    pub za: [u8; 32],
    pub zs: [u8; 32],
    pub zr: [u8; 32],
    pub zu: [u8; 32],
}

fn dec_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    use curve25519_dalek::ristretto::CompressedRistretto;
    CompressedRistretto(*bytes).decompress()
}

fn dec_scalar(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

fn enc_point(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}
fn enc_scalar(s: &Scalar) -> [u8; 32] {
    s.to_bytes()
}

/// SigProve((pk, A, B, g0, g1, rho); (a, sk=(s,r,u))) -> π (Fig.4).:contentReference[oaicite:7]{index=7}
pub fn sig_prove(
    par: &Params,
    pk_i: &RistrettoPoint,
    a_i_point: &RistrettoPoint, // A
    b_i: &RistrettoPoint,        // B
    g0: &RistrettoPoint,
    g1: &RistrettoPoint,
    rho: &[u8; 32],
    a: &Scalar,
    sk: &SecretKeyShare,
) -> Proof {
    // (h0, h1) := (F0(rho), F1(rho))
    let h0 = f0(rho);
    let h1 = f1(rho);

    // sample hats
    let a_hat = crate::randutil::random_scalar();
    let s_hat = crate::randutil::random_scalar();
    let r_hat = crate::randutil::random_scalar();
    let u_hat = crate::randutil::random_scalar();

    // XA := g^{a_hat} g0^{r_hat} g1^{u_hat}
    let xa = par.g * a_hat + (*g0) * r_hat + (*g1) * u_hat;
    // XB := g^{a_hat} h0^{r_hat} h1^{u_hat}
    let xb = par.g * a_hat + h0 * r_hat + h1 * u_hat;
    // Xpk := g^{s_hat} h^{r_hat} v^{u_hat}
    let xpk = par.g * s_hat + par.h * r_hat + par.v * u_hat;

    // e := HFS(...)
    let e = hfs(&xa, &xb, &xpk, a_i_point, b_i, pk_i, g0, g1, rho);

    // responses
    let za = a_hat + (*a) * e;
    let zs = s_hat + sk.s * e;
    let zr = r_hat + sk.r * e;
    let zu = u_hat + sk.u * e;

    Proof {
        xa: enc_point(&xa),
        xb: enc_point(&xb),
        xpk: enc_point(&xpk),
        za: enc_scalar(&za),
        zs: enc_scalar(&zs),
        zr: enc_scalar(&zr),
        zu: enc_scalar(&zu),
    }
}

/// SigVer((pk, A, B, g0, g1, rho); π) -> bool (Fig.4).:contentReference[oaicite:8]{index=8}
pub fn sig_verify(
    par: &Params,
    pk_i: &RistrettoPoint,
    a_i_point: &RistrettoPoint, // A
    b_i: &RistrettoPoint,        // B
    g0: &RistrettoPoint,
    g1: &RistrettoPoint,
    rho: &[u8; 32],
    proof: &Proof,
) -> bool {
    let xa = match dec_point(&proof.xa) {
        Some(p) => p,
        None => return false,
    };
    let xb = match dec_point(&proof.xb) {
        Some(p) => p,
        None => return false,
    };
    let xpk = match dec_point(&proof.xpk) {
        Some(p) => p,
        None => return false,
    };

    let za = dec_scalar(&proof.za);
    let zs = dec_scalar(&proof.zs);
    let zr = dec_scalar(&proof.zr);
    let zu = dec_scalar(&proof.zu);

    let h0 = f0(rho);
    let h1 = f1(rho);

    let e = hfs(&xa, &xb, &xpk, a_i_point, b_i, pk_i, g0, g1, rho);

    // Check:
    // g^za g0^zr g1^zu == XA * A^e
    let left1 = par.g * za + (*g0) * zr + (*g1) * zu;
    let right1 = xa + (*a_i_point) * e;

    // g^za h0^zr h1^zu == XB * B^e
    let left2 = par.g * za + h0 * zr + h1 * zu;
    let right2 = xb + (*b_i) * e;

    // g^zs h^zr v^zu == Xpk * pk^e
    let left3 = par.g * zs + par.h * zr + par.v * zu;
    let right3 = xpk + (*pk_i) * e;

    left1 == right1 && left2 == right2 && left3 == right3
}
