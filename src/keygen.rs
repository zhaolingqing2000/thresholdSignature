use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use crate::hash::derive_generator;
use crate::shamir::sample_poly_with_constant;
use crate::types::{Params, PublicKeyShare, SecretKeyShare};

/// Setup(1^λ, n, t) (Fig.3 Setup).:contentReference[oaicite:9]{index=9}
pub fn setup(n: usize, t: usize) -> Params {
    // We use deterministic hash-derived generators to avoid "rng plumbing".
    // This plays the role of sampling independent random generators in the paper.
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = derive_generator(b"h");
    let v = derive_generator(b"v");
    Params { n, t, g, h, v }
}

/// KGen(par) (Fig.3 line 6-11).:contentReference[oaicite:10]{index=10}
pub fn kgen(par: &Params) -> (RistrettoPoint, Vec<PublicKeyShare>, Vec<SecretKeyShare>) {
    // sample degree-t polynomials s(x), r(x), u(x) with r(0)=u(0)=0.
    let s0 = crate::randutil::random_scalar();
    let s_poly = sample_poly_with_constant(par.t, s0);
    let r_poly = sample_poly_with_constant(par.t, Scalar::ZERO);
    let u_poly = sample_poly_with_constant(par.t, Scalar::ZERO);

    let mut pks = Vec::with_capacity(par.n);
    let mut sks = Vec::with_capacity(par.n);

    for i in 1..=par.n {
        let x = Scalar::from(i as u64);
        let s_i = s_poly.eval(x);
        let r_i = r_poly.eval(x);
        let u_i = u_poly.eval(x);

        let sk_i = SecretKeyShare { s: s_i, r: r_i, u: u_i };
        let pk_i = par.g * s_i + par.h * r_i + par.v * u_i;

        sks.push(sk_i);
        pks.push(PublicKeyShare { pk_i });
    }

    // joint public key pk = g^{s(0)} (since r(0)=u(0)=0).:contentReference[oaicite:11]{index=11}
    let pk = par.g * s0;
    (pk, pks, sks)
}
