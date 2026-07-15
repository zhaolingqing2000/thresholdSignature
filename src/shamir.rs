use curve25519_dalek::scalar::Scalar;

use crate::randutil::random_scalar;

/// Degree-(t-1) polynomial represented by coefficients [c0, c1, ..., c_{t-1}]
#[derive(Clone, Debug)]
pub struct Poly {
    pub coeffs: Vec<Scalar>,
}

impl Poly {
    /// Evaluate polynomial at x using Horner's rule
    pub fn eval(&self, x: Scalar) -> Scalar {
        let mut acc = Scalar::ZERO;
        for c in self.coeffs.iter().rev() {
            acc *= x;
            acc += c;
        }
        acc
    }
}

/// Sample random degree-(t-1) polynomial with chosen constant term.
/// This corresponds to Shamir secret sharing with threshold t.
pub fn sample_poly_with_constant(t_minus_1: usize, c0: Scalar) -> Poly {
    let mut coeffs = Vec::with_capacity(t_minus_1 + 1);
    coeffs.push(c0);

    for _ in 0..t_minus_1 {
        coeffs.push(random_scalar());
    }

    Poly { coeffs }
}

/// Lagrange coefficient L_{i,S} evaluated at 0
///
/// `L_{i,S} = product_{k in S, k != i} k / (k - i)`
///
/// Used to reconstruct the secret or aggregate threshold Schnorr shares.
pub fn lagrange_coeff(i: u32, s: &[u32]) -> Scalar {
    let i_s = Scalar::from(i as u64);

    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;

    for &k in s {
        if k == i {
            continue;
        }

        let k_s = Scalar::from(k as u64);
        num *= k_s;
        den *= k_s - i_s;
    }

    num * den.invert()
}
