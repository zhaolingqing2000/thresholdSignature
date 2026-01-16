use curve25519_dalek::scalar::Scalar;

use crate::randutil::random_scalar;

/// Degree-t polynomial represented by coefficients [c0, c1, ..., ct]
#[derive(Clone, Debug)]
pub struct Poly {
    pub coeffs: Vec<Scalar>,
}

impl Poly {
    pub fn eval(&self, x: Scalar) -> Scalar {
        let mut pow = Scalar::ONE;
        let mut acc = Scalar::ZERO;
        for c in &self.coeffs {
            acc += c * pow;
            pow *= x;
        }
        acc
    }
}

/// Sample random degree-t polynomial with chosen constant term.
pub fn sample_poly_with_constant(t: usize, c0: Scalar) -> Poly {
    let mut coeffs = Vec::with_capacity(t + 1);
    coeffs.push(c0);
    for _ in 0..t {
        coeffs.push(random_scalar());
    }
    Poly { coeffs }
}

/// Lagrange coefficient L_{i,SS} = Π_{k∈SS\{i}} k/(k-i)
pub fn lagrange_coeff(i: u32, ss: &[u32]) -> Scalar {
    let i_s = Scalar::from(i as u64);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &k in ss {
        if k == i {
            continue;
        }
        let k_s = Scalar::from(k as u64);
        num *= k_s;
        den *= k_s - i_s;
    }
    num * den.invert()
}
