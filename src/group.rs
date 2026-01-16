use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

pub fn scalar_from_u64(x: u64) -> Scalar {
    Scalar::from(x)
}

pub fn point_mul(base: &RistrettoPoint, k: &Scalar) -> RistrettoPoint {
    base * k
}

pub fn point_add(a: &RistrettoPoint, b: &RistrettoPoint) -> RistrettoPoint {
    a + b
}

pub fn point_sub(a: &RistrettoPoint, b: &RistrettoPoint) -> RistrettoPoint {
    a - b
}
