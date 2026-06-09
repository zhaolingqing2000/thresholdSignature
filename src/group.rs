use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

pub fn scalar_from_u64(x: u64) -> Scalar {
    Scalar::from(x)
}

pub fn random_scalar() -> Scalar {
    let bytes: [u8; 64] = rand::random();
    Scalar::from_bytes_mod_order_wide(&bytes)
}

pub fn scalar_add(a: &Scalar, b: &Scalar) -> Scalar {
    a + b
}

pub fn scalar_mul(a: &Scalar, b: &Scalar) -> Scalar {
    a * b
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

pub fn compress_point(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

pub fn decompress_point(b: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*b).decompress()
}
