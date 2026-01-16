use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::rngs::OsRng;
use rand::TryRngCore;


pub fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut bytes).unwrap();
    Scalar::from_bytes_mod_order_wide(&bytes)
}

pub fn hash_to_scalar(bytes: &[u8]) -> Scalar {
    let mut wide = [0u8; 64];
    let take = bytes.len().min(64);
    wide[..take].copy_from_slice(&bytes[..take]);
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub fn hash_to_point(bytes: &[u8]) -> RistrettoPoint {
    let mut wide = [0u8; 64];
    let take = bytes.len().min(64);
    wide[..take].copy_from_slice(&bytes[..take]);
    RistrettoPoint::from_uniform_bytes(&wide)
}
