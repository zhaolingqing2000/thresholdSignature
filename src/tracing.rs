// src/tracing.rs
//
// Message-dependent authorized tracing (paper-faithful structure)

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256};

use rand::rand_core::{OsRng, RngCore};


#[derive(Clone, Debug)]
pub struct AdmitterKey {
    pub sk: Scalar,        // tracing master secret
    pub pk: RistrettoPoint,
}

#[derive(Clone, Debug)]
pub struct TraceToken {
    pub msg_hash: [u8; 32],
    pub tau: Scalar,      // authorization scalar
}

#[derive(Clone, Debug)]
pub struct TraceCiphertext {
    pub c1: RistrettoPoint,
    pub c2: [u8; 32],
    pub msg_hash: [u8; 32],
}

// Setup tracing authority
pub fn setup_admitter() -> AdmitterKey {
    let buf: [u8; 64] = rand::random();
    let sk = Scalar::from_bytes_mod_order_wide(&buf);
    let pk = RistrettoPoint::default() * sk;
    AdmitterKey { sk, pk }
}

// Token issued for a specific message
pub fn admitter_issue_token(ad: &AdmitterKey, message: &[u8]) -> TraceToken {
    let h = Sha256::digest(message);
    let mut mh = [0u8; 32];
    mh.copy_from_slice(&h);

    let mut mh = [0u8; 32];
    mh.copy_from_slice(&h);
    let tau = Scalar::from_bytes_mod_order(mh) * ad.sk;

    TraceToken { msg_hash: mh, tau }
}

// Encrypt a share under tracing
pub fn trace_encrypt(token: &TraceToken, share: &[u8], label: &[u8]) -> TraceCiphertext {
    let r_bytes: [u8; 64] = rand::random();

    let r = Scalar::from_bytes_mod_order_wide(&r_bytes);

    let c1 = RistrettoPoint::default() * r;

    let mut h = Sha256::new();
    h.update(c1.compress().as_bytes());
    h.update(token.tau.as_bytes());
    h.update(label);
    let key = h.finalize();

    let mut c2 = [0u8; 32];
    for i in 0..32 {
        c2[i] = key[i] ^ share[i];
    }

    TraceCiphertext {
        c1,
        c2,
        msg_hash: token.msg_hash,
    }
}

// Decrypt traced share
pub fn trace_decrypt(token: &TraceToken, tc: &TraceCiphertext) -> Option<Vec<u8>> {
    if tc.msg_hash != token.msg_hash {
        return None;
    }

    let mut h = Sha256::new();
    h.update(tc.c1.compress().as_bytes());
    h.update(token.tau.as_bytes());
    let key = h.finalize();

    let mut out = vec![0u8; 32];
    for i in 0..32 {
        out[i] = key[i] ^ tc.c2[i];
    }
    Some(out)
}
