use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};
use rand::RngCore;

#[derive(Clone, Debug)]
pub struct TimedParams {
    pub n: BigUint,   // RSA modulus N = p*q
    pub g: BigUint,   // base in Z*_N
    pub h: BigUint,   // h = g^{2^T} mod N
    pub t: u64,       // number of squarings
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TimedCiphertext {
    pub u: Vec<u8>,   // mod N
    pub v: Vec<u8>,   // mod N^2
    pub aad: Vec<u8>,
}

// x <- x^{2^t} mod N  via t sequential squarings
fn pow_2t_mod(mut x: BigUint, t: u64, n: &BigUint) -> BigUint {
    for _ in 0..t {
        x = (&x * &x) % n;
    }
    x
}

fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        (a, BigInt::one(), BigInt::zero())
    } else {
        let (g, x, y) = egcd(b.clone(), a.clone() % b.clone());
        (g, y.clone(), x - (a / b) * y)
    }
}

fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_i = BigInt::from_biguint(Sign::Plus, a.clone());
    let m_i = BigInt::from_biguint(Sign::Plus, m.clone());
    let (g, x, _) = egcd(a_i, m_i.clone());
    if g != BigInt::one() { return None; }
    let mut x = x % m_i.clone();
    if x.sign() == Sign::Minus { x += m_i; }
    Some(x.to_biguint().unwrap())
}

pub fn derive_h(n: &BigUint, g: &BigUint, t: u64) -> BigUint {
    pow_2t_mod(g.clone() % n, t, n)
}

fn paillier_L(x: &BigUint, n: &BigUint) -> BigUint {
    (x - BigUint::one()) / n
}

// r ∈ [1, N^2 − 1]
fn sample_r(n: &BigUint) -> BigUint {
    let n2 = n * n;

    let mut rng = rand::rng();   // <-- this is the new RNG in rand 0.9

    loop {
        let mut buf = vec![0u8; (n2.bits() as usize + 7) / 8];
        rng.fill_bytes(&mut buf);
        let r = BigUint::from_bytes_be(&buf) % &n2;
        if !r.is_zero() {
            return r;
        }
    }
}


pub fn timed_encrypt(pp: &TimedParams, plaintext: &[u8], aad: &[u8]) -> TimedCiphertext {
    let s = BigUint::from_bytes_be(plaintext);
    assert!(s < pp.n, "plaintext must be < N");

    let n = &pp.n;
    let n2 = n * n;
    let r = sample_r(n);

    let u = pp.g.modpow(&r, n);

    let one_plus_n = n + BigUint::one();
    let rN = &r * n;
    let term1 = (pp.h.clone() % &n2).modpow(&rN, &n2);
    let term2 = one_plus_n.modpow(&s, &n2);
    let v = (term1 * term2) % &n2;

    TimedCiphertext {
        u: u.to_bytes_be(),
        v: v.to_bytes_be(),
        aad: aad.to_vec(),
    }
}

pub fn timed_decrypt(pp: &TimedParams, ct: &TimedCiphertext, aad_expected: &[u8]) -> Option<Vec<u8>> {
    if ct.aad != aad_expected { return None; }

    let n = &pp.n;
    let n2 = n * n;

    let u = BigUint::from_bytes_be(&ct.u);
    let v = BigUint::from_bytes_be(&ct.v) % &n2;

    // w = u^{2^T} mod N
    let w = pow_2t_mod(u % n, pp.t, n);

    // w^N mod N^2
    let wN = (w % &n2).modpow(n, &n2);
    let inv_wN = modinv(&wN, &n2)?;

    // (1 + N)^s mod N^2
    let x = (v * inv_wN) % &n2;

    // Recover s
    let s = paillier_L(&x, n) % n;

    let mut out = s.to_bytes_be();
    if out.len() > 32 { return None; }
    if out.len() < 32 {
        let mut pad = vec![0u8; 32 - out.len()];
        pad.extend_from_slice(&out);
        out = pad;
    }
    Some(out)
}
