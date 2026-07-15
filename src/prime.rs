use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;

fn modexp(mut base: BigUint, mut exp: BigUint, modu: &BigUint) -> BigUint {
    let mut res = BigUint::one();
    base %= modu;
    while exp > BigUint::zero() {
        if (&exp & BigUint::one()) == BigUint::one() {
            res = (&res * &base) % modu;
        }
        base = (&base * &base) % modu;
        exp >>= 1;
    }
    res
}

// Miller–Rabin primality test
fn is_probable_prime(n: &BigUint, k: usize, rng: &mut impl RngCore) -> bool {
    if *n < BigUint::from(4u32) {
        return *n == BigUint::from(2u32) || *n == BigUint::from(3u32);
    }
    if n % 2u32 == BigUint::zero() {
        return false;
    }

    let mut d = n - 1u32;
    let mut s = 0usize;
    while &d % 2u32 == BigUint::zero() {
        d >>= 1;
        s += 1;
    }

    for _ in 0..k {
        let a = random_biguint_range(&BigUint::from(2u32), &(n - 2u32), rng);
        let mut x = modexp(a, d.clone(), n);

        if x == BigUint::one() || x == n - 1u32 {
            continue;
        }

        let mut witness_composite = true;
        for _ in 0..(s - 1) {
            x = (&x * &x) % n;
            if x == n - 1u32 {
                witness_composite = false;
                break;
            }
        }

        if witness_composite {
            return false;
        }
    }

    true
}

fn random_biguint_bits(bits: usize, rng: &mut impl RngCore) -> BigUint {
    assert!(bits > 0);

    let byte_len = (bits + 7) / 8;
    let mut bytes = vec![0u8; byte_len];
    rng.fill_bytes(&mut bytes);

    let excess_bits = byte_len * 8 - bits;
    if excess_bits > 0 {
        let mask = 0xFFu8 >> excess_bits;
        bytes[0] &= mask;
    }

    BigUint::from_bytes_be(&bytes)
}

fn random_biguint_below(upper: &BigUint, rng: &mut impl RngCore) -> BigUint {
    assert!(!upper.is_zero());

    let bits = upper.bits() as usize;
    loop {
        let x = random_biguint_bits(bits, rng);
        if &x < upper {
            return x;
        }
    }
}

fn random_biguint_range(low: &BigUint, high: &BigUint, rng: &mut impl RngCore) -> BigUint {
    assert!(low < high);
    let width = high - low;
    low + random_biguint_below(&width, rng)
}

pub fn random_prime(bits: usize, rng: &mut impl RngCore) -> BigUint {
    assert!(bits >= 2);

    loop {
        let mut candidate = random_biguint_bits(bits, rng);

        // force exact bit length
        candidate |= BigUint::one() << (bits - 1);
        // force odd
        candidate |= BigUint::one();

        if is_probable_prime(&candidate, 40, rng) {
            return candidate;
        }
    }
}