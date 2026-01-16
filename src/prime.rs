use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;

fn modexp(mut base: BigUint, mut exp: BigUint, modu: &BigUint) -> BigUint {
    let mut res = BigUint::one();
    base %= modu;
    while exp > BigUint::zero() {
        if &exp & BigUint::one() == BigUint::one() {
            res = (&res * &base) % modu;
        }
        base = (&base * &base) % modu;
        exp >>= 1;
    }
    res
}

// Miller–Rabin primality test
fn is_probable_prime(n: &BigUint, k: usize, rng: &mut impl RngCore) -> bool {
    if *n < BigUint::from(4u32) { return *n == BigUint::from(2u32) || *n == BigUint::from(3u32); }
    if n % 2u32 == BigUint::zero() { return false; }

    let mut d = n - 1u32;
    let mut s = 0;
    while &d % 2u32 == BigUint::zero() {
        d >>= 1;
        s += 1;
    }

    for _ in 0..k {
        let a = BigUint::from(2u32) + BigUint::from(rng.next_u64()) % (n - 3u32);
        let mut x = modexp(a, d.clone(), n);
        if x == BigUint::one() || x == n - 1u32 { continue; }
        let mut composite = true;
        for _ in 0..s - 1 {
            x = (&x * &x) % n;
            if x == n - 1u32 {
                composite = false;
                break;
            }
        }
        if composite { return false; }
    }
    true
}

pub fn random_prime(bits: usize, rng: &mut impl RngCore) -> BigUint {
    loop {
        let mut candidate = BigUint::from(rng.next_u64());
        candidate |= BigUint::one() << (bits - 1);
        candidate |= BigUint::one();

        if is_probable_prime(&candidate, 40, rng) {
            return candidate;
        }
    }
}
