use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::error::ErrorStack;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum LhtlpError {
    OpenSsl(ErrorStack),
    InvalidLength,
    InvalidRange,
    InvalidGroupElement,
    InvalidPlaintext,
}

impl From<ErrorStack> for LhtlpError {
    fn from(err: ErrorStack) -> Self {
        Self::OpenSsl(err)
    }
}

pub type LhtlpResult<T> = Result<T, LhtlpError>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LhtlpPublicParams {
    pub delta: u64,
    pub n: Vec<u8>,
    pub n_squared: Vec<u8>,
    pub g_t: Vec<u8>,
    pub h_t: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LhtlpPuzzle {
    pub u: Vec<u8>,
    pub v: Vec<u8>,
}

#[derive(Debug)]
pub struct LhtlpBackend {
    params: LhtlpPublicParams,
    n: BigNum,
    n_squared: BigNum,
    g_t: BigNum,
    h_t: BigNum,
    n_width: usize,
    n_squared_width: usize,
}

impl LhtlpPublicParams {
    pub fn modulus_bits(&self) -> usize {
        self.n.len() * 8
    }
}

impl Clone for LhtlpBackend {
    fn clone(&self) -> Self {
        Self::from_params(self.params.clone()).expect("validated LHTLP params must roundtrip")
    }
}

impl LhtlpBackend {
    pub fn setup(modulus_bits: u32, delta: u64) -> LhtlpResult<Self> {
        let prime_bits = (modulus_bits / 2) as i32;
        let mut ctx = BigNumContext::new()?;
        let mut p = BigNum::new()?;
        p.generate_prime(prime_bits, true, None, None)?;
        let mut q = BigNum::new()?;
        q.generate_prime(prime_bits, true, None, None)?;
        while p == q {
            q.generate_prime(prime_bits, true, None, None)?;
        }

        let mut n = BigNum::new()?;
        n.checked_mul(&p, &q, &mut ctx)?;
        let mut n_squared = BigNum::new()?;
        n_squared.sqr(&n, &mut ctx)?;

        let g_t = sample_unit_square(&n, &mut ctx)?;
        let exp = power_of_two(delta)?;
        let mut h_t = BigNum::new()?;
        h_t.mod_exp(&g_t, &exp, &n, &mut ctx)?;

        p.clear();
        q.clear();

        Self::from_params(LhtlpPublicParams {
            delta,
            n: fixed(&n, width(&n)?)?,
            n_squared: fixed(&n_squared, width(&n_squared)?)?,
            g_t: fixed(&g_t, width(&n)?)?,
            h_t: fixed(&h_t, width(&n)?)?,
        })
    }

    pub fn from_params(params: LhtlpPublicParams) -> LhtlpResult<Self> {
        if params.n.is_empty() || params.n_squared.is_empty() {
            return Err(LhtlpError::InvalidLength);
        }
        let n = BigNum::from_slice(&params.n)?;
        let n_squared = BigNum::from_slice(&params.n_squared)?;
        let g_t = BigNum::from_slice(&params.g_t)?;
        let h_t = BigNum::from_slice(&params.h_t)?;
        let mut ctx = BigNumContext::new()?;
        let mut expected = BigNum::new()?;
        expected.sqr(&n, &mut ctx)?;
        if expected != n_squared {
            return Err(LhtlpError::InvalidRange);
        }
        let one = BigNum::from_u32(1)?;
        if n <= one || g_t <= one || h_t <= one || g_t >= n || h_t >= n {
            return Err(LhtlpError::InvalidRange);
        }
        require_unit(&g_t, &n, &mut ctx)?;
        require_unit(&h_t, &n, &mut ctx)?;
        Ok(Self {
            params,
            n_width: width(&n)?,
            n_squared_width: width(&n_squared)?,
            n,
            n_squared,
            g_t,
            h_t,
        })
    }

    pub fn params(&self) -> &LhtlpPublicParams {
        &self.params
    }

    pub fn pgen_bytes(&self, scalar: &[u8]) -> LhtlpResult<LhtlpPuzzle> {
        let s = BigNum::from_slice(scalar)?;
        self.pgen(&s)
    }

    pub fn pgen_with_randomness_bytes(
        &self,
        scalar: &[u8],
        randomness: &[u8],
    ) -> LhtlpResult<LhtlpPuzzle> {
        let s = BigNum::from_slice(scalar)?;
        let r = BigNum::from_slice(randomness)?;
        self.pgen_with_randomness(&s, &r)
    }

    pub fn pgen(&self, s: &BigNumRef) -> LhtlpResult<LhtlpPuzzle> {
        let mut ctx = BigNumContext::new()?;
        let r = random_below_unit(&self.n, &mut ctx)?;
        self.pgen_with_randomness(s, &r)
    }

    pub fn pgen_with_randomness(&self, s: &BigNumRef, r: &BigNumRef) -> LhtlpResult<LhtlpPuzzle> {
        if s >= self.n.as_ref() {
            return Err(LhtlpError::InvalidPlaintext);
        }
        let mut ctx = BigNumContext::new()?;
        let one = BigNum::from_u32(1)?;
        if r <= one.as_ref() || r >= self.n.as_ref() {
            return Err(LhtlpError::InvalidRange);
        }
        require_unit(r, &self.n, &mut ctx)?;
        let mut u = BigNum::new()?;
        u.mod_exp(&self.g_t, r, &self.n, &mut ctx)?;

        let mut rn = BigNum::new()?;
        rn.checked_mul(r, &self.n, &mut ctx)?;
        let mut lhs = BigNum::new()?;
        lhs.mod_exp(&self.h_t, &rn, &self.n_squared, &mut ctx)?;

        let one_plus_n = one_plus(&self.n)?;
        let mut rhs = BigNum::new()?;
        rhs.mod_exp(&one_plus_n, s, &self.n_squared, &mut ctx)?;

        let mut v = BigNum::new()?;
        v.mod_mul(&lhs, &rhs, &self.n_squared, &mut ctx)?;
        Ok(LhtlpPuzzle {
            u: fixed(&u, self.n_width)?,
            v: fixed(&v, self.n_squared_width)?,
        })
    }

    pub fn peval(&self, puzzles: &[LhtlpPuzzle]) -> LhtlpResult<LhtlpPuzzle> {
        let mut ctx = BigNumContext::new()?;
        let mut u_acc = BigNum::from_u32(1)?;
        let mut v_acc = BigNum::from_u32(1)?;
        for puzzle in puzzles {
            let (u, v) = self.decode_puzzle(puzzle)?;
            let mut next_u = BigNum::new()?;
            next_u.mod_mul(&u_acc, &u, &self.n, &mut ctx)?;
            u_acc = next_u;
            let mut next_v = BigNum::new()?;
            next_v.mod_mul(&v_acc, &v, &self.n_squared, &mut ctx)?;
            v_acc = next_v;
        }
        Ok(LhtlpPuzzle {
            u: fixed(&u_acc, self.n_width)?,
            v: fixed(&v_acc, self.n_squared_width)?,
        })
    }

    pub fn psolve(&self, puzzle: &LhtlpPuzzle) -> LhtlpResult<(Vec<u8>, u64)> {
        let (u, v) = self.decode_puzzle(puzzle)?;
        let mut ctx = BigNumContext::new()?;
        let mut w = u.to_owned()?;
        for _ in 0..self.params.delta {
            let mut next = BigNum::new()?;
            next.mod_sqr(&w, &self.n, &mut ctx)?;
            w = next;
        }

        let mut w_n = BigNum::new()?;
        w_n.mod_exp(&w, &self.n, &self.n_squared, &mut ctx)?;
        let mut inv = BigNum::new()?;
        inv.mod_inverse(&w_n, &self.n_squared, &mut ctx)?;
        let mut a = BigNum::new()?;
        a.mod_mul(&v, &inv, &self.n_squared, &mut ctx)?;

        let one = BigNum::from_u32(1)?;
        if a < one {
            return Err(LhtlpError::InvalidPlaintext);
        }
        let mut numerator = BigNum::new()?;
        numerator.checked_sub(&a, &one)?;
        let mut quotient = BigNum::new()?;
        let mut remainder = BigNum::new()?;
        quotient.div_rem(&mut remainder, &numerator, &self.n, &mut ctx)?;
        if remainder != BigNum::from_u32(0)? {
            return Err(LhtlpError::InvalidPlaintext);
        }
        Ok((fixed(&quotient, self.n_width)?, self.params.delta))
    }

    pub fn encode_puzzle(&self, puzzle: &LhtlpPuzzle) -> LhtlpResult<Vec<u8>> {
        self.decode_puzzle(puzzle)?;
        let mut out = Vec::with_capacity(self.n_width + self.n_squared_width);
        out.extend_from_slice(&puzzle.u);
        out.extend_from_slice(&puzzle.v);
        Ok(out)
    }

    pub fn decode_puzzle_bytes(&self, bytes: &[u8]) -> LhtlpResult<LhtlpPuzzle> {
        if bytes.len() != self.n_width + self.n_squared_width {
            return Err(LhtlpError::InvalidLength);
        }
        let puzzle = LhtlpPuzzle {
            u: bytes[..self.n_width].to_vec(),
            v: bytes[self.n_width..].to_vec(),
        };
        self.decode_puzzle(&puzzle)?;
        Ok(puzzle)
    }

    fn decode_puzzle(&self, puzzle: &LhtlpPuzzle) -> LhtlpResult<(BigNum, BigNum)> {
        if puzzle.u.len() != self.n_width || puzzle.v.len() != self.n_squared_width {
            return Err(LhtlpError::InvalidLength);
        }
        let u = BigNum::from_slice(&puzzle.u)?;
        let v = BigNum::from_slice(&puzzle.v)?;
        let one = BigNum::from_u32(1)?;
        if u <= one || u >= self.n || v <= one || v >= self.n_squared {
            return Err(LhtlpError::InvalidRange);
        }
        let mut ctx = BigNumContext::new()?;
        require_unit(&u, &self.n, &mut ctx)?;
        require_unit(&v, &self.n_squared, &mut ctx)?;
        Ok((u, v))
    }
}

fn width(n: &BigNumRef) -> LhtlpResult<usize> {
    Ok(((n.num_bits() + 7) / 8) as usize)
}

fn fixed(n: &BigNumRef, width: usize) -> LhtlpResult<Vec<u8>> {
    Ok(n.to_vec_padded(width as i32)?)
}

fn one_plus(n: &BigNumRef) -> LhtlpResult<BigNum> {
    let one = BigNum::from_u32(1)?;
    let mut out = BigNum::new()?;
    out.checked_add(n, &one)?;
    Ok(out)
}

fn power_of_two(delta: u64) -> LhtlpResult<BigNum> {
    if delta > i32::MAX as u64 {
        return Err(LhtlpError::InvalidRange);
    }
    let mut out = BigNum::from_u32(0)?;
    out.set_bit(delta as i32)?;
    Ok(out)
}

fn require_unit(
    value: &BigNumRef,
    modulus: &BigNumRef,
    ctx: &mut BigNumContext,
) -> LhtlpResult<()> {
    let one = BigNum::from_u32(1)?;
    let mut gcd = BigNum::new()?;
    gcd.gcd(value, modulus, ctx)?;
    if gcd != one {
        return Err(LhtlpError::InvalidGroupElement);
    }
    Ok(())
}

fn random_below_unit(modulus: &BigNumRef, ctx: &mut BigNumContext) -> LhtlpResult<BigNum> {
    let one = BigNum::from_u32(1)?;
    loop {
        let mut r = BigNum::new()?;
        modulus.rand_range(&mut r)?;
        if r > one {
            require_unit(&r, modulus, ctx)?;
            return Ok(r);
        }
    }
}

fn sample_unit_square(n: &BigNumRef, ctx: &mut BigNumContext) -> LhtlpResult<BigNum> {
    let x = random_below_unit(n, ctx)?;
    let mut g = BigNum::new()?;
    g.mod_sqr(&x, n, ctx)?;
    Ok(g)
}
