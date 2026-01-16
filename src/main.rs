use threshold_signature::keygen::{kgen, setup};
use threshold_signature::protocol::{combine, sig1, sig2, sig3_with_pk, verify};
use threshold_signature::timed::{timed_encrypt, timed_decrypt, derive_h as timed_derive_h, TimedParams};
use threshold_signature::commitment::{
    commit_z, derive_h_from_g, aggregate_commitments, aggregate_openings, verify_aggregate,
};
use threshold_signature::tracing::{setup_admitter, admitter_issue_token, trace_encrypt, trace_decrypt};

use num_bigint::BigUint;
use std::time::{Duration, Instant};

mod prime;
use prime::random_prime;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Baseline,
    VC,
    VC_Timed,
    VC_Timed_Tracing,
}


impl Mode {
    fn name(&self) -> &'static str {
        match self {
            Mode::Baseline => "baseline",
            Mode::VC => "vc",
            Mode::VC_Timed => "vc+timed",
            Mode::VC_Timed_Tracing => "vc+timed+tracing",
        }
    }
}

#[derive(Default, Clone, Debug)]
struct Timings {
    total: Duration,
    keygen: Duration,
    r1: Duration,
    r2: Duration,
    r3: Duration,
    combine: Duration,
    verify: Duration,
    vc_commit: Duration,
    vc_verify: Duration,
    timed_enc: Duration,
    timed_dec: Duration,
    tracing_enc: Duration,
    tracing_dec: Duration,
}

fn add(a: &mut Duration, b: Duration) { *a += b; }

fn avg(d: Duration, n: usize) -> Duration {
    if n == 0 { d } else { Duration::from_nanos((d.as_nanos() / n as u128) as u64) }
}

fn make_timed_params(T: u64) -> TimedParams {
    let mut rng = rand::rng();
    let p = random_prime(1024, &mut rng);
    let q = random_prime(1024, &mut rng);
    let n = &p * &q;

    let g = BigUint::from(5u32);
    let h = timed_derive_h(&n, &g, T);

    TimedParams { n, g, h, t: T }
}

fn run_once(n: usize, t: usize, mode: Mode, timed: &TimedParams, T: u64) -> (Timings, bool) {
    let total_start = Instant::now();
    let mut tm = Timings::default();

    let par = setup(n, t);
    let (pk_joint, pk_shares, sk_shares) = kgen(&par);

    let msg = b"hello gargos threshold schnorr";
    let ss: Vec<u32> = (1..=(t+1)).map(|i| i as u32).collect();

    let t1 = Instant::now();
    let mut commits = vec![];
    let mut states = vec![];
    for &i in &ss {
        let (cm, st) = sig1(&par, i, &sk_shares[i as usize - 1]);
        commits.push((cm.i, cm.mu_i));
        states.push(st);
    }
    tm.r1 = t1.elapsed();

    let t2 = Instant::now();
    let mut opens = vec![];
    let mut states2 = vec![];
    for (idx, &i) in ss.iter().enumerate() {
        let (om, st2) = sig2(&par, msg, i, &commits,
                             &pk_shares[i as usize - 1],
                             &sk_shares[i as usize - 1],
                             &states[idx]);
        opens.push(om);
        states2.push(st2);
    }
    tm.r2 = t2.elapsed();

    let pk_map: Vec<(u32, _)> = (1..=n as u32)
        .map(|i| (i, pk_shares[i as usize - 1].pk_i)).collect();

    let h_vc = derive_h_from_g(&par.g);
    let admitter = setup_admitter();

    let t3 = Instant::now();
    let mut sigshares = vec![];
    let mut vc_cm = vec![];
    let mut vc_op = vec![];
    let mut timed_ct = vec![];
    let mut trace_ct = vec![];

    for (idx, &i) in ss.iter().enumerate() {
        let ps = sig3_with_pk(&par, msg, &ss, i,
            &pk_joint, &pk_map, &sk_shares[i as usize - 1],
            &states2[idx], &commits, &opens).unwrap();

        let z = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(ps.z_i);

        let t = Instant::now();
        let (cm, op) = commit_z(i, &par.g, &h_vc, &z);
        if mode != Mode::Baseline { tm.vc_commit += t.elapsed(); }
        vc_cm.push(cm); vc_op.push(op);

        let t = Instant::now();
        let ct = timed_encrypt(timed, &ps.z_i, b"timed-z");
        if matches!(mode, Mode::VC_Timed | Mode::VC_Timed_Tracing) { tm.timed_enc += t.elapsed(); }
        timed_ct.push(ct);

        let t = Instant::now();
        let tok = admitter_issue_token(&admitter, msg);
        let tc = trace_encrypt(&tok, &ps.z_i, b"trace-z");
        if matches!(mode, Mode::VC_Timed_Tracing) { tm.tracing_enc += t.elapsed(); }
        trace_ct.push(tc);

        sigshares.push(ps);
    }
    tm.r3 = t3.elapsed();

    let t = Instant::now();
    let sig = combine(&ss, &opens, &sigshares).unwrap();
    tm.combine = t.elapsed();

    let t = Instant::now();
    let ok_sig = verify(&par, &pk_joint, msg, &sig);
    tm.verify = t.elapsed();

    let t = Instant::now();
    let c_agg = aggregate_commitments(&vc_cm);
    let r_agg = aggregate_openings(&vc_op);
    let ok_vc = verify_aggregate(&par.g, &h_vc, &c_agg, &sig.z, &r_agg);
    tm.vc_verify = t.elapsed();

    let t = Instant::now();
    let ok_timed = timed_ct.iter().all(|c| timed_decrypt(timed, c, b"timed-z").is_some());
    tm.timed_dec = t.elapsed();

    let t = Instant::now();
    let ok_trace = trace_decrypt(&admitter_issue_token(&admitter, msg), &trace_ct[0]).is_some();
    tm.tracing_dec = t.elapsed();

    tm.total = total_start.elapsed();

    (tm, ok_sig && ok_vc && ok_timed && ok_trace && timed.t == T)
}

fn run_exp(n: usize, t: usize, mode: Mode, reps: usize, T: u64) {
    let timed = make_timed_params(T);
    let mut sum = Timings::default();
    let mut ok = true;

    for _ in 0..reps {
        let (tm, good) = run_once(n, t, mode, &timed, T);
        ok &= good;
        add(&mut sum.total, tm.total);
        add(&mut sum.keygen, tm.keygen);
        add(&mut sum.r1, tm.r1);
        add(&mut sum.r2, tm.r2);
        add(&mut sum.r3, tm.r3);
        add(&mut sum.combine, tm.combine);
        add(&mut sum.verify, tm.verify);
        add(&mut sum.vc_commit, tm.vc_commit);
        add(&mut sum.vc_verify, tm.vc_verify);
        add(&mut sum.timed_enc, tm.timed_enc);
        add(&mut sum.timed_dec, tm.timed_dec);
        add(&mut sum.tracing_enc, tm.tracing_enc);
        add(&mut sum.tracing_dec, tm.tracing_dec);
    }

    let avg = Timings {
        total: avg(sum.total, reps),
        keygen: avg(sum.keygen, reps),
        r1: avg(sum.r1, reps),
        r2: avg(sum.r2, reps),
        r3: avg(sum.r3, reps),
        combine: avg(sum.combine, reps),
        verify: avg(sum.verify, reps),
        vc_commit: avg(sum.vc_commit, reps),
        vc_verify: avg(sum.vc_verify, reps),
        timed_enc: avg(sum.timed_enc, reps),
        timed_dec: avg(sum.timed_dec, reps),
        tracing_enc: avg(sum.tracing_enc, reps),
        tracing_dec: avg(sum.tracing_dec, reps),
    };

    println!(
        "RESULT,n={},t={},mode={},T={},reps={},ok={},total_ms={:.3},r1_ms={:.3},r2_ms={:.3},r3_ms={:.3},combine_ms={:.3},verify_ms={:.3},vc_commit_ms={:.3},vc_verify_ms={:.3},timed_enc_ms={:.3},timed_dec_ms={:.3},tracing_enc_ms={:.3},tracing_dec_ms={:.3}",
        n, t, mode.name(), T, reps, ok,
        avg.total.as_secs_f64()*1e3,
        avg.r1.as_secs_f64()*1e3,
        avg.r2.as_secs_f64()*1e3,
        avg.r3.as_secs_f64()*1e3,
        avg.combine.as_secs_f64()*1e3,
        avg.verify.as_secs_f64()*1e3,
        avg.vc_commit.as_secs_f64()*1e3,
        avg.vc_verify.as_secs_f64()*1e3,
        avg.timed_enc.as_secs_f64()*1e3,
        avg.timed_dec.as_secs_f64()*1e3,
        avg.tracing_enc.as_secs_f64()*1e3,
        avg.tracing_dec.as_secs_f64()*1e3,
    );
}

fn main() {
    let reps = 10;

    for n in [8,16,32,64,128] {
        let t = n/2;
        for m in [Mode::Baseline, Mode::VC, Mode::VC_Timed, Mode::VC_Timed_Tracing] {
            run_exp(n, t, m, reps, 12);
        }
    }

    let n = 64;
    for t in [1,4,8,16,32] {
        for m in [Mode::Baseline, Mode::VC, Mode::VC_Timed, Mode::VC_Timed_Tracing] {
            run_exp(n, t, m, reps, 12);
        }
    }
}
