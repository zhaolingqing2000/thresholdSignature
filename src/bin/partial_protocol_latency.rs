use std::fs::OpenOptions;
use std::io::Write;
use std::time::{Duration, Instant};

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use threshold_signature::construction::{
    combine, open, setup_construction_with_lhtlp_delta, sign_encap, trace, verify,
};
use threshold_signature::hash::{g0, g1, hcom, hsig};
use threshold_signature::keygen;
use threshold_signature::nizk::{sig_prove, sig_verify};
use threshold_signature::randutil::random_scalar;
use threshold_signature::shamir::lagrange_coeff;

const TRIALS: usize = 20;

#[derive(Clone)]
struct Stats {
    mean: f64,
    median: f64,
    std: f64,
    p95: f64,
}

struct Row {
    ell: usize,
    gargos: Stats,
    sign_encap: Stats,
    aux: f64,
    combine: Stats,
    open: Stats,
    verify: Stats,
    trace: Stats,
    total: Stats,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let mut rows = Vec::new();
    for ell in [2usize, 4, 8] {
        eprintln!("[partial-protocol] ell={ell}");
        let gargos = stats(TRIALS, || {
            assert!(gargos_once(ell));
        });
        let (pp, secrets, _) = setup_construction_with_lhtlp_delta(ell, ell - 1, 64);
        let signer_set: Vec<u32> = (1..=ell as u32).collect();
        let mut sign = Vec::new();
        let mut combine_v = Vec::new();
        let mut open_v = Vec::new();
        let mut verify_v = Vec::new();
        let mut trace_v = Vec::new();
        let mut total_v = Vec::new();
        for trial in 0..TRIALS {
            let mut registry = Default::default();
            let msg = format!("partial-protocol-{ell}-{trial}").into_bytes();
            let total_start = Instant::now();
            let s = Instant::now();
            let out = sign_encap(&pp, &secrets, &mut registry, &msg, &signer_set).unwrap();
            sign.push(ms(s.elapsed()));
            let s = Instant::now();
            let sigma = combine(&pp, &registry, &msg, &out.d, &out.packages).unwrap();
            combine_v.push(ms(s.elapsed()));
            let s = Instant::now();
            let opened = open(&pp, &registry, &msg, &out.d).unwrap();
            open_v.push(ms(s.elapsed()));
            assert_eq!(sigma.z, opened.z);
            assert_eq!(sigma.tau, opened.tau);
            let s = Instant::now();
            assert!(verify(&pp, &registry, &msg, &sigma));
            verify_v.push(ms(s.elapsed()));
            let s = Instant::now();
            assert_eq!(
                trace(&pp, &secrets, &registry, &msg, &sigma).unwrap(),
                signer_set
            );
            trace_v.push(ms(s.elapsed()));
            total_v.push(ms(total_start.elapsed()));
        }
        let sign_encap = summarize(sign);
        rows.push(Row {
            ell,
            aux: (sign_encap.mean - gargos.mean).max(0.0),
            gargos,
            sign_encap,
            combine: summarize(combine_v),
            open: summarize(open_v),
            verify: summarize(verify_v),
            trace: summarize(trace_v),
            total: summarize(total_v),
        });
    }
    append_report(&rows, started.elapsed())?;
    Ok(())
}

fn append_report(rows: &[Row], elapsed: Duration) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = String::new();
    out.push_str("\n# Focused Partial-Concrete Protocol Latency\n\n");
    out.push_str("This focused supplement measures `Gargos + concrete auxiliary components excluding NIZK proving and verification`. `Aux. generation` is computed as measured `SignEncap excluding NIZK proving` minus the Gargos-only online signing latency under the same ell. It therefore covers the concrete auxiliary data-flow added around Gargos: Pedersen commitment, two LHTLP puzzles, IBE ciphertext, nullifier, and statement/witness construction, but excludes all NIZK proving and verification.\n\n");
    out.push_str("## Distribution Summary\n\n");
    out.push_str("| ell | Stage | Trials | Mean | Median | Std | P95 |\n|---:|---|---:|---:|---:|---:|---:|\n");
    for r in rows {
        for (name, s) in [
            ("Gargos signing", &r.gargos),
            ("SignEncap excluding NIZK proving", &r.sign_encap),
            ("Combine excluding NIZK verification", &r.combine),
            ("Open", &r.open),
            ("Verify excluding NIZK verification", &r.verify),
            ("Trace", &r.trace),
            (
                "Partial-concrete total excluding NIZK proving and verification",
                &r.total,
            ),
        ] {
            out.push_str(&format!(
                "| {} | {} | {} | {:.3} | {:.3} | {:.3} | {:.3} |\n",
                r.ell, name, TRIALS, s.mean, s.median, s.std, s.p95
            ));
        }
    }
    out.push_str("\n## Paper-Ready Table\n\n");
    out.push_str("| ell | Gargos | Aux. generation | Combine | Open | Trace | Total |\n|---:|---:|---:|---:|---:|---:|---:|\n");
    for r in rows {
        out.push_str(&format!(
            "| {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} |\n",
            r.ell, r.gargos.mean, r.aux, r.combine.mean, r.open.mean, r.trace.mean, r.total.mean
        ));
    }
    out.push_str("\n```latex\n");
    out.push_str("\\begin{table}[!htbp]\n\\centering\n\\caption{Partial-concrete protocol latency excluding NIZK proving and\nverification. Times are in milliseconds.}\n\\label{tab:partial-concrete-protocol}\n\\small\n\\begin{tabular}{crrrrrr}\n\\toprule\n$\\ell$ & Gargos & Aux. generation & Combine & Open & Trace & Total \\\\\n\\midrule\n");
    for r in rows {
        out.push_str(&format!(
            "{} & {:.3} & {:.3} & {:.3} & {:.3} & {:.3} & {:.3} \\\\\n",
            r.ell, r.gargos.mean, r.aux, r.combine.mean, r.open.mean, r.trace.mean, r.total.mean
        ));
    }
    out.push_str("\\bottomrule\n\\end{tabular}\n\\end{table}\n```\n\n");
    out.push_str(&format!("Focused supplement runtime: {:.3?}\n", elapsed));
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("results/partial_concrete_evaluation.md")?;
    file.write_all(out.as_bytes())?;
    Ok(())
}

fn gargos_once(ell: usize) -> bool {
    let par = keygen::setup(ell, ell - 1);
    let (public_key, pks, sks) = keygen::kgen(&par);
    let msg = format!("gargos-{ell}").into_bytes();
    let signer_set: Vec<u32> = (1..=ell as u32).collect();
    let mut first = Vec::new();
    for &i in &signer_set {
        let sk = &sks[i as usize - 1];
        let a = random_scalar();
        let rho: [u8; 32] = rand::random();
        let b = par.g * a
            + threshold_signature::hash::f0(&rho) * sk.r
            + threshold_signature::hash::f1(&rho) * sk.u;
        let mu = hcom(i, &rho, &b);
        first.push((i, a, rho, b, mu));
    }
    let mu_vec: Vec<_> = first.iter().map(|(i, _, _, _, mu)| (*i, *mu)).collect();
    let g0p = g0(&msg, &mu_vec);
    let g1p = g1(&msg, &mu_vec);
    let mut a_hat = RistrettoPoint::identity();
    let mut terms = Vec::new();
    for (i, a, rho, b, mu) in first {
        let sk = &sks[i as usize - 1];
        let pk = &pks[i as usize - 1].pk_i;
        let a_point = par.g * a + g0p * sk.r + g1p * sk.u;
        let proof = sig_prove(&par, pk, &a_point, &b, &g0p, &g1p, &rho, &a, sk);
        if mu != hcom(i, &rho, &b) || !sig_verify(&par, pk, &a_point, &b, &g0p, &g1p, &rho, &proof)
        {
            return false;
        }
        let li = lagrange_coeff(i, &signer_set);
        a_hat += a_point * li;
        terms.push((li, a, sk.s));
    }
    let c = hsig(&a_hat, &public_key, &msg);
    let z = terms
        .iter()
        .fold(Scalar::ZERO, |acc, (li, a, s)| acc + *li * (*a + c * *s));
    par.g * z == a_hat + public_key * c
}

fn stats<F: FnMut()>(n: usize, mut f: F) -> Stats {
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        f();
        samples.push(ms(start.elapsed()));
    }
    summarize(samples)
}

fn summarize(mut samples: Vec<f64>) -> Stats {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = samples.len();
    let mean = samples.iter().sum::<f64>() / n as f64;
    let std = (samples
        .iter()
        .map(|x| {
            let d = x - mean;
            d * d
        })
        .sum::<f64>()
        / n as f64)
        .sqrt();
    Stats {
        mean,
        median: samples[n / 2],
        std,
        p95: samples[((n as f64 * 0.95).ceil() as usize)
            .saturating_sub(1)
            .min(n - 1)],
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
