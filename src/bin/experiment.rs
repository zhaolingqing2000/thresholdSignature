use std::collections::BTreeMap;
use std::fs;
use std::hint::black_box;
use std::time::Instant;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use threshold_signature::construction::{
    aggregate_htlp_bytes, aggregate_puzzles_for_benchmark, binding_proof_bytes,
    binding_proof_for_benchmark, combine, commitment_for_benchmark, final_signature_bytes,
    handle_bytes, ibe_encrypt, nullifier, open,
    private_package_bytes as construction_package_bytes, puzzle_bytes, puzzle_eval, puzzle_gen,
    puzzle_solve, puzzle_solve_with_delay_for_benchmark, record_bytes,
    robustness_checks_for_benchmark, setup_construction, sign_encap, trace,
    tracing_ciphertext_bytes, verify, AdditivePuzzle, AuxiliaryHandle, BindingProof,
    ConstructionPublicParams, ConstructionSecretState, Registry, SessionDescriptor,
};
use threshold_signature::hash::{enc_point, g0, g1, hsig_bound};
use threshold_signature::keygen::{kgen, setup};
use threshold_signature::nizk::sig_verify;
use threshold_signature::protocol::{sig1, sig2};
use threshold_signature::randutil::random_scalar;
use threshold_signature::shamir::lagrange_coeff;
use threshold_signature::types::{
    OpeningMessage, Params, PublicKeyShare, SecretKeyShare, SignerState,
};

const SIGNER_SET_SIZES: &[usize] = &[4, 8, 16, 32, 64];
const TRIALS: usize = 100;
const WARMUP_TRIALS: usize = 10;
const MICRO_TRIALS: usize = 1000;
const MATRIX_TRIALS: usize = 1000;
const MESSAGE: &[u8] = b"test message";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Mode {
    Baseline,
    Full,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Baseline => "baseline_gargos",
            Mode::Full => "full_construction",
        }
    }
}

#[derive(Clone, Debug, Default)]
struct TrialMetrics {
    success: bool,
    signing_ms: f64,
    aggregation_ms: f64,
    opening_ms: f64,
    verification_ms: f64,
    tracing_ms: f64,
    total_ms: f64,
    transcript_bytes: usize,
}

#[derive(Clone, Debug, Default)]
struct Stats {
    avg: f64,
    median: f64,
    std: f64,
    p95: f64,
}

#[derive(Clone, Debug)]
struct SummaryRow {
    mode: Mode,
    signer_count: usize,
    trials: usize,
    success: usize,
    failure: usize,
    signing: Stats,
    aggregation: Stats,
    opening: Stats,
    verification: Stats,
    tracing: Stats,
    total: Stats,
    transcript_bytes: Stats,
}

fn dec_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
}

fn normalize_mu_vec(mut mu: Vec<(u32, [u8; 32])>) -> Vec<(u32, [u8; 32])> {
    mu.sort_by_key(|(i, _)| *i);
    mu
}

fn lagrange_map(signer_set: &[u32]) -> Vec<(u32, Scalar)> {
    signer_set
        .iter()
        .map(|&i| (i, lagrange_coeff(i, signer_set)))
        .collect()
}

fn lagrange_for(lagranges: &[(u32, Scalar)], i: u32) -> Option<Scalar> {
    lagranges.iter().find(|(id, _)| *id == i).map(|(_, li)| *li)
}

fn recompute_a_hat(
    openings: &[OpeningMessage],
    lagranges: &[(u32, Scalar)],
) -> Option<RistrettoPoint> {
    let mut a_hat = RistrettoPoint::identity();
    for opening in openings {
        a_hat += dec_point(&opening.a_point)? * lagrange_for(lagranges, opening.i)?;
    }
    Some(a_hat)
}

fn private_package_estimated_bytes(signer_count: usize) -> usize {
    signer_count * (32 + 32 + 32 + 32)
}

fn baseline_transcript_bytes(signer_count: usize) -> usize {
    let base = 32 + MESSAGE.len() + signer_count * 4;
    let mu = signer_count * (4 + 32);
    let openings = signer_count * (4 + 32 + 32 + 32 + 7 * 32);
    let signature = 32 + 32;
    base + mu + openings + signature
}

fn run_baseline(
    par: &Params,
    pk_joint: &RistrettoPoint,
    pk_shares: &[PublicKeyShare],
    sk_shares: &[SecretKeyShare],
    signer_set: &[u32],
    lagranges: &[(u32, Scalar)],
) -> TrialMetrics {
    let total_start = Instant::now();
    let sid: [u8; 32] = rand::random();

    let sign_start = Instant::now();
    let mut commits = Vec::with_capacity(signer_set.len());
    let mut states = Vec::with_capacity(signer_set.len());
    for &i in signer_set {
        let Some(sk_i) = sk_shares.get(i as usize - 1) else {
            return TrialMetrics::default();
        };
        let (commit, state) = sig1(par, &sid, signer_set, MESSAGE, i, sk_i);
        commits.push((commit.i, commit.mu_i));
        states.push(state);
    }
    let mu = normalize_mu_vec(commits);

    let mut openings = Vec::with_capacity(signer_set.len());
    let mut states2: Vec<SignerState> = Vec::with_capacity(signer_set.len());
    for (idx, &i) in signer_set.iter().enumerate() {
        let Some(pk_i) = pk_shares.get(i as usize - 1) else {
            return TrialMetrics::default();
        };
        let Some(sk_i) = sk_shares.get(i as usize - 1) else {
            return TrialMetrics::default();
        };
        let (opening, state) = sig2(par, MESSAGE, i, &mu, pk_i, sk_i, &states[idx]);
        openings.push(opening);
        states2.push(state);
    }
    let Some(a_hat) = recompute_a_hat(&openings, lagranges) else {
        return TrialMetrics::default();
    };
    let c = hsig_bound(&sid, signer_set, &a_hat, pk_joint, MESSAGE);
    let mut partials = Vec::with_capacity(signer_set.len());
    for (idx, &i) in signer_set.iter().enumerate() {
        let Some(sk_i) = sk_shares.get(i as usize - 1) else {
            return TrialMetrics::default();
        };
        let Some(li) = lagrange_for(lagranges, i) else {
            return TrialMetrics::default();
        };
        partials.push(li * (states2[idx].a_i + c * sk_i.s));
    }
    let signing_ms = sign_start.elapsed().as_secs_f64() * 1000.0;

    let aggregation_start = Instant::now();
    let g0p = g0(MESSAGE, &mu);
    let g1p = g1(MESSAGE, &mu);
    let mut aggregation_ok = true;
    for opening in &openings {
        let Some(pk_i) = pk_shares.get(opening.i as usize - 1).map(|pk| pk.pk_i) else {
            aggregation_ok = false;
            break;
        };
        let Some(a_i) = dec_point(&opening.a_point) else {
            aggregation_ok = false;
            break;
        };
        let Some(b_i) = dec_point(&opening.b_point) else {
            aggregation_ok = false;
            break;
        };
        if !sig_verify(
            par,
            &pk_i,
            &a_i,
            &b_i,
            &g0p,
            &g1p,
            &opening.rho_i,
            &opening.pi_open,
        ) {
            aggregation_ok = false;
            break;
        }
    }
    let z = partials.iter().fold(Scalar::ZERO, |acc, z_i| acc + z_i);
    aggregation_ok &= par.g * z == a_hat + (*pk_joint) * c;
    let aggregation_ms = aggregation_start.elapsed().as_secs_f64() * 1000.0;

    let verification_start = Instant::now();
    let verification_ok =
        par.g * z == a_hat + (*pk_joint) * hsig_bound(&sid, signer_set, &a_hat, pk_joint, MESSAGE);
    let verification_ms = verification_start.elapsed().as_secs_f64() * 1000.0;
    let transcript_bytes = baseline_transcript_bytes(signer_set.len());
    black_box(transcript_bytes);

    TrialMetrics {
        success: black_box(aggregation_ok && verification_ok),
        signing_ms,
        aggregation_ms,
        verification_ms,
        total_ms: total_start.elapsed().as_secs_f64() * 1000.0,
        transcript_bytes,
        ..TrialMetrics::default()
    }
}

fn run_full(
    pp: &ConstructionPublicParams,
    secrets: &ConstructionSecretState,
    signer_set: &[u32],
) -> TrialMetrics {
    let total_start = Instant::now();
    let mut registry = Registry::default();

    let sign_start = Instant::now();
    let Some(out) = sign_encap(pp, secrets, &mut registry, MESSAGE, signer_set) else {
        return TrialMetrics::default();
    };
    let signing_ms = sign_start.elapsed().as_secs_f64() * 1000.0;

    let aggregation_start = Instant::now();
    let Some(sigma) = combine(pp, &registry, MESSAGE, &out.d, &out.packages) else {
        return TrialMetrics {
            signing_ms,
            ..TrialMetrics::default()
        };
    };
    let aggregation_ms = aggregation_start.elapsed().as_secs_f64() * 1000.0;

    let opening_start = Instant::now();
    let Some(opened) = open(pp, &registry, MESSAGE, &out.d) else {
        return TrialMetrics {
            signing_ms,
            aggregation_ms,
            ..TrialMetrics::default()
        };
    };
    let opening_ms = opening_start.elapsed().as_secs_f64() * 1000.0;

    let verification_start = Instant::now();
    let verification_ok = verify(pp, &registry, MESSAGE, &sigma);
    let verification_ms = verification_start.elapsed().as_secs_f64() * 1000.0;

    let tracing_start = Instant::now();
    let tracing_ok = trace(pp, secrets, &registry, MESSAGE, &sigma).is_some();
    let tracing_ms = tracing_start.elapsed().as_secs_f64() * 1000.0;

    let record = registry.retrieve_session_record(&out.d).unwrap();
    let transcript_bytes = baseline_transcript_bytes(signer_set.len())
        + private_package_estimated_bytes(signer_set.len())
        + record_bytes(record).len()
        + final_signature_bytes(&sigma).len();
    black_box(transcript_bytes);

    TrialMetrics {
        success: black_box(verification_ok && tracing_ok && opened == sigma),
        signing_ms,
        aggregation_ms,
        opening_ms,
        verification_ms,
        tracing_ms,
        total_ms: total_start.elapsed().as_secs_f64() * 1000.0,
        transcript_bytes,
    }
}

fn stats(values: &[f64]) -> Stats {
    if values.is_empty() {
        return Stats::default();
    }
    let avg = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values.iter().map(|v| (v - avg) * (v - avg)).sum::<f64>() / values.len() as f64;
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = sorted.len() / 2;
    let median = if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    };
    let p95_idx = ((sorted.len() as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    Stats {
        avg,
        median,
        std: variance.sqrt(),
        p95: sorted[p95_idx],
    }
}

fn summarize(mode: Mode, signer_count: usize, metrics: &[TrialMetrics]) -> SummaryRow {
    let success = metrics.iter().filter(|m| m.success).count();
    let vals = |f: fn(&TrialMetrics) -> f64| metrics.iter().map(f).collect::<Vec<f64>>();
    SummaryRow {
        mode,
        signer_count,
        trials: metrics.len(),
        success,
        failure: metrics.len() - success,
        signing: stats(&vals(|m| m.signing_ms)),
        aggregation: stats(&vals(|m| m.aggregation_ms)),
        opening: stats(&vals(|m| m.opening_ms)),
        verification: stats(&vals(|m| m.verification_ms)),
        tracing: stats(&vals(|m| m.tracing_ms)),
        total: stats(&vals(|m| m.total_ms)),
        transcript_bytes: stats(
            &metrics
                .iter()
                .map(|m| m.transcript_bytes as f64)
                .collect::<Vec<_>>(),
        ),
    }
}

fn write_csv(rows: &[SummaryRow]) -> std::io::Result<()> {
    let mut csv = String::from("mode,S,trials,success,failure,signing_ms_avg,signing_ms_median,signing_ms_std,signing_ms_p95,aggregation_ms_avg,aggregation_ms_median,aggregation_ms_std,opening_ms_avg,opening_ms_median,opening_ms_std,verification_ms_avg,verification_ms_median,verification_ms_std,tracing_ms_avg,tracing_ms_median,tracing_ms_std,total_ms_avg,total_ms_median,total_ms_std,total_ms_p95,transcript_bytes_avg,transcript_bytes_std\n");
    for row in rows {
        csv.push_str(&format!(
            "{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.3},{:.3}\n",
            row.mode.as_str(), row.signer_count, row.trials, row.success, row.failure,
            row.signing.avg, row.signing.median, row.signing.std, row.signing.p95,
            row.aggregation.avg, row.aggregation.median, row.aggregation.std,
            row.opening.avg, row.opening.median, row.opening.std,
            row.verification.avg, row.verification.median, row.verification.std,
            row.tracing.avg, row.tracing.median, row.tracing.std,
            row.total.avg, row.total.median, row.total.std, row.total.p95,
            row.transcript_bytes.avg, row.transcript_bytes.std
        ));
    }
    fs::write("results/experiment_results.csv", csv)
}

fn row<'a>(rows: &'a [SummaryRow], mode: Mode, s: usize) -> Option<&'a SummaryRow> {
    rows.iter().find(|r| r.mode == mode && r.signer_count == s)
}

fn write_summary(rows: &[SummaryRow]) -> std::io::Result<()> {
    let mut out = String::new();
    out.push_str("# Experiment Summary\n\n");
    out.push_str("The experiment uses the construction-aligned Rust path: Setup, SignEncap, Combine, Open, Verify, and Trace. Baseline is the unmodified Gargos three-round signing path with standard response aggregation and Schnorr verification. Full construction adds response/randomizer puzzles, Pedersen response commitments, binding-proof checks, canonical registry validation, delayed opening, and message-dependent tracing.\n\n");
    out.push_str(&format!("Each row uses {} measured trials after {} warmup trials. Setup and key generation are excluded from online timings.\n\n", TRIALS, WARMUP_TRIALS));
    out.push_str("| mode | S | success/trials | signing median ms | combine median ms | open median ms | verify median ms | trace median ms | total median ms | transcript bytes |\n");
    out.push_str("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for r in rows {
        out.push_str(&format!(
            "| {} | {} | {}/{} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.0} |\n",
            r.mode.as_str(),
            r.signer_count,
            r.success,
            r.trials,
            r.signing.median,
            r.aggregation.median,
            r.opening.median,
            r.verification.median,
            r.tracing.median,
            r.total.median,
            r.transcript_bytes.avg
        ));
    }
    out.push_str("\n## Overhead ratios\n\n");
    out.push_str("| S | full/baseline total median | extra total ms | extra bytes |\n");
    out.push_str("|---:|---:|---:|---:|\n");
    for &s in SIGNER_SET_SIZES {
        if let (Some(b), Some(f)) = (row(rows, Mode::Baseline, s), row(rows, Mode::Full, s)) {
            out.push_str(&format!(
                "| {} | {:.3}x | {:.3} | {:.0} |\n",
                s,
                f.total.median / b.total.median,
                f.total.median - b.total.median,
                f.transcript_bytes.avg - b.transcript_bytes.avg
            ));
        }
    }
    out.push_str("\nPrototype notes: the HTLP, IBE, and cross-layer binding proof modules implement the interfaces required by the construction for integration testing. They are local prototype primitives rather than production cryptographic backends.\n");
    fs::write("results/experiment_summary.md", out)
}

fn write_latex_tables(rows: &[SummaryRow]) -> std::io::Result<()> {
    let mut out = String::new();
    out.push_str("% Generated from results/experiment_results.csv\n");
    out.push_str("\\begin{table}[t]\n\\centering\n\\caption{End-to-end runtime comparison.}\n\\label{tab:new-runtime}\n\\small\n\\begin{tabular}{lrrrr}\n\\toprule\nMode & $|S|$ & Sign & Verify & Total \\\\\n\\midrule\n");
    for r in rows {
        out.push_str(&format!(
            "{} & {} & {:.3} & {:.3} & {:.3} \\\\\n",
            r.mode.as_str().replace('_', "\\_"),
            r.signer_count,
            r.signing.median,
            r.verification.median,
            r.total.median
        ));
    }
    out.push_str("\\bottomrule\n\\end{tabular}\n\\end{table}\n\n");
    out.push_str("\\begin{table}[t]\n\\centering\n\\caption{Communication overhead from serialized records.}\n\\label{tab:new-communication}\n\\small\n\\begin{tabular}{rrrrr}\n\\toprule\n$|S|$ & Baseline bytes & Full bytes & Additional bytes & Ratio \\\\\n\\midrule\n");
    for &s in SIGNER_SET_SIZES {
        if let (Some(b), Some(f)) = (row(rows, Mode::Baseline, s), row(rows, Mode::Full, s)) {
            out.push_str(&format!(
                "{} & {:.0} & {:.0} & {:.0} & {:.2}x \\\\\n",
                s,
                b.transcript_bytes.avg,
                f.transcript_bytes.avg,
                f.transcript_bytes.avg - b.transcript_bytes.avg,
                f.transcript_bytes.avg / b.transcript_bytes.avg
            ));
        }
    }
    out.push_str("\\bottomrule\n\\end{tabular}\n\\end{table}\n");
    fs::write("results/experiment_tables.tex", out)
}

fn run_parameter_set(signer_count: usize) -> Vec<SummaryRow> {
    let signer_set: Vec<u32> = (1..=signer_count as u32).collect();
    let lagranges = lagrange_map(&signer_set);
    let par = setup(signer_count, signer_count - 1);
    let (pk_joint, pk_shares, sk_shares) = kgen(&par);
    let (full_pp, full_secrets, _) = setup_construction(signer_count, signer_count - 1);

    for _ in 0..WARMUP_TRIALS {
        black_box(run_baseline(
            &par,
            &pk_joint,
            &pk_shares,
            &sk_shares,
            &signer_set,
            &lagranges,
        ));
        black_box(run_full(&full_pp, &full_secrets, &signer_set));
    }

    let mut metrics: BTreeMap<Mode, Vec<TrialMetrics>> = BTreeMap::new();
    metrics.insert(Mode::Baseline, Vec::with_capacity(TRIALS));
    metrics.insert(Mode::Full, Vec::with_capacity(TRIALS));
    for trial in 0..TRIALS {
        if trial % 2 == 0 {
            metrics.get_mut(&Mode::Baseline).unwrap().push(run_baseline(
                &par,
                &pk_joint,
                &pk_shares,
                &sk_shares,
                &signer_set,
                &lagranges,
            ));
            metrics.get_mut(&Mode::Full).unwrap().push(run_full(
                &full_pp,
                &full_secrets,
                &signer_set,
            ));
        } else {
            metrics.get_mut(&Mode::Full).unwrap().push(run_full(
                &full_pp,
                &full_secrets,
                &signer_set,
            ));
            metrics.get_mut(&Mode::Baseline).unwrap().push(run_baseline(
                &par,
                &pk_joint,
                &pk_shares,
                &sk_shares,
                &signer_set,
                &lagranges,
            ));
        }
    }
    vec![
        summarize(
            Mode::Baseline,
            signer_count,
            metrics.get(&Mode::Baseline).unwrap(),
        ),
        summarize(Mode::Full, signer_count, metrics.get(&Mode::Full).unwrap()),
    ]
}

#[derive(Clone, Debug)]
struct ComponentRow {
    component: &'static str,
    stats: Stats,
}

#[derive(Clone, Debug)]
struct DelayRow {
    delay_iters: u64,
    stats: Stats,
}

#[derive(Clone, Debug)]
struct NtRow {
    n: usize,
    t: usize,
    ell: usize,
    success: usize,
    total: Stats,
    signing: Stats,
    verification: Stats,
    transcript_bytes: Stats,
}

#[derive(Clone, Debug)]
struct CorrectnessRow {
    signer_count: usize,
    trials: usize,
    verify_success: usize,
    delayed_success: usize,
    trace_success: usize,
    normal_delayed_equal: usize,
}

#[derive(Clone, Debug)]
struct PhaseRow {
    phase: &'static str,
    stats: Stats,
}

#[derive(Clone, Debug)]
struct CommunicationRow {
    item: &'static str,
    bytes: usize,
}

#[derive(Clone, Debug, Default)]
struct RobustnessSummary {
    trials: usize,
    modified_commitment_rejected: usize,
    modified_puzzle_rejected: usize,
    modified_ciphertext_rejected: usize,
    modified_nullifier_rejected: usize,
    modified_proof_rejected: usize,
    modified_message_rejected: usize,
    modified_digest_rejected: usize,
    modified_response_rejected: usize,
    duplicate_nullifier_rejected: usize,
    missing_handle_rejected: usize,
    cross_session_handle_rejected: usize,
    wrong_tracing_key_rejected: usize,
}

fn time_micro<F: FnMut()>(mut f: F, trials: usize) -> Stats {
    let mut values = Vec::with_capacity(trials);
    for _ in 0..20 {
        f();
    }
    for _ in 0..trials {
        let start = Instant::now();
        f();
        values.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    stats(&values)
}

fn sample_descriptor_and_handle(
    pp: &ConstructionPublicParams,
    secrets: &ConstructionSecretState,
) -> (SessionDescriptor, AuxiliaryHandle) {
    let d = [7u8; 32];
    let m = MESSAGE.to_vec();
    let a_hat = pp.gargos.g * random_scalar();
    let ell = 4;
    let z = random_scalar();
    let tau = random_scalar();
    let c_i = enc_point(&commitment_for_benchmark(pp, &z, &tau));
    let t_i_z = puzzle_gen(&z);
    let t_i_tau = puzzle_gen(&tau);
    let e_i = ibe_encrypt(&pp.ibe_public, MESSAGE, 1);
    let nu_i = nullifier(&d, &secrets.secret_key_shares[0].s);
    let desc = SessionDescriptor { d, m, a_hat, ell };
    let mut handle = AuxiliaryHandle {
        c_i,
        t_i_z,
        t_i_tau,
        e_i,
        nu_i,
        pi_i_bind: BindingProof {
            statement_digest: [0u8; 32],
        },
    };
    handle.pi_i_bind = binding_proof_for_benchmark(&desc, &handle);
    (desc, handle)
}

fn run_component_benchmarks() -> Vec<ComponentRow> {
    let (pp, secrets, _) = setup_construction(8, 2);
    let (desc, handle) = sample_descriptor_and_handle(&pp, &secrets);
    let rows = [
        (
            "Commitment generation",
            time_micro(
                || {
                    let z = random_scalar();
                    let tau = random_scalar();
                    black_box(commitment_for_benchmark(&pp, &z, &tau));
                },
                MICRO_TRIALS,
            ),
        ),
        (
            "HTLP generation",
            time_micro(
                || {
                    let z = random_scalar();
                    black_box(puzzle_gen(&z));
                },
                MICRO_TRIALS,
            ),
        ),
        (
            "IBE encryption",
            time_micro(
                || {
                    black_box(ibe_encrypt(&pp.ibe_public, MESSAGE, 1));
                },
                MICRO_TRIALS,
            ),
        ),
        (
            "NIZK proof generation",
            time_micro(
                || {
                    black_box(binding_proof_for_benchmark(&desc, &handle));
                },
                MICRO_TRIALS,
            ),
        ),
        (
            "Nullifier computation",
            time_micro(
                || {
                    black_box(nullifier(&[3u8; 32], &secrets.secret_key_shares[0].s));
                },
                MICRO_TRIALS,
            ),
        ),
    ];
    rows.into_iter()
        .map(|(component, stats)| ComponentRow { component, stats })
        .collect()
}

fn run_delay_benchmarks() -> Vec<DelayRow> {
    let delays = [0_u64, 1_000, 5_000, 10_000, 20_000];
    let puzzles: Vec<AdditivePuzzle> = (0..16).map(|_| puzzle_gen(&random_scalar())).collect();
    let aggregate = puzzle_eval(&puzzles);
    delays
        .iter()
        .map(|&delay_iters| {
            let st = time_micro(
                || {
                    black_box(puzzle_solve_with_delay_for_benchmark(
                        &aggregate,
                        delay_iters,
                    ));
                },
                100,
            );
            DelayRow {
                delay_iters,
                stats: st,
            }
        })
        .collect()
}

fn run_nt_scalability() -> Vec<NtRow> {
    let configs = [(10, 2), (20, 4), (32, 8), (48, 16)];
    configs
        .iter()
        .map(|&(n, t)| {
            let ell = t + 1;
            let signer_set: Vec<u32> = (1..=ell as u32).collect();
            let (pp, secrets, _) = setup_construction(n, t);
            for _ in 0..WARMUP_TRIALS {
                black_box(run_full(&pp, &secrets, &signer_set));
            }
            let metrics: Vec<TrialMetrics> = (0..50)
                .map(|_| run_full(&pp, &secrets, &signer_set))
                .collect();
            let success = metrics.iter().filter(|m| m.success).count();
            NtRow {
                n,
                t,
                ell,
                success,
                total: stats(&metrics.iter().map(|m| m.total_ms).collect::<Vec<_>>()),
                signing: stats(&metrics.iter().map(|m| m.signing_ms).collect::<Vec<_>>()),
                verification: stats(
                    &metrics
                        .iter()
                        .map(|m| m.verification_ms)
                        .collect::<Vec<_>>(),
                ),
                transcript_bytes: stats(
                    &metrics
                        .iter()
                        .map(|m| m.transcript_bytes as f64)
                        .collect::<Vec<_>>(),
                ),
            }
        })
        .collect()
}

fn run_correctness_matrix() -> Vec<CorrectnessRow> {
    SIGNER_SET_SIZES
        .iter()
        .map(|&s| {
            let signer_set: Vec<u32> = (1..=s as u32).collect();
            let (pp, secrets, _) = setup_construction(s, s - 1);
            let mut row = CorrectnessRow {
                signer_count: s,
                trials: MATRIX_TRIALS,
                verify_success: 0,
                delayed_success: 0,
                trace_success: 0,
                normal_delayed_equal: 0,
            };
            for _ in 0..MATRIX_TRIALS {
                let mut registry = Registry::default();
                if let Some(out) = sign_encap(&pp, &secrets, &mut registry, MESSAGE, &signer_set) {
                    if let Some(sigma) = combine(&pp, &registry, MESSAGE, &out.d, &out.packages) {
                        if verify(&pp, &registry, MESSAGE, &sigma) {
                            row.verify_success += 1;
                        }
                        if let Some(opened) = open(&pp, &registry, MESSAGE, &out.d) {
                            row.delayed_success += 1;
                            if opened == sigma {
                                row.normal_delayed_equal += 1;
                            }
                        }
                        if trace(&pp, &secrets, &registry, MESSAGE, &sigma).as_ref()
                            == Some(&signer_set)
                        {
                            row.trace_success += 1;
                        }
                    }
                }
            }
            row
        })
        .collect()
}

fn run_phase_breakdown() -> Vec<PhaseRow> {
    let signer_count = 32;
    let signer_set: Vec<u32> = (1..=signer_count as u32).collect();
    let lagranges = lagrange_map(&signer_set);
    let par = setup(signer_count, signer_count - 1);
    let (pk_joint, pk_shares, sk_shares) = kgen(&par);
    let (pp, secrets, _) = setup_construction(signer_count, signer_count - 1);
    let (desc, handle) = sample_descriptor_and_handle(&pp, &secrets);

    let phases = [
        (
            "Gargos baseline signing",
            time_micro(
                || {
                    black_box(run_baseline(
                        &par,
                        &pk_joint,
                        &pk_shares,
                        &sk_shares,
                        &signer_set,
                        &lagranges,
                    ));
                },
                100,
            ),
        ),
        (
            "Auxiliary handle generation per signer",
            time_micro(
                || {
                    let z = random_scalar();
                    let tau = random_scalar();
                    let c_i = enc_point(&commitment_for_benchmark(&pp, &z, &tau));
                    let mut h = AuxiliaryHandle {
                        c_i,
                        t_i_z: puzzle_gen(&z),
                        t_i_tau: puzzle_gen(&tau),
                        e_i: ibe_encrypt(&pp.ibe_public, MESSAGE, 1),
                        nu_i: nullifier(&[9u8; 32], &secrets.secret_key_shares[0].s),
                        pi_i_bind: BindingProof {
                            statement_digest: [0u8; 32],
                        },
                    };
                    h.pi_i_bind = binding_proof_for_benchmark(&desc, &h);
                    black_box(h);
                },
                MICRO_TRIALS,
            ),
        ),
        (
            "Commitment generation",
            time_micro(
                || {
                    black_box(commitment_for_benchmark(
                        &pp,
                        &random_scalar(),
                        &random_scalar(),
                    ));
                },
                MICRO_TRIALS,
            ),
        ),
        (
            "Two HTLP puzzle generations",
            time_micro(
                || {
                    let z = random_scalar();
                    let tau = random_scalar();
                    black_box((puzzle_gen(&z), puzzle_gen(&tau)));
                },
                MICRO_TRIALS,
            ),
        ),
        (
            "IBE encryption",
            time_micro(
                || {
                    black_box(ibe_encrypt(&pp.ibe_public, MESSAGE, 1));
                },
                MICRO_TRIALS,
            ),
        ),
        (
            "Binding-proof generation",
            time_micro(
                || {
                    black_box(binding_proof_for_benchmark(&desc, &handle));
                },
                MICRO_TRIALS,
            ),
        ),
        (
            "Normal Combine",
            time_micro(
                || {
                    let mut reg = Registry::default();
                    let out = sign_encap(&pp, &secrets, &mut reg, MESSAGE, &signer_set).unwrap();
                    black_box(combine(&pp, &reg, MESSAGE, &out.d, &out.packages));
                },
                100,
            ),
        ),
        (
            "Delayed Open PEval",
            time_micro(
                || {
                    let mut reg = Registry::default();
                    let out = sign_encap(&pp, &secrets, &mut reg, MESSAGE, &signer_set).unwrap();
                    let rec = reg.retrieve_session_record(&out.d).unwrap();
                    black_box(aggregate_puzzles_for_benchmark(rec));
                },
                100,
            ),
        ),
        (
            "Delayed Open PSolve",
            time_micro(
                || {
                    let p = puzzle_gen(&random_scalar());
                    black_box(puzzle_solve(&p));
                },
                MICRO_TRIALS,
            ),
        ),
        (
            "Public Verify",
            time_micro(
                || {
                    let mut reg = Registry::default();
                    let out = sign_encap(&pp, &secrets, &mut reg, MESSAGE, &signer_set).unwrap();
                    let sig = combine(&pp, &reg, MESSAGE, &out.d, &out.packages).unwrap();
                    black_box(verify(&pp, &reg, MESSAGE, &sig));
                },
                100,
            ),
        ),
        (
            "Trace",
            time_micro(
                || {
                    let mut reg = Registry::default();
                    let out = sign_encap(&pp, &secrets, &mut reg, MESSAGE, &signer_set).unwrap();
                    let sig = combine(&pp, &reg, MESSAGE, &out.d, &out.packages).unwrap();
                    black_box(trace(&pp, &secrets, &reg, MESSAGE, &sig));
                },
                100,
            ),
        ),
        (
            "End-to-end baseline",
            time_micro(
                || {
                    black_box(run_baseline(
                        &par,
                        &pk_joint,
                        &pk_shares,
                        &sk_shares,
                        &signer_set,
                        &lagranges,
                    ));
                },
                100,
            ),
        ),
        (
            "End-to-end full construction",
            time_micro(
                || {
                    black_box(run_full(&pp, &secrets, &signer_set));
                },
                100,
            ),
        ),
    ];
    phases
        .into_iter()
        .map(|(phase, stats)| PhaseRow { phase, stats })
        .collect()
}

fn run_communication_breakdown() -> Vec<CommunicationRow> {
    let signer_count = 32;
    let signer_set: Vec<u32> = (1..=signer_count as u32).collect();
    let (pp, secrets, mut registry) = setup_construction(signer_count, signer_count - 1);
    let out = sign_encap(&pp, &secrets, &mut registry, MESSAGE, &signer_set).unwrap();
    let sigma = combine(&pp, &registry, MESSAGE, &out.d, &out.packages).unwrap();
    let record = registry.retrieve_session_record(&out.d).unwrap();
    let one_handle = &record.handles[0];
    let one_package = &out.packages[0];
    let baseline = baseline_transcript_bytes(signer_count);
    let full = baseline
        + out
            .packages
            .iter()
            .map(|p| construction_package_bytes(p).len())
            .sum::<usize>()
        + record_bytes(record).len()
        + final_signature_bytes(&sigma).len();
    vec![
        CommunicationRow {
            item: "Baseline Gargos transcript",
            bytes: baseline,
        },
        CommunicationRow {
            item: "One public handle",
            bytes: handle_bytes(one_handle).len(),
        },
        CommunicationRow {
            item: "Complete canonical public record",
            bytes: record_bytes(record).len(),
        },
        CommunicationRow {
            item: "One private final-round package",
            bytes: construction_package_bytes(one_package).len(),
        },
        CommunicationRow {
            item: "Aggregate HTLP objects",
            bytes: aggregate_htlp_bytes(&sigma).len(),
        },
        CommunicationRow {
            item: "Final auxiliary signature package",
            bytes: final_signature_bytes(&sigma).len(),
        },
        CommunicationRow {
            item: "Total full construction",
            bytes: full,
        },
        CommunicationRow {
            item: "Additional bytes relative to Gargos",
            bytes: full - baseline,
        },
        CommunicationRow {
            item: "Per-signer marginal overhead",
            bytes: (full - baseline) / signer_count,
        },
        CommunicationRow {
            item: "Handle: commitment",
            bytes: 32,
        },
        CommunicationRow {
            item: "Handle: two HTLPs",
            bytes: puzzle_bytes(&one_handle.t_i_z).len() + puzzle_bytes(&one_handle.t_i_tau).len(),
        },
        CommunicationRow {
            item: "Handle: IBE ciphertext",
            bytes: tracing_ciphertext_bytes(&one_handle.e_i).len(),
        },
        CommunicationRow {
            item: "Handle: nullifier",
            bytes: one_handle.nu_i.len(),
        },
        CommunicationRow {
            item: "Handle: binding proof",
            bytes: binding_proof_bytes(&one_handle.pi_i_bind).len(),
        },
    ]
}

fn run_robustness_matrix() -> RobustnessSummary {
    let signer_set: Vec<u32> = (1..=8u32).collect();
    let (pp, secrets, _) = setup_construction(8, 7);
    let mut summary = RobustnessSummary {
        trials: MATRIX_TRIALS,
        ..RobustnessSummary::default()
    };
    for _ in 0..MATRIX_TRIALS {
        if let Some(r) = robustness_checks_for_benchmark(&pp, &secrets, MESSAGE, &signer_set) {
            summary.modified_commitment_rejected += r.modified_commitment_rejected as usize;
            summary.modified_puzzle_rejected += r.modified_puzzle_rejected as usize;
            summary.modified_ciphertext_rejected += r.modified_ciphertext_rejected as usize;
            summary.modified_nullifier_rejected += r.modified_nullifier_rejected as usize;
            summary.modified_proof_rejected += r.modified_proof_rejected as usize;
            summary.modified_message_rejected += r.modified_message_rejected as usize;
            summary.modified_digest_rejected += r.modified_digest_rejected as usize;
            summary.modified_response_rejected += r.modified_response_rejected as usize;
            summary.duplicate_nullifier_rejected += r.duplicate_nullifier_rejected as usize;
            summary.missing_handle_rejected += r.missing_handle_rejected as usize;
            summary.cross_session_handle_rejected += r.cross_session_handle_rejected as usize;
            summary.wrong_tracing_key_rejected += r.wrong_tracing_key_rejected as usize;
        }
    }
    summary
}

fn write_extended_csv(
    component_rows: &[ComponentRow],
    delay_rows: &[DelayRow],
    nt_rows: &[NtRow],
    correctness_rows: &[CorrectnessRow],
    phase_rows: &[PhaseRow],
    communication_rows: &[CommunicationRow],
    robustness: &RobustnessSummary,
) -> std::io::Result<()> {
    let mut component = String::from("component,avg_ms,median_ms,std_ms,p95_ms\n");
    for r in component_rows {
        component.push_str(&format!(
            "{},{:.6},{:.6},{:.6},{:.6}\n",
            r.component, r.stats.avg, r.stats.median, r.stats.std, r.stats.p95
        ));
    }
    fs::write("results/component_breakdown.csv", component)?;

    let mut delay = String::from("delay_iters,avg_ms,median_ms,std_ms,p95_ms\n");
    for r in delay_rows {
        delay.push_str(&format!(
            "{},{:.6},{:.6},{:.6},{:.6}\n",
            r.delay_iters, r.stats.avg, r.stats.median, r.stats.std, r.stats.p95
        ));
    }
    fs::write("results/htlp_delay.csv", delay)?;

    let mut nt = String::from("n,t,ell,trials,success,signing_median_ms,verification_median_ms,total_median_ms,transcript_bytes\n");
    for r in nt_rows {
        nt.push_str(&format!(
            "{},{},{},50,{},{:.6},{:.6},{:.6},{:.0}\n",
            r.n,
            r.t,
            r.ell,
            r.success,
            r.signing.median,
            r.verification.median,
            r.total.median,
            r.transcript_bytes.avg
        ));
    }
    fs::write("results/nt_scalability.csv", nt)?;

    let mut corr = String::from(
        "S,trials,verify_success,delayed_recovery_success,trace_accuracy,normal_delayed_equal\n",
    );
    for r in correctness_rows {
        corr.push_str(&format!(
            "{},{},{},{},{},{}\n",
            r.signer_count,
            r.trials,
            r.verify_success,
            r.delayed_success,
            r.trace_success,
            r.normal_delayed_equal
        ));
    }
    fs::write("results/correctness_matrix.csv", corr)?;

    let mut phase = String::from("phase,avg_ms,median_ms,std_ms,p95_ms\n");
    for r in phase_rows {
        phase.push_str(&format!(
            "{},{:.6},{:.6},{:.6},{:.6}\n",
            r.phase, r.stats.avg, r.stats.median, r.stats.std, r.stats.p95
        ));
    }
    fs::write("results/phase_breakdown.csv", phase)?;

    let mut comm = String::from("item,bytes\n");
    for r in communication_rows {
        comm.push_str(&format!("{},{}\n", r.item, r.bytes));
    }
    fs::write("results/communication_breakdown.csv", comm)?;

    let mut robust = String::from("test,trials,rejected,rate_percent\n");
    let rows = [
        (
            "modified commitment",
            robustness.modified_commitment_rejected,
        ),
        ("modified puzzle", robustness.modified_puzzle_rejected),
        (
            "modified ciphertext",
            robustness.modified_ciphertext_rejected,
        ),
        ("modified nullifier", robustness.modified_nullifier_rejected),
        ("modified proof", robustness.modified_proof_rejected),
        ("modified message", robustness.modified_message_rejected),
        (
            "modified session digest",
            robustness.modified_digest_rejected,
        ),
        (
            "modified aggregate response",
            robustness.modified_response_rejected,
        ),
        (
            "duplicate nullifier",
            robustness.duplicate_nullifier_rejected,
        ),
        ("missing handle", robustness.missing_handle_rejected),
        (
            "cross-session handle",
            robustness.cross_session_handle_rejected,
        ),
        ("wrong tracing key", robustness.wrong_tracing_key_rejected),
    ];
    for (name, rejected) in rows {
        robust.push_str(&format!(
            "{},{},{},{:.2}\n",
            name,
            robustness.trials,
            rejected,
            pct(rejected, robustness.trials)
        ));
    }
    fs::write("results/robustness_rejection.csv", robust)
}

fn pct(success: usize, trials: usize) -> f64 {
    100.0 * success as f64 / trials as f64
}

fn write_experimental_section(
    rows: &[SummaryRow],
    component_rows: &[ComponentRow],
    delay_rows: &[DelayRow],
    nt_rows: &[NtRow],
    correctness_rows: &[CorrectnessRow],
) -> std::io::Result<()> {
    let mut tex = String::new();
    tex.push_str(
        r"\section{Experimental Evaluation}
\label{sec:experiment}

\subsection{Experimental Setup}

We evaluate the Rust prototype that implements the construction in
Section~\ref{sec:construction}. The implementation exposes the same top-level
interfaces as the construction: \textsf{Setup}, \textsf{SignEncap},
\textsf{Combine}, \textsf{Open}, \textsf{Verify}, and \textsf{Trace}. The
baseline is the unmodified Gargos-style threshold Schnorr path. The full
construction keeps the Gargos challenge, response equation, aggregation rule,
and Schnorr verification equation unchanged, while adding the auxiliary response
layer consisting of response commitments, two additive time-lock puzzles,
message-dependent tracing ciphertexts, nullifiers, binding proofs, and a
canonical public record.

All measurements were obtained in Rust release mode using
\texttt{std::time::Instant}. Unless otherwise stated, each end-to-end
configuration uses 100 measured trials after 10 warmup trials. Setup and key
generation are excluded from online timing. The HTLP, IBE, and binding-proof
backends are local interface-compatible prototype components. The measurements
therefore evaluate construction-level integration overhead rather than claiming
the intrinsic performance of a production HTLP, IBE, or general-purpose NIZK
backend.

The evaluation proceeds in six steps. We first validate correctness over repeated
executions. We then isolate auxiliary-layer component costs, measure the effect
of the prototype HTLP delay parameter, compare end-to-end overhead with the
Gargos baseline, evaluate scalability under different threshold parameters, and
finally compare the resulting functionality with TiMTAPS and related threshold
signing functionality.

\subsection{Repeated Correctness Validation}

The first question is whether the complete implementation executes the full
pipeline reliably. Table~\ref{tab:correctness-matrix} reports repeated tests of
public verification, delayed recovery, tracing accuracy, and byte-level equality
between normal and delayed release outputs. A trial is counted as a delayed
recovery success only when \textsf{Open} reconstructs an output accepted by the
same checks as \textsf{Combine}; equality requires the two final packages to be
identical.

\begin{table}[t]
\centering
\caption{Repeated correctness validation of the full construction.}
\label{tab:correctness-matrix}
\small
\begin{tabular}{rrrrr}
\toprule
$|S|$ & Verify & Delayed recovery & Trace accuracy & Equal outputs \\
\midrule
",
    );
    for r in correctness_rows {
        tex.push_str(&format!(
            "{} & {:.1}\\% & {:.1}\\% & {:.1}\\% & {:.1}\\% \\\\\n",
            r.signer_count,
            pct(r.verify_success, r.trials),
            pct(r.delayed_success, r.trials),
            pct(r.trace_success, r.trials),
            pct(r.normal_delayed_equal, r.trials)
        ));
    }
    tex.push_str(
        r"\bottomrule
\end{tabular}
\end{table}

Table~\ref{tab:correctness-matrix} shows that all tested executions verify,
recover, and trace correctly. This establishes that the implementation exercises
the complete construction rather than only the underlying signing path.

\subsection{Auxiliary-Layer Component Breakdown}

After validating correctness, we isolate the cost of the auxiliary layer.
Table~\ref{tab:component-breakdown-new} reports microbenchmarks for commitment
generation, HTLP generation, IBE encryption, prototype binding-proof generation,
and nullifier computation. These are signer-local operations performed by
\textsf{SignEncap} after the Gargos response share has been computed.

\begin{table}[t]
\centering
\caption{Auxiliary-layer component cost in the Rust prototype.}
\label{tab:component-breakdown-new}
\small
\begin{tabular}{lrr}
\toprule
Component & Median (ms) & Std. dev. (ms) \\
\midrule
",
    );
    for r in component_rows {
        tex.push_str(&format!(
            "{} & {:.6} & {:.6} \\\\\n",
            r.component, r.stats.median, r.stats.std
        ));
    }
    tex.push_str(
        r"\bottomrule
\end{tabular}
\end{table}

The component results show that the measured auxiliary operations are small in
this prototype. Commitment generation is the most visible group-operation cost,
while HTLP generation, tracing encryption, nullifier computation, and the
prototype binding proof are dominated by hashing and serialization. In a
production implementation, the binding-proof row should be replaced by the cost
of the chosen NIZK backend.

\subsection{HTLP Delay Parameter}

The delayed path depends on the time-lock puzzle solving work. Table~\ref{tab:htlp-delay}
therefore measures the prototype \textsf{PSolve} interface under different
sequential-work parameters. The parameter is reported as the number of
sequential hash iterations used by the local benchmark backend.

\begin{table}[t]
\centering
\caption{Prototype HTLP solving time under different delay parameters.}
\label{tab:htlp-delay}
\small
\begin{tabular}{rrr}
\toprule
Delay iterations & Median (ms) & Std. dev. (ms) \\
\midrule
",
    );
    for r in delay_rows {
        tex.push_str(&format!(
            "{} & {:.3} & {:.3} \\\\\n",
            r.delay_iters, r.stats.median, r.stats.std
        ));
    }
    tex.push_str(
        r"\bottomrule
\end{tabular}
\end{table}

As expected, the solving time grows with the delay parameter. Changing this
parameter affects delayed-release latency but not the protocol structure: the
same canonical record, aggregate commitment, and verification equations are used
for every row in Table~\ref{tab:htlp-delay}.

\subsection{End-to-End Runtime Overhead}

Component costs do not by themselves determine deployability. The main runtime
metric is the overhead of the full construction relative to the original Gargos
path. Table~\ref{tab:runtime-new} reports median online latency for signing,
verification, and total execution.

\begin{table}[t]
\centering
\caption{End-to-end median runtime comparison in milliseconds.}
\label{tab:runtime-new}
\small
\begin{tabular}{lrrrr}
\toprule
Mode & $|S|$ & Sign & Verify & Total \\
\midrule
",
    );
    for r in rows {
        tex.push_str(&format!(
            "{} & {} & {:.3} & {:.3} & {:.3} \\\\\n",
            r.mode.as_str().replace('_', "\\_"),
            r.signer_count,
            r.signing.median,
            r.verification.median,
            r.total.median
        ));
    }
    tex.push_str(
        r"\bottomrule
\end{tabular}
\end{table}

The full construction adds signer-local auxiliary work, so signing is the phase
that increases most clearly. At larger signer sets, total overhead remains
moderate because the Gargos baseline also scales with the number of active
signers.

\subsection{Scalability Across Threshold Parameters}

We next vary the threshold configuration rather than only the active signer set.
For each pair $(n,t)$, the active set uses the minimum authorized size
$\ell=t+1$. Table~\ref{tab:nt-scalability} reports the resulting median signing,
verification, total latency, and serialized byte size.

\begin{table}[t]
\centering
\caption{Scalability under different threshold parameters.}
\label{tab:nt-scalability}
\small
\begin{tabular}{rrrrrr}
\toprule
$n$ & $t$ & $\ell$ & Sign & Verify & Total \\
\midrule
",
    );
    for r in nt_rows {
        tex.push_str(&format!(
            "{} & {} & {} & {:.3} & {:.3} & {:.3} \\\\\n",
            r.n, r.t, r.ell, r.signing.median, r.verification.median, r.total.median
        ));
    }
    tex.push_str(
        r"\bottomrule
\end{tabular}
\end{table}

Table~\ref{tab:nt-scalability} shows that the implementation scales with the
number of active signers rather than with the total registered population alone.
This matches the construction: the public record stores one certified handle per
participating signer, and verification checks the handle set associated with the
session digest.

\subsection{Communication Overhead}

Threshold protocols also incur communication and storage cost. Table~\ref{tab:comm-new}
reports serialized sizes for the baseline transcript and for the full
construction, where the full size includes the baseline Gargos transcript,
private response packages, canonical record, and final auxiliary signature
package.

\begin{table}[t]
\centering
\caption{Serialized communication size of baseline and full construction.}
\label{tab:comm-new}
\small
\begin{tabular}{rrrrr}
\toprule
$|S|$ & Baseline bytes & Full bytes & Additional bytes & Ratio \\
\midrule
",
    );
    for &s in SIGNER_SET_SIZES {
        if let (Some(b), Some(f)) = (row(rows, Mode::Baseline, s), row(rows, Mode::Full, s)) {
            tex.push_str(&format!(
                "{} & {:.0} & {:.0} & {:.0} & {:.2}x \\\\\n",
                s,
                b.transcript_bytes.avg,
                f.transcript_bytes.avg,
                f.transcript_bytes.avg - b.transcript_bytes.avg,
                f.transcript_bytes.avg / b.transcript_bytes.avg
            ));
        }
    }
    tex.push_str(r"\bottomrule
\end{tabular}
\end{table}

The communication overhead is linear in $|S|$. Each signer contributes one
commitment, two puzzle objects, one tracing ciphertext, one nullifier, one
binding proof object, and one private package. Aggregate session objects remain
fixed size.

\subsection{Functional Comparison}

Table~\ref{tab:functional-comparison-new} compares the construction with Gargos
and TiMTAPS at the level of supported functionality. The comparison is
qualitative because the schemes target different underlying signing models.

\begin{table}[t]
\centering
\caption{Functional comparison with related schemes.}
\label{tab:functional-comparison-new}
\small
\begin{tabular}{lccccc}
\toprule
Scheme & Adaptive security & 3-round signing & Timed combining & Verifiable combining & Message-dependent tracing \\
\midrule
Gargos & Yes & Yes & No & No & No \\
TiMTAPS & Not Gargos-based & No & Yes & Yes & Yes \\
Ours & Inherits Gargos layer & Yes & Yes & Yes & Yes \\
\bottomrule
\end{tabular}
\end{table}

Gargos provides the low-latency adaptive threshold Schnorr signing path, but it
does not provide delayed release or tracing. TiMTAPS provides timed combining
and tracing functionality, but it is not built around the Gargos three-round
adaptive signing path. Our construction combines these properties by attaching a
certified auxiliary response layer after the accepted Gargos transcript.

\subsection{Discussion}

The experiments show that the full construction is implemented end to end and
that normal release, delayed release, verification, and tracing agree over
repeated executions. The added functionality introduces measurable but moderate
runtime overhead, mainly in signer-local auxiliary generation. Communication
cost grows linearly with the active signer set because one public handle and one
private package are produced per signer. The prototype measurements should be
read as integration results: replacing the local HTLP, IBE, or binding-proof
backends with production implementations will change absolute costs, but not the
protocol-level structure measured here.
");
    fs::write("results/experimental_evaluation_section.tex", tex)
}

fn main() -> std::io::Result<()> {
    fs::create_dir_all("results")?;
    let mut rows = Vec::new();
    println!("correctness: S,mode,trials,success,failure");
    for &s in SIGNER_SET_SIZES {
        let set_rows = run_parameter_set(s);
        for r in &set_rows {
            println!(
                "{},{},{},{},{}",
                s,
                r.mode.as_str(),
                r.trials,
                r.success,
                r.failure
            );
        }
        rows.extend(set_rows);
    }

    let component_rows = run_component_benchmarks();
    let delay_rows = run_delay_benchmarks();
    let nt_rows = run_nt_scalability();
    let correctness_rows = run_correctness_matrix();
    let phase_rows = run_phase_breakdown();
    let communication_rows = run_communication_breakdown();
    let robustness = run_robustness_matrix();

    write_csv(&rows)?;
    write_summary(&rows)?;
    write_latex_tables(&rows)?;
    write_extended_csv(
        &component_rows,
        &delay_rows,
        &nt_rows,
        &correctness_rows,
        &phase_rows,
        &communication_rows,
        &robustness,
    )?;
    write_experimental_section(
        &rows,
        &component_rows,
        &delay_rows,
        &nt_rows,
        &correctness_rows,
    )?;
    println!("wrote results/experiment_results.csv");
    println!("wrote results/component_breakdown.csv");
    println!("wrote results/htlp_delay.csv");
    println!("wrote results/nt_scalability.csv");
    println!("wrote results/correctness_matrix.csv");
    println!("wrote results/phase_breakdown.csv");
    println!("wrote results/communication_breakdown.csv");
    println!("wrote results/robustness_rejection.csv");
    println!("wrote results/experimental_evaluation_section.tex");
    Ok(())
}
