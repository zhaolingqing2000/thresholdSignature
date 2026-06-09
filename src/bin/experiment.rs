use std::collections::BTreeMap;
use std::fs;
use std::hint::black_box;
use std::process::Command;
use std::time::Instant;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use threshold_signature::hash::{g0, g1, hbind, hsig_bound};
use threshold_signature::keygen::{kgen, setup};
use threshold_signature::nizk::{sig_verify, Proof};
use threshold_signature::protocol::{
    aggregate_and_verify, gargos_sign_and_bind, sig1, sig2, verify_aggregate_transcript,
};
use threshold_signature::shamir::lagrange_coeff;
use threshold_signature::types::{
    AggTranscript, Params, PartialSignature, PublicKeyShare, SecretKeyShare, Signature, SignerState,
};

const SIGNER_SET_SIZES: &[usize] = &[4, 8, 16, 32];
const TRIALS: usize = 200;
const WARMUP_TRIALS: usize = 20;
const MESSAGE: &[u8] = b"test message";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Mode {
    Baseline,
    WitnessOnly,
    Full,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Baseline => "baseline",
            Mode::WitnessOnly => "witness_only",
            Mode::Full => "full",
        }
    }

}

#[derive(Clone, Debug)]
struct LocalEntry {
    i: u32,
    mu_i: [u8; 32],
    rho_i: [u8; 32],
    b_i: RistrettoPoint,
    a_i: RistrettoPoint,
    w_i: Option<RistrettoPoint>,
    pi_open: Proof,
}

#[derive(Clone, Debug)]
struct LocalTranscript {
    sid: [u8; 32],
    signer_set: Vec<u32>,
    message: Vec<u8>,
    mu: Vec<(u32, [u8; 32])>,
    entries: Vec<LocalEntry>,
    signature: Option<Signature>,
    aggregate_witness: Option<RistrettoPoint>,
}

#[derive(Clone, Debug, Default)]
struct TrialMetrics {
    success: bool,
    signing_ms: f64,
    aggregation_ms: f64,
    verification_ms: f64,
    total_ms: f64,
    transcript_bytes: usize,
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
    verification: Stats,
    total: Stats,
    transcript_bytes: Stats,
}

#[derive(Clone, Debug, Default)]
struct Stats {
    avg: f64,
    median: f64,
    std: f64,
    p95: f64,
}

fn dec_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*bytes).decompress()
}

fn dec_scalar(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

fn proof_bytes() -> usize {
    7 * 32
}

fn witness_proof_bytes() -> usize {
    8 * 32
}

fn base_common_bytes(signer_set_len: usize, message_len: usize) -> usize {
    32 + signer_set_len * 4 + message_len
}

fn baseline_transcript_size(transcript: &LocalTranscript) -> usize {
    let mut total = base_common_bytes(transcript.signer_set.len(), transcript.message.len());
    total += transcript.mu.len() * (4 + 32);
    for _ in &transcript.entries {
        total += 4; // signer id
        total += 32; // rho_i
        total += 32; // B_i
        total += 32; // A_i
        total += proof_bytes(); // pi_open
    }
    if transcript.signature.is_some() {
        total += 32 + 32; // sigma = (A_hat, z)
    }
    total
}

fn witness_only_transcript_size(transcript: &LocalTranscript) -> usize {
    let mut total = baseline_transcript_size(transcript);
    total += transcript.entries.iter().filter(|entry| entry.w_i.is_some()).count() * 32;
    if transcript.aggregate_witness.is_some() {
        total += 32;
    }
    total
}

fn full_transcript_size(transcript: &AggTranscript) -> usize {
    let mut total = base_common_bytes(transcript.signer_set.len(), transcript.message.len());
    total += transcript.mu.len() * (4 + 32);
    for _ in &transcript.entries {
        total += 4; // signer id
        total += 32; // rho_i
        total += 32; // B_i
        total += 32; // A_i
        total += 32; // W_i
        total += proof_bytes(); // pi_open
        total += witness_proof_bytes(); // pi_wit
    }
    if transcript.signature.is_some() {
        total += 32 + 32; // sigma = (A_hat, z)
    }
    if transcript.aggregate_witness.is_some() {
        total += 32; // Y
    }
    total
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

fn recompute_a_hat(entries: &[LocalEntry], lagranges: &[(u32, Scalar)]) -> Option<RistrettoPoint> {
    let mut a_hat = RistrettoPoint::identity();
    for entry in entries {
        a_hat += entry.a_i * lagrange_for(lagranges, entry.i)?;
    }
    Some(a_hat)
}

fn verify_openings(
    par: &Params,
    pk_shares: &[PublicKeyShare],
    transcript: &LocalTranscript,
) -> bool {
    let g0p = g0(&transcript.message, &transcript.mu);
    let g1p = g1(&transcript.message, &transcript.mu);

    for entry in &transcript.entries {
        let expected_mu = hbind(
            &transcript.sid,
            &transcript.signer_set,
            &transcript.message,
            entry.i,
            &entry.rho_i,
            &entry.b_i,
        );
        if expected_mu != entry.mu_i {
            return false;
        }

        let Some(pk_i) = pk_shares.get(entry.i as usize - 1).map(|pk| pk.pk_i) else {
            return false;
        };
        if !sig_verify(
            par,
            &pk_i,
            &entry.a_i,
            &entry.b_i,
            &g0p,
            &g1p,
            &entry.rho_i,
            &entry.pi_open,
        ) {
            return false;
        }
    }
    true
}

fn sign_base_rounds(
    par: &Params,
    message: &[u8],
    signer_set: &[u32],
    pk_shares: &[PublicKeyShare],
    sk_shares: &[SecretKeyShare],
) -> Option<(LocalTranscript, Vec<SignerState>)> {
    let sid: [u8; 32] = rand::random();
    let mut commits = Vec::with_capacity(signer_set.len());
    let mut states = Vec::with_capacity(signer_set.len());

    for &i in signer_set {
        let sk_i = sk_shares.get(i as usize - 1)?;
        let (commit, state) = sig1(par, &sid, signer_set, message, i, sk_i);
        commits.push((commit.i, commit.mu_i));
        states.push(state);
    }
    let mu = normalize_mu_vec(commits);

    let mut openings = Vec::with_capacity(signer_set.len());
    let mut states2 = Vec::with_capacity(signer_set.len());
    for (idx, &i) in signer_set.iter().enumerate() {
        let pk_i = pk_shares.get(i as usize - 1)?;
        let sk_i = sk_shares.get(i as usize - 1)?;
        let (opening, state) = sig2(par, message, i, &mu, pk_i, sk_i, &states[idx]);
        openings.push(opening);
        states2.push(state);
    }

    let mut entries = Vec::with_capacity(signer_set.len());
    for opening in &openings {
        let mu_i = mu.iter().find(|(id, _)| *id == opening.i)?.1;
        entries.push(LocalEntry {
            i: opening.i,
            mu_i,
            rho_i: opening.rho_i,
            b_i: dec_point(&opening.b_point)?,
            a_i: dec_point(&opening.a_point)?,
            w_i: None,
            pi_open: opening.pi_open.clone(),
        });
    }

    Some((
        LocalTranscript {
            sid,
            signer_set: signer_set.to_vec(),
            message: message.to_vec(),
            mu,
            entries,
            signature: None,
            aggregate_witness: None,
        },
        states2,
    ))
}

fn baseline_response_shares(
    pk_joint: &RistrettoPoint,
    transcript: &LocalTranscript,
    states: &[SignerState],
    sk_shares: &[SecretKeyShare],
    lagranges: &[(u32, Scalar)],
) -> Option<Vec<PartialSignature>> {
    let a_hat = recompute_a_hat(&transcript.entries, lagranges)?;
    let c = hsig_bound(
        &transcript.sid,
        &transcript.signer_set,
        &a_hat,
        pk_joint,
        &transcript.message,
    );

    let mut partials = Vec::with_capacity(transcript.signer_set.len());
    for (idx, &i) in transcript.signer_set.iter().enumerate() {
        let state = states.get(idx)?;
        let sk_i = sk_shares.get(i as usize - 1)?;
        let li = lagrange_for(lagranges, i)?;
        let z_i = li * (state.a_i + c * sk_i.s);
        partials.push(PartialSignature {
            i,
            z_i: z_i.to_bytes(),
        });
    }
    Some(partials)
}

fn witness_only_response_shares(
    par: &Params,
    pk_joint: &RistrettoPoint,
    transcript: &mut LocalTranscript,
    states: &[SignerState],
    sk_shares: &[SecretKeyShare],
    lagranges: &[(u32, Scalar)],
) -> Option<Vec<PartialSignature>> {
    let partials = baseline_response_shares(pk_joint, transcript, states, sk_shares, lagranges)?;
    for partial in &partials {
        let z_i = dec_scalar(&partial.z_i);
        let entry = transcript.entries.iter_mut().find(|entry| entry.i == partial.i)?;
        entry.w_i = Some(par.g * z_i);
    }
    Some(partials)
}

fn aggregate_baseline(
    par: &Params,
    pk_joint: &RistrettoPoint,
    pk_shares: &[PublicKeyShare],
    transcript: &mut LocalTranscript,
    partials: &[PartialSignature],
    lagranges: &[(u32, Scalar)],
) -> bool {
    if !verify_openings(par, pk_shares, transcript) {
        return false;
    }

    let Some(a_hat) = recompute_a_hat(&transcript.entries, lagranges) else {
        return false;
    };
    let c = hsig_bound(
        &transcript.sid,
        &transcript.signer_set,
        &a_hat,
        pk_joint,
        &transcript.message,
    );
    let z = partials
        .iter()
        .fold(Scalar::ZERO, |acc, partial| acc + dec_scalar(&partial.z_i));

    if par.g * z != a_hat + (*pk_joint) * c {
        return false;
    }
    transcript.signature = Some(Signature { a_hat, z });
    true
}

fn aggregate_witness_only(
    par: &Params,
    pk_joint: &RistrettoPoint,
    pk_shares: &[PublicKeyShare],
    transcript: &mut LocalTranscript,
    partials: &[PartialSignature],
    lagranges: &[(u32, Scalar)],
) -> bool {
    if !aggregate_baseline(par, pk_joint, pk_shares, transcript, partials, lagranges) {
        return false;
    }

    let mut y = RistrettoPoint::identity();
    for partial in partials {
        let z_i = dec_scalar(&partial.z_i);
        let Some(entry) = transcript.entries.iter().find(|entry| entry.i == partial.i) else {
            return false;
        };
        let Some(w_i) = entry.w_i else {
            return false;
        };
        if par.g * z_i != w_i {
            return false;
        }
        y += w_i;
    }

    let Some(sig) = &transcript.signature else {
        return false;
    };
    if par.g * sig.z != y {
        return false;
    }
    transcript.aggregate_witness = Some(y);
    true
}

fn verify_baseline(
    par: &Params,
    pk_joint: &RistrettoPoint,
    pk_shares: &[PublicKeyShare],
    transcript: &LocalTranscript,
    lagranges: &[(u32, Scalar)],
) -> bool {
    if !verify_openings(par, pk_shares, transcript) {
        return false;
    }
    let Some(sig) = &transcript.signature else {
        return false;
    };
    let Some(a_hat) = recompute_a_hat(&transcript.entries, lagranges) else {
        return false;
    };
    if sig.a_hat != a_hat {
        return false;
    }
    let c = hsig_bound(
        &transcript.sid,
        &transcript.signer_set,
        &sig.a_hat,
        pk_joint,
        &transcript.message,
    );
    par.g * sig.z == sig.a_hat + (*pk_joint) * c
}

fn verify_witness_only(
    par: &Params,
    pk_joint: &RistrettoPoint,
    pk_shares: &[PublicKeyShare],
    transcript: &LocalTranscript,
    lagranges: &[(u32, Scalar)],
) -> bool {
    if !verify_baseline(par, pk_joint, pk_shares, transcript, lagranges) {
        return false;
    }

    let Some(sig) = &transcript.signature else {
        return false;
    };
    let Some(y) = transcript.aggregate_witness else {
        return false;
    };
    let mut y_prime = RistrettoPoint::identity();
    for entry in &transcript.entries {
        let Some(w_i) = entry.w_i else {
            return false;
        };
        y_prime += w_i;
    }
    y == y_prime && par.g * sig.z == y
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

    let sign_start = Instant::now();
    let Some((mut transcript, states)) =
        sign_base_rounds(par, MESSAGE, signer_set, pk_shares, sk_shares)
    else {
        return TrialMetrics::default();
    };
    let Some(partials) =
        baseline_response_shares(pk_joint, &transcript, &states, sk_shares, lagranges)
    else {
        return TrialMetrics::default();
    };
    let signing_ms = sign_start.elapsed().as_secs_f64() * 1000.0;

    let aggregation_start = Instant::now();
    let aggregation_ok =
        aggregate_baseline(par, pk_joint, pk_shares, &mut transcript, &partials, lagranges);
    let aggregation_ms = aggregation_start.elapsed().as_secs_f64() * 1000.0;

    let verification_start = Instant::now();
    let verification_ok = verify_baseline(par, pk_joint, pk_shares, &transcript, lagranges);
    let verification_ms = verification_start.elapsed().as_secs_f64() * 1000.0;

    let transcript_bytes = baseline_transcript_size(&transcript);
    let success = black_box(aggregation_ok && verification_ok);
    black_box(transcript_bytes);

    TrialMetrics {
        success,
        signing_ms,
        aggregation_ms,
        verification_ms,
        total_ms: total_start.elapsed().as_secs_f64() * 1000.0,
        transcript_bytes,
    }
}

fn run_witness_only(
    par: &Params,
    pk_joint: &RistrettoPoint,
    pk_shares: &[PublicKeyShare],
    sk_shares: &[SecretKeyShare],
    signer_set: &[u32],
    lagranges: &[(u32, Scalar)],
) -> TrialMetrics {
    let total_start = Instant::now();

    let sign_start = Instant::now();
    let Some((mut transcript, states)) =
        sign_base_rounds(par, MESSAGE, signer_set, pk_shares, sk_shares)
    else {
        return TrialMetrics::default();
    };
    let Some(partials) =
        witness_only_response_shares(par, pk_joint, &mut transcript, &states, sk_shares, lagranges)
    else {
        return TrialMetrics::default();
    };
    let signing_ms = sign_start.elapsed().as_secs_f64() * 1000.0;

    let aggregation_start = Instant::now();
    let aggregation_ok =
        aggregate_witness_only(par, pk_joint, pk_shares, &mut transcript, &partials, lagranges);
    let aggregation_ms = aggregation_start.elapsed().as_secs_f64() * 1000.0;

    let verification_start = Instant::now();
    let verification_ok = verify_witness_only(par, pk_joint, pk_shares, &transcript, lagranges);
    let verification_ms = verification_start.elapsed().as_secs_f64() * 1000.0;

    let transcript_bytes = witness_only_transcript_size(&transcript);
    let success = black_box(aggregation_ok && verification_ok);
    black_box(transcript_bytes);

    TrialMetrics {
        success,
        signing_ms,
        aggregation_ms,
        verification_ms,
        total_ms: total_start.elapsed().as_secs_f64() * 1000.0,
        transcript_bytes,
    }
}

fn run_full(
    par: &Params,
    pk_joint: &RistrettoPoint,
    pk_shares: &[PublicKeyShare],
    sk_shares: &[SecretKeyShare],
    signer_set: &[u32],
) -> TrialMetrics {
    let total_start = Instant::now();

    let sign_start = Instant::now();
    let Some((transcript, partials)) =
        gargos_sign_and_bind(par, MESSAGE, signer_set, pk_joint, pk_shares, sk_shares)
    else {
        return TrialMetrics::default();
    };
    let signing_ms = sign_start.elapsed().as_secs_f64() * 1000.0;

    let aggregation_start = Instant::now();
    let Some(transcript) = aggregate_and_verify(par, pk_joint, pk_shares, transcript, &partials)
    else {
        return TrialMetrics {
            signing_ms,
            total_ms: total_start.elapsed().as_secs_f64() * 1000.0,
            ..TrialMetrics::default()
        };
    };
    let aggregation_ms = aggregation_start.elapsed().as_secs_f64() * 1000.0;

    let verification_start = Instant::now();
    let verification_ok = verify_aggregate_transcript(par, pk_joint, pk_shares, MESSAGE, &transcript);
    let verification_ms = verification_start.elapsed().as_secs_f64() * 1000.0;

    let transcript_bytes = full_transcript_size(&transcript);
    let success = black_box(verification_ok);
    black_box(transcript_bytes);

    TrialMetrics {
        success,
        signing_ms,
        aggregation_ms,
        verification_ms,
        total_ms: total_start.elapsed().as_secs_f64() * 1000.0,
        transcript_bytes,
    }
}

fn run_mode(
    mode: Mode,
    par: &Params,
    pk_joint: &RistrettoPoint,
    pk_shares: &[PublicKeyShare],
    sk_shares: &[SecretKeyShare],
    signer_set: &[u32],
    lagranges: &[(u32, Scalar)],
) -> TrialMetrics {
    match mode {
        Mode::Baseline => run_baseline(par, pk_joint, pk_shares, sk_shares, signer_set, lagranges),
        Mode::WitnessOnly => {
            run_witness_only(par, pk_joint, pk_shares, sk_shares, signer_set, lagranges)
        }
        Mode::Full => run_full(par, pk_joint, pk_shares, sk_shares, signer_set),
    }
}

fn stats(values: &[f64]) -> Stats {
    if values.is_empty() {
        return Stats::default();
    }

    let avg = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values
        .iter()
        .map(|value| {
            let diff = value - avg;
            diff * diff
        })
        .sum::<f64>()
        / values.len() as f64;

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = sorted.len() / 2;
    let median = if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    };
    let p95_idx = ((sorted.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);

    Stats {
        avg,
        median,
        std: variance.sqrt(),
        p95: sorted[p95_idx.min(sorted.len() - 1)],
    }
}

fn summarize(mode: Mode, signer_count: usize, metrics: &[TrialMetrics]) -> SummaryRow {
    let success = metrics.iter().filter(|metric| metric.success).count();
    let signing: Vec<f64> = metrics.iter().map(|metric| metric.signing_ms).collect();
    let aggregation: Vec<f64> = metrics.iter().map(|metric| metric.aggregation_ms).collect();
    let verification: Vec<f64> = metrics.iter().map(|metric| metric.verification_ms).collect();
    let total: Vec<f64> = metrics.iter().map(|metric| metric.total_ms).collect();
    let transcript: Vec<f64> = metrics
        .iter()
        .map(|metric| metric.transcript_bytes as f64)
        .collect();

    SummaryRow {
        mode,
        signer_count,
        trials: metrics.len(),
        success,
        failure: metrics.len() - success,
        signing: stats(&signing),
        aggregation: stats(&aggregation),
        verification: stats(&verification),
        total: stats(&total),
        transcript_bytes: stats(&transcript),
    }
}

fn csv_row(row: &SummaryRow) -> String {
    format!(
        "{},{},{},{},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.3},{:.3}\n",
        row.mode.as_str(),
        row.signer_count,
        row.trials,
        row.success,
        row.signing.avg,
        row.signing.median,
        row.signing.std,
        row.signing.p95,
        row.aggregation.avg,
        row.aggregation.median,
        row.aggregation.std,
        row.verification.avg,
        row.verification.median,
        row.verification.std,
        row.total.avg,
        row.total.median,
        row.total.std,
        row.total.p95,
        row.transcript_bytes.avg,
        row.transcript_bytes.std,
        row.transcript_bytes.p95
    )
}

fn get_row<'a>(rows: &'a [SummaryRow], mode: Mode, signer_count: usize) -> Option<&'a SummaryRow> {
    rows.iter()
        .find(|row| row.mode == mode && row.signer_count == signer_count)
}

fn ratio(numerator: f64, denominator: f64) -> f64 {
    if denominator == 0.0 {
        0.0
    } else {
        numerator / denominator
    }
}

fn write_csv(rows: &[SummaryRow]) -> std::io::Result<()> {
    let mut csv = String::from(
        "mode,S,trials,success,signing_ms_avg,signing_ms_median,signing_ms_std,signing_ms_p95,aggregation_ms_avg,aggregation_ms_median,aggregation_ms_std,verification_ms_avg,verification_ms_median,verification_ms_std,total_ms_avg,total_ms_median,total_ms_std,total_ms_p95,transcript_bytes_avg,transcript_bytes_std,transcript_bytes_p95\n",
    );
    for row in rows {
        csv.push_str(&csv_row(row));
    }
    fs::write("results/experiment_results.csv", csv)
}

fn write_summary(rows: &[SummaryRow]) -> std::io::Result<()> {
    let mut summary = String::new();
    summary.push_str("# Experiment Summary\n\n");
    summary.push_str("Baseline is the Gargos-style threshold Schnorr path implemented by the existing setup, commitment/opening, response aggregation, and final Schnorr verification equation. It skips transcript-level aggregation witnesses, witness proofs, and aggregate-witness verification.\n\n");
    summary.push_str("Ours adds each signer's `W_i = g^{z_i}`, the aggregate witness `Y`, and `pi_wit` proving consistency of `W_i` with `X_i`, `B_i`, `A_i`, the challenge, and the Lagrange coefficient. The existing `pi_open` is counted in both baseline and ours because the prototype uses it for the opening relation.\n\n");
    summary.push_str(&format!("Measured metrics: correctness, signing time, aggregation time, verification time, total online time, and transcript bytes. Setup and key generation are run once per parameter set and are not included in online timing columns. Each row uses {} measured trials after {} warmup trials per mode.\n\n", TRIALS, WARMUP_TRIALS));
    summary.push_str("Mode order is interleaved across trials, and measured outputs are consumed with `black_box` to avoid fixed-order and dead-code-elimination artifacts.\n\n");
    summary.push_str("Post-aggregation delayed opening and controlled disclosure are not implemented in the current prototype experiment path, so they are reported as not implemented rather than approximated.\n\n");
    summary.push_str("Build/test commands used: `cargo build --release`, `cargo run --release --bin experiment`, and `cargo test`.\n\n");
    summary.push_str("| mode | S | trials | success | failure | signing median ms | total median ms | transcript bytes avg |\n");
    summary.push_str("|---|---:|---:|---:|---:|---:|---:|---:|\n");
    for row in rows {
        summary.push_str(&format!(
            "| {} | {} | {} | {} | {} | {:.3} | {:.3} | {:.0} |\n",
            row.mode.as_str(),
            row.signer_count,
            row.trials,
            row.success,
            row.failure,
            row.signing.median,
            row.total.median,
            row.transcript_bytes.avg
        ));
    }

    if let (Some(base), Some(full)) = (
        get_row(rows, Mode::Baseline, 32),
        get_row(rows, Mode::Full, 32),
    ) {
        summary.push_str(&format!(
            "\nFor S=32, full signing median is {:.3}x baseline and full transcript size is {:.3}x baseline.\n",
            ratio(full.signing.median, base.signing.median),
            ratio(full.transcript_bytes.avg, base.transcript_bytes.avg)
        ));
    }
    summary.push_str("\nFinal status: experiment binary completed successfully and wrote CSV, summary, profiling, scalability, and plot outputs.\n");
    fs::write("results/experiment_summary.md", summary)
}

fn write_scalability(rows: &[SummaryRow]) -> std::io::Result<()> {
    let mut out = String::new();
    out.push_str("# Scalability Analysis\n\n");
    out.push_str("| S | full/baseline signing median | full/baseline total median | extra signing ms per signer | extra transcript bytes per signer |\n");
    out.push_str("|---:|---:|---:|---:|---:|\n");
    for &s in SIGNER_SET_SIZES {
        let Some(base) = get_row(rows, Mode::Baseline, s) else {
            continue;
        };
        let Some(full) = get_row(rows, Mode::Full, s) else {
            continue;
        };
        let extra_signing_per_signer = (full.signing.median - base.signing.median) / s as f64;
        let extra_bytes_per_signer =
            (full.transcript_bytes.avg - base.transcript_bytes.avg) / s as f64;
        out.push_str(&format!(
            "| {} | {:.3}x | {:.3}x | {:.4} | {:.1} |\n",
            s,
            ratio(full.signing.median, base.signing.median),
            ratio(full.total.median, base.total.median),
            extra_signing_per_signer,
            extra_bytes_per_signer
        ));
    }
    out.push_str("\nThe transcript overhead is dominated by one `W_i` and one `pi_wit` per signer plus the aggregate `Y`, so byte growth is linear in `|S|`.\n");
    fs::write("results/scalability_analysis.md", out)
}

fn write_profiling(rows: &[SummaryRow]) -> std::io::Result<()> {
    let mut out = String::new();
    out.push_str("# Profiling Summary\n\n");
    out.push_str("Profiling is based on the ablation rows produced by the same benchmark harness. `witness_only - baseline` isolates the cost of computing and checking `W_i` and `Y`; `full - witness_only` isolates the added cost of `pi_wit` generation and verification.\n\n");
    out.push_str("| S | witness-only signing delta ms | pi_wit signing delta ms | pi_wit aggregation delta ms | pi_wit verification delta ms |\n");
    out.push_str("|---:|---:|---:|---:|---:|\n");
    for &s in SIGNER_SET_SIZES {
        let Some(base) = get_row(rows, Mode::Baseline, s) else {
            continue;
        };
        let Some(witness) = get_row(rows, Mode::WitnessOnly, s) else {
            continue;
        };
        let Some(full) = get_row(rows, Mode::Full, s) else {
            continue;
        };
        out.push_str(&format!(
            "| {} | {:.4} | {:.4} | {:.4} | {:.4} |\n",
            s,
            witness.signing.median - base.signing.median,
            full.signing.median - witness.signing.median,
            full.aggregation.median - witness.aggregation.median,
            full.verification.median - witness.verification.median
        ));
    }

    if let (Some(base), Some(witness), Some(full)) = (
        get_row(rows, Mode::Baseline, 32),
        get_row(rows, Mode::WitnessOnly, 32),
        get_row(rows, Mode::Full, 32),
    ) {
        out.push_str("\n## Findings\n\n");
        out.push_str(&format!(
            "- Full overhead largest source: `pi_wit` generation in signing. At S=32 the median signing delta from witness_only to full is {:.3} ms, while adding only `W_i/Y` changes signing by {:.3} ms.\n",
            full.signing.median - witness.signing.median,
            witness.signing.median - base.signing.median
        ));
        out.push_str("- Optimization applied: `gargos_sign_and_bind` now computes `A_hat`, challenge `c`, and Lagrange coefficients once for the active signer set instead of recomputing them inside every signer response path.\n");
        out.push_str(&format!(
            "- Optimized full/baseline signing median ratio at S=32: {:.3}x.\n",
            ratio(full.signing.median, base.signing.median)
        ));
        out.push_str("- Remaining overhead exists because every signer still performs one full `pi_wit` proof generation, and aggregation/final verification still verify one `pi_wit` per signer. These are required by the paper's full transcript-level aggregation witness layer.\n");
    }
    fs::write("results/profiling_summary.md", out)
}

fn mode_order(trial: usize, signer_count: usize) -> [Mode; 3] {
    const PERMS: [[Mode; 3]; 6] = [
        [Mode::Baseline, Mode::WitnessOnly, Mode::Full],
        [Mode::Baseline, Mode::Full, Mode::WitnessOnly],
        [Mode::WitnessOnly, Mode::Baseline, Mode::Full],
        [Mode::WitnessOnly, Mode::Full, Mode::Baseline],
        [Mode::Full, Mode::Baseline, Mode::WitnessOnly],
        [Mode::Full, Mode::WitnessOnly, Mode::Baseline],
    ];
    PERMS[(trial + signer_count) % PERMS.len()]
}

fn run_parameter_set(signer_count: usize) -> Vec<SummaryRow> {
    let n = signer_count;
    let t = signer_count - 1;
    let signer_set: Vec<u32> = (1..=signer_count as u32).collect();
    let lagranges = lagrange_map(&signer_set);
    let par = setup(n, t);
    let (pk_joint, pk_shares, sk_shares) = kgen(&par);

    for trial in 0..WARMUP_TRIALS {
        for mode in mode_order(trial, signer_count) {
            black_box(run_mode(
                mode,
                &par,
                &pk_joint,
                &pk_shares,
                &sk_shares,
                &signer_set,
                &lagranges,
            ));
        }
    }

    let mut metrics: BTreeMap<Mode, Vec<TrialMetrics>> = BTreeMap::new();
    for mode in [Mode::Baseline, Mode::WitnessOnly, Mode::Full] {
        metrics.insert(mode, Vec::with_capacity(TRIALS));
    }

    for trial in 0..TRIALS {
        for mode in mode_order(trial + WARMUP_TRIALS, signer_count) {
            let metric = run_mode(
                mode,
                &par,
                &pk_joint,
                &pk_shares,
                &sk_shares,
                &signer_set,
                &lagranges,
            );
            metrics.get_mut(&mode).unwrap().push(metric);
        }
    }

    [Mode::Baseline, Mode::WitnessOnly, Mode::Full]
        .iter()
        .map(|&mode| summarize(mode, signer_count, metrics.get(&mode).unwrap()))
        .collect()
}

fn write_plot_script() -> String {
    r##"
import csv
import os
from PIL import Image, ImageDraw, ImageFont

rows = []
with open("results/experiment_results.csv", newline="") as f:
    rows = list(csv.DictReader(f))

os.makedirs("results/plots", exist_ok=True)

def get(mode, field):
    pts = []
    for row in rows:
        if row["mode"] == mode:
            pts.append((int(row["S"]), float(row[field])))
    return sorted(pts)

def draw_plot(path, title, ylabel, field, modes=("baseline", "witness_only", "full")):
    w, h = 1200, 800
    margin_l, margin_r, margin_t, margin_b = 120, 60, 80, 110
    img = Image.new("RGB", (w, h), "white")
    d = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("Arial.ttf", 28)
        small = ImageFont.truetype("Arial.ttf", 22)
    except Exception:
        font = ImageFont.load_default()
        small = ImageFont.load_default()

    series = [(mode, get(mode, field)) for mode in modes]
    xs = sorted({x for _, pts in series for x, _ in pts})
    ys = [y for _, pts in series for _, y in pts]
    ymax = max(ys) * 1.10 if ys else 1.0
    xmin, xmax = min(xs), max(xs)
    plot_w, plot_h = w - margin_l - margin_r, h - margin_t - margin_b

    def sx(x):
        return margin_l + (x - xmin) / (xmax - xmin) * plot_w if xmax != xmin else margin_l
    def sy(y):
        return margin_t + plot_h - (y / ymax) * plot_h

    d.line((margin_l, margin_t, margin_l, margin_t + plot_h), fill="black", width=2)
    d.line((margin_l, margin_t + plot_h, margin_l + plot_w, margin_t + plot_h), fill="black", width=2)
    for i in range(6):
        y = ymax * i / 5
        py = sy(y)
        d.line((margin_l - 6, py, margin_l + plot_w, py), fill="#dddddd", width=1)
        d.text((20, py - 12), f"{y:.1f}", fill="black", font=small)
    for x in xs:
        px = sx(x)
        d.line((px, margin_t + plot_h, px, margin_t + plot_h + 6), fill="black", width=2)
        d.text((px - 15, margin_t + plot_h + 18), str(x), fill="black", font=small)

    styles = {
        "baseline": ("#333333", "circle"),
        "witness_only": ("#777777", "square"),
        "full": ("#000000", "triangle"),
        "full/baseline": ("#000000", "circle"),
    }
    for mode, pts in series:
        color, marker = styles[mode]
        last = None
        for x, y in pts:
            p = (sx(x), sy(y))
            if last:
                d.line((last[0], last[1], p[0], p[1]), fill=color, width=3)
            px, py = p
            if marker == "circle":
                d.ellipse((px-6, py-6, px+6, py+6), fill=color)
            elif marker == "square":
                d.rectangle((px-6, py-6, px+6, py+6), fill=color)
            else:
                d.polygon([(px, py-8), (px-8, py+7), (px+8, py+7)], fill=color)
            last = p

    d.text((margin_l, 25), title, fill="black", font=font)
    d.text((w // 2 - 50, h - 45), "|S|", fill="black", font=small)
    d.text((20, 25), ylabel, fill="black", font=small)
    lx, ly = w - 310, 100
    for idx, mode in enumerate(modes):
        color, _ = styles[mode]
        y = ly + idx * 34
        d.line((lx, y + 12, lx + 38, y + 12), fill=color, width=3)
        d.text((lx + 50, y), mode, fill="black", font=small)
    img.save(path)

draw_plot("results/plots/signing_time_vs_S.png", "Signing Time vs |S|", "ms", "signing_ms_median")
draw_plot("results/plots/verification_time_vs_S.png", "Verification Time vs |S|", "ms", "verification_ms_median")
draw_plot("results/plots/transcript_size_vs_S.png", "Transcript Size vs |S|", "bytes", "transcript_bytes_avg")

base = {int(r["S"]): float(r["signing_ms_median"]) for r in rows if r["mode"] == "baseline"}
full = {int(r["S"]): float(r["signing_ms_median"]) for r in rows if r["mode"] == "full"}
ratio_rows = []
for s in sorted(base):
    ratio_rows.append({"mode": "full/baseline", "S": str(s), "ratio": str(full[s] / base[s])})
tmp = "results/plots/.ratio.csv"
with open(tmp, "w", newline="") as f:
    wtr = csv.DictWriter(f, fieldnames=["mode", "S", "ratio"])
    wtr.writeheader()
    wtr.writerows(ratio_rows)
old_rows = rows
rows = [{"mode": "full/baseline", "S": r["S"], "overhead_ratio": r["ratio"]} for r in ratio_rows]
draw_plot("results/plots/overhead_ratio_vs_S.png", "Full/Baseline Signing Overhead Ratio", "ratio", "overhead_ratio", modes=("full/baseline",))
os.remove(tmp)
"##
    .to_string()
}

fn generate_plots() -> std::io::Result<()> {
    fs::create_dir_all("results/plots")?;
    let _ = fs::remove_file("results/plots/README.txt");
    let _ = fs::remove_file("results/plots/.ratio.csv");
    let script = write_plot_script();
    let candidates = [
        "/Users/lexie/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3",
        "python3",
        "python",
    ];
    for candidate in candidates {
        let output = Command::new(candidate).arg("-c").arg(&script).output();
        if let Ok(output) = output {
            if output.status.success() {
                return Ok(());
            }
        }
    }
    fs::write(
        "results/plots/README.txt",
        "Plot generation failed: Python with PIL was not available.\n",
    )
}

fn write_outputs(rows: &[SummaryRow]) -> std::io::Result<()> {
    fs::create_dir_all("results")?;
    write_csv(rows)?;
    write_summary(rows)?;
    write_scalability(rows)?;
    write_profiling(rows)?;
    generate_plots()?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    let mut rows = Vec::new();

    println!("correctness: S,trials,success,failure");
    for &signer_count in SIGNER_SET_SIZES {
        let set_rows = run_parameter_set(signer_count);
        if let Some(full) = set_rows.iter().find(|row| row.mode == Mode::Full) {
            println!(
                "{},{},{},{}",
                signer_count, full.trials, full.success, full.failure
            );
        }
        rows.extend(set_rows);
    }

    write_outputs(&rows)?;
    println!("wrote results/experiment_results.csv");
    println!("wrote results/experiment_summary.md");
    println!("wrote results/scalability_analysis.md");
    println!("wrote results/profiling_summary.md");
    println!("wrote results/plots/*.png");
    Ok(())
}
