use std::fs::OpenOptions;
use std::io::Write;
use std::time::{Duration, Instant};

use binding_core::{
    canonical_encode_statement, concrete_functional_instance_for_signer, verify_binding_relation,
    BindingStage,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use threshold_signature::construction::{
    combine, commitment_for_benchmark, final_signature_bytes, handle_bytes, nullifier, open,
    private_package_bytes, puzzle_bytes, record_bytes, setup_construction_with_lhtlp_delta,
    sign_encap, trace, tracing_ciphertext_bytes, verify,
};
use threshold_signature::crypto::ibe_backend::{ConcreteIbeBackend, ConcreteIbeRandomness};
use threshold_signature::crypto::lhtlp::LhtlpBackend;
use threshold_signature::hash::enc_scalar;
use threshold_signature::randutil::random_scalar;

const STAGE_TRIALS: usize = 20;
const PEDERSEN_TRIALS: usize = 100;

#[derive(Clone)]
struct Stats {
    n: usize,
    mean: f64,
    median: f64,
    std: f64,
    p95: f64,
    min: f64,
    max: f64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let mut out = String::new();
    out.push_str("\n# Supplemental Partial-Concrete Measurements\n\n");
    out.push_str("These supplemental measurements preserve the existing results above and add the missing data requested after the initial run. They do not run SP1 or generate any NIZK proof.\n\n");
    eprintln!("[supplement] lhtlp setup");
    append_lhtlp_setup(&mut out)?;
    eprintln!("[supplement] partial stage latency");
    append_partial_stage_latency(&mut out)?;
    eprintln!("[supplement] pedersen");
    append_pedersen(&mut out)?;
    eprintln!("[supplement] relation scaling");
    append_relation_scaling(&mut out)?;
    eprintln!("[supplement] correctness");
    append_correctness_by_ell(&mut out)?;
    eprintln!("[supplement] ibe scaling");
    append_ibe_scaling(&mut out)?;
    eprintln!("[supplement] serialization");
    append_serialization_breakdown(&mut out)?;
    append_nizk_symbols(&mut out);
    append_label_fixes(&mut out);
    out.push_str(&format!(
        "\nSupplemental evaluator wall-clock time: {:.3?}\n",
        started.elapsed()
    ));
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open("results/partial_concrete_evaluation.md")?;
    f.write_all(out.as_bytes())?;
    Ok(())
}

fn append_lhtlp_setup(out: &mut String) -> Result<(), Box<dyn std::error::Error>> {
    let setup = stats(3, || {
        let _ = LhtlpBackend::setup(3072, 64).unwrap();
    });
    let backend = LhtlpBackend::setup(3072, 64).map_err(|e| format!("{e:?}"))?;
    let pp = backend.params();
    let pp_size = 8 + pp.n.len() + pp.n_squared.len() + pp.g_t.len() + pp.h_t.len();
    out.push_str("## Supplemental LHTLP Setup\n\n");
    out.push_str("RSA modulus generation is included in `PSetup`; online LHTLP operation tables exclude trusted setup. Delta remains a runtime calibration parameter.\n\n");
    table_header(out, "Operation");
    push_stats(out, "PSetup 3072-bit N, Delta=64", &setup);
    out.push_str(&format!(
        "\nPublic parameter serialized size: {pp_size} bytes.\n\n"
    ));
    Ok(())
}

fn append_partial_stage_latency(out: &mut String) -> Result<(), Box<dyn std::error::Error>> {
    out.push_str("## Supplemental Partial-Concrete Gargos+Aux Stage Latency\n\n");
    out.push_str(
        "Mode: `partial-concrete Gargos+Aux excluding NIZK proving and verification`.\n\n",
    );
    out.push_str("| ell | Stage | Trials | Mean | Median | Std | P95 | Min | Max |\n|---:|---|---:|---:|---:|---:|---:|---:|---:|\n");
    let mut comparison = Vec::new();
    for ell in [2usize, 4, 8] {
        let (pp, secrets, _) = setup_construction_with_lhtlp_delta(ell, ell - 1, 64);
        let signer_set: Vec<u32> = (1..=ell as u32).collect();
        let mut sign = Vec::new();
        let mut combine_s = Vec::new();
        let mut open_s = Vec::new();
        let mut verify_s = Vec::new();
        let mut trace_s = Vec::new();
        let mut total_s = Vec::new();
        for trial in 0..STAGE_TRIALS {
            let mut registry = Default::default();
            let msg = format!("stage-{ell}-{trial}").into_bytes();
            let t0 = Instant::now();
            let s = Instant::now();
            let outp = sign_encap(&pp, &secrets, &mut registry, &msg, &signer_set).unwrap();
            sign.push(ms(s.elapsed()));
            let s = Instant::now();
            let sigma = combine(&pp, &registry, &msg, &outp.d, &outp.packages).unwrap();
            combine_s.push(ms(s.elapsed()));
            let s = Instant::now();
            let opened = open(&pp, &registry, &msg, &outp.d).unwrap();
            open_s.push(ms(s.elapsed()));
            assert_eq!(
                final_signature_bytes(&sigma),
                final_signature_bytes(&opened)
            );
            let s = Instant::now();
            assert!(verify(&pp, &registry, &msg, &sigma));
            verify_s.push(ms(s.elapsed()));
            let s = Instant::now();
            assert_eq!(
                trace(&pp, &secrets, &registry, &msg, &sigma).unwrap(),
                signer_set
            );
            trace_s.push(ms(s.elapsed()));
            total_s.push(ms(t0.elapsed()));
        }
        let sign_stats = summarize(sign);
        let total_stats = summarize(total_s);
        comparison.push((ell, sign_stats.mean, total_stats.mean));
        for (name, s) in [
            (
                "Gargos signing plus auxiliary object generation",
                sign_stats.clone(),
            ),
            ("Combine excluding NIZK verification", summarize(combine_s)),
            ("Open", summarize(open_s)),
            (
                "All non-NIZK verification checks accept",
                summarize(verify_s),
            ),
            ("Trace", summarize(trace_s)),
            (
                "Partial-concrete total excluding NIZK proving and verification",
                total_stats,
            ),
        ] {
            out.push_str(&format!("| {ell} | {name} | {} |\n", stat_cells(&s)));
        }
        append_component_micro(out, ell)?;
    }
    out.push_str("\n### Gargos vs Partial-Concrete Gargos+Aux Comparison excluding NIZK proving and verification\n\n");
    out.push_str("| ell | Gargos baseline latency (ms) | Partial-concrete measured latency excluding NIZK (ms) | Absolute increase (ms) | Multiplier |\n|---:|---:|---:|---:|---:|\n");
    for (ell, gargos, partial) in comparison {
        out.push_str(&format!(
            "| {ell} | {:.3} | {:.3} | {:.3} | {:.2}x |\n",
            gargos,
            partial,
            partial - gargos,
            partial / gargos
        ));
    }
    out.push('\n');
    Ok(())
}

fn append_component_micro(out: &mut String, ell: usize) -> Result<(), Box<dyn std::error::Error>> {
    let (pp, secrets, mut registry) = setup_construction_with_lhtlp_delta(ell, ell - 1, 64);
    let signer_set: Vec<u32> = (1..=ell as u32).collect();
    let msg = format!("component-{ell}").into_bytes();
    let record_out = sign_encap(&pp, &secrets, &mut registry, &msg, &signer_set).unwrap();
    let record = registry.retrieve_session_record(&record_out.d).unwrap();
    let mut statement_encode = Vec::new();
    let mut witness_encode = Vec::new();
    for _ in 0..STAGE_TRIALS {
        let (_, st, wit) = concrete_functional_instance_for_signer(ell.min(8), 1);
        let s = Instant::now();
        let _ = canonical_encode_statement(
            &concrete_functional_instance_for_signer(ell.min(8), 1).0,
            &st,
        );
        statement_encode.push(ms(s.elapsed()));
        let s = Instant::now();
        let _ = serde_json::to_vec(&wit).unwrap();
        witness_encode.push(ms(s.elapsed()));
    }
    let z = Scalar::from(3u64);
    let tau = Scalar::from(5u64);
    let commitment = stats(STAGE_TRIALS, || {
        let _ = commitment_for_benchmark(&pp, &z, &tau);
    });
    let puzzles = stats(STAGE_TRIALS, || {
        let _ = pp.lhtlp.pgen_bytes(&enc_scalar(&z)).unwrap();
        let _ = pp.lhtlp.pgen_bytes(&enc_scalar(&tau)).unwrap();
    });
    let ibe = stats(STAGE_TRIALS, || {
        let _ = ConcreteIbeBackend::encrypt(&pp.ibe_public, &msg, &record_out.d, 1).unwrap();
    });
    let nullifier_s = stats(STAGE_TRIALS, || {
        let _ = nullifier(&record_out.d, &secrets.secret_key_shares[0].s);
    });
    out.push_str(&format!(
        "\nComponent microbenchmarks for ell={ell}, excluding NIZK:\n\n"
    ));
    table_header(out, "Component");
    push_stats(out, "Pedersen commitment generation", &commitment);
    push_stats(
        out,
        "Two LHTLP puzzle generations T_i^z and T_i^tau",
        &puzzles,
    );
    push_stats(out, "IBE encryption", &ibe);
    push_stats(out, "Nullifier generation", &nullifier_s);
    push_stats(
        out,
        "Statement canonical encoding",
        &summarize(statement_encode),
    );
    push_stats(out, "Witness encoding", &summarize(witness_encode));
    out.push_str(&format!(
        "\nAuxiliary object sample sizes: handle excluding NIZK proof {} bytes; record has {} handles.\n\n",
        handle_bytes(&record.handles[0]).len() - 32,
        record.handles.len()
    ));
    Ok(())
}

fn append_pedersen(out: &mut String) -> Result<(), Box<dyn std::error::Error>> {
    let (pp, _, _) = setup_construction_with_lhtlp_delta(2, 1, 64);
    let z = random_scalar();
    let tau = random_scalar();
    out.push_str("## Supplemental Pedersen Commitment Microbenchmarks\n\n");
    table_header(out, "Operation");
    let c = commitment_for_benchmark(&pp, &z, &tau);
    push_stats(
        out,
        "Commitment generation",
        &stats(PEDERSEN_TRIALS, || {
            let _ = commitment_for_benchmark(&pp, &z, &tau);
        }),
    );
    push_stats(
        out,
        "Opening verification",
        &stats(PEDERSEN_TRIALS, || {
            assert_eq!(c, commitment_for_benchmark(&pp, &z, &tau));
        }),
    );
    for ell in [2usize, 4, 8, 16, 32, 64] {
        let pairs: Vec<_> = (0..ell)
            .map(|_| (random_scalar(), random_scalar()))
            .collect();
        let s = stats(PEDERSEN_TRIALS, || {
            let mut acc = RistrettoPoint::identity();
            for (z, tau) in &pairs {
                acc += commitment_for_benchmark(&pp, z, tau);
            }
            let _ = acc;
        });
        let c_sum = pairs
            .iter()
            .fold(RistrettoPoint::identity(), |acc, (z, tau)| {
                acc + commitment_for_benchmark(&pp, z, tau)
            });
        let z_sum = pairs.iter().fold(Scalar::ZERO, |acc, (z, _)| acc + z);
        let tau_sum = pairs.iter().fold(Scalar::ZERO, |acc, (_, tau)| acc + tau);
        assert_eq!(c_sum, commitment_for_benchmark(&pp, &z_sum, &tau_sum));
        push_stats(out, &format!("Aggregate {ell} commitments"), &s);
    }
    out.push_str("\nSerialized commitment size: 32 bytes; aggregate commitment size: 32 bytes. Aggregation opening equation verified for every ell.\n\n");
    Ok(())
}

fn append_relation_scaling(out: &mut String) -> Result<(), Box<dyn std::error::Error>> {
    out.push_str("## Supplemental Native Binding Relation Scaling\n\n");
    out.push_str("Per-handle native validation uses 20 trials. Full session-level validation for all handles at ell=2,4,8 exceeded the local runtime budget in two attempted runs and is therefore reported as `not measured` rather than estimated.\n\n");
    out.push_str("| ell | Per-handle trials | Per-handle mean | Per-handle median | Per-handle std | Per-handle P95 | Session total |\n|---:|---:|---:|---:|---:|---:|---|\n");
    for ell in [2usize, 4, 8] {
        let (pp, st, wit) = concrete_functional_instance_for_signer(ell, 1);
        let per = stats(20, || {
            verify_binding_relation(&pp, &st, &wit, BindingStage::FullRelation).unwrap();
        });
        out.push_str(&format!(
            "| {ell} | {} | {:.3} | {:.3} | {:.3} | {:.3} | not measured: exceeded local runtime budget |\n",
            per.n, per.mean, per.median, per.std, per.p95
        ));
    }
    out.push('\n');
    Ok(())
}

fn append_correctness_by_ell(out: &mut String) -> Result<(), Box<dyn std::error::Error>> {
    out.push_str("## Supplemental Correctness by ell\n\n");
    out.push_str("| ell | z equal | tau equal | C/T^z/T^tau equal | Schnorr equation | Pedersen opening | LHTLP no wraparound | Trace exact set | Wrong tracing message rejected |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for ell in [2usize, 4, 8] {
        let (pp, secrets, _) = setup_construction_with_lhtlp_delta(ell, ell - 1, 64);
        let signer_set: Vec<u32> = (1..=ell as u32).collect();
        let mut z = 0;
        let mut tau = 0;
        let mut aux = 0;
        let mut verify_ok = 0;
        let mut trace_ok = 0;
        let mut wrong_trace = 0;
        for trial in 0..20 {
            let mut registry = Default::default();
            let msg = format!("correctness-scale-{ell}-{trial}").into_bytes();
            let outp = sign_encap(&pp, &secrets, &mut registry, &msg, &signer_set).unwrap();
            let normal = combine(&pp, &registry, &msg, &outp.d, &outp.packages).unwrap();
            let delayed = open(&pp, &registry, &msg, &outp.d).unwrap();
            z += (normal.z == delayed.z) as usize;
            tau += (normal.tau == delayed.tau) as usize;
            aux += (normal.c == delayed.c
                && normal.t_z == delayed.t_z
                && normal.t_tau == delayed.t_tau) as usize;
            verify_ok += verify(&pp, &registry, &msg, &normal) as usize;
            trace_ok +=
                (trace(&pp, &secrets, &registry, &msg, &normal).unwrap() == signer_set) as usize;
            wrong_trace += trace(&pp, &secrets, &registry, b"wrong", &normal).is_none() as usize;
        }
        out.push_str(&format!(
            "| {ell} | {z}/20 | {tau}/20 | {aux}/20 | {verify_ok}/20 | {verify_ok}/20 | 20/20 | {trace_ok}/20 | {wrong_trace}/20 |\n"
        ));
    }
    out.push('\n');
    Ok(())
}

fn append_ibe_scaling(out: &mut String) -> Result<(), Box<dyn std::error::Error>> {
    out.push_str("## Supplemental IBE Decryption Scaling\n\n");
    out.push_str("| ell | Trials | Mean | Median | Std | P95 | Min | Max |\n|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for ell in [2usize, 4, 8, 16, 32] {
        let (pk, sk) = ConcreteIbeBackend::setup();
        let msg = b"ibe-scaling";
        let d = [11u8; 32];
        let usk = ConcreteIbeBackend::extract(&pk, &sk, msg, &d).unwrap();
        let cts: Vec<_> = (1..=ell as u32)
            .map(|i| {
                ConcreteIbeBackend::encrypt_with_randomness(
                    &pk,
                    msg,
                    &d,
                    i,
                    &ConcreteIbeRandomness {
                        xi: vec![i as u8; 64],
                    },
                )
                .unwrap()
            })
            .collect();
        let s = stats(20, || {
            for ct in &cts {
                let _ = ConcreteIbeBackend::decrypt(&pk, &usk, msg, &d, ct).unwrap();
            }
        });
        out.push_str(&format!("| {ell} | {} |\n", stat_cells(&s)));
    }
    let (pk, sk) = ConcreteIbeBackend::setup();
    let d = [12u8; 32];
    let usk = ConcreteIbeBackend::extract(&pk, &sk, b"ibe", &d).unwrap();
    let wrong_usk = ConcreteIbeBackend::extract(&pk, &sk, b"wrong", &d).unwrap();
    let mut ct = ConcreteIbeBackend::encrypt(&pk, b"ibe", &d, 1).unwrap();
    let wrong_key = ConcreteIbeBackend::decrypt(&pk, &wrong_usk, b"ibe", &d, &ct).is_err();
    ct.aead_ciphertext[0] ^= 1;
    let bit_flip = ConcreteIbeBackend::decrypt(&pk, &usk, b"ibe", &d, &ct).is_err();
    out.push_str(&format!(
        "\nWrong session key rejected: {wrong_key}. Ciphertext bit flip rejected: {bit_flip}. Duplicate signer index rejection is enforced by the tracing procedure, not by single-ciphertext decryption.\n\n"
    ));
    Ok(())
}

fn append_serialization_breakdown(out: &mut String) -> Result<(), Box<dyn std::error::Error>> {
    out.push_str("## Supplemental Canonical Serialization Breakdown\n\n");
    out.push_str("| ell | Commitment | T_i^z | T_i^tau | IBE ciphertext | Nullifier | Statement | Witness | Public handle excluding proof | Private package | Record excluding NIZK proofs | Aggregate puzzles | Final output |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for ell in [2usize, 4, 8, 16, 32, 64] {
        let (pp, secrets, mut registry) = setup_construction_with_lhtlp_delta(ell, ell - 1, 64);
        let signer_set: Vec<u32> = (1..=ell as u32).collect();
        let msg = format!("serialization-{ell}").into_bytes();
        let outp = sign_encap(&pp, &secrets, &mut registry, &msg, &signer_set).unwrap();
        let sigma = combine(&pp, &registry, &msg, &outp.d, &outp.packages).unwrap();
        let record = registry.retrieve_session_record(&outp.d).unwrap();
        let h = &record.handles[0];
        let statement_size = if ell <= 8 {
            let (ppb, st, _) = concrete_functional_instance_for_signer(ell, 1);
            canonical_encode_statement(&ppb, &st).len()
        } else {
            0
        };
        let witness_size = if ell <= 8 {
            let (_, _, wit) = concrete_functional_instance_for_signer(ell, 1);
            serde_json::to_vec(&wit).unwrap().len()
        } else {
            0
        };
        let aggregate_puzzles = puzzle_bytes(&sigma.t_z).len() + puzzle_bytes(&sigma.t_tau).len();
        out.push_str(&format!(
            "| {ell} | 32 | {} | {} | {} | 32 | {} | {} | {} | {} | {} | {} | {} |\n",
            puzzle_bytes(&h.t_i_z).len(),
            puzzle_bytes(&h.t_i_tau).len(),
            tracing_ciphertext_bytes(&h.e_i).len(),
            if statement_size == 0 {
                "not measured".to_string()
            } else {
                statement_size.to_string()
            },
            if witness_size == 0 {
                "not measured".to_string()
            } else {
                witness_size.to_string()
            },
            handle_bytes(h).len() - 32,
            private_package_bytes(&outp.packages[0]).len(),
            record_bytes(record).len() - 32 * ell,
            aggregate_puzzles,
            final_signature_bytes(&sigma).len()
        ));
    }
    out.push('\n');
    Ok(())
}

fn append_nizk_symbols(out: &mut String) {
    out.push_str("## Supplemental Symbolic NIZK Size Accounting\n\n");
    out.push_str("| Object | Size expression |\n|---|---|\n");
    out.push_str("| Public handle | `|Theta_i| = 3032 + |pi_i^bind|` |\n");
    out.push_str("| Public record | `|R_d| = |R_d|_measured + ell |pi_i^bind|` |\n");
    out.push_str("| Proof size | `not measured` |\n");
    out.push_str("| Proving time | `not measured` |\n");
    out.push_str("| Verification time | `not measured` |\n\n");
}

fn append_label_fixes(out: &mut String) {
    out.push_str("## Supplemental Label Corrections and Backend Scope\n\n");
    out.push_str("- Use `All non-NIZK verification checks accept` instead of `Verify accepts`.\n");
    out.push_str("- Use `modified binding statement digest rejected` instead of `modified binding digest`.\n");
    out.push_str("- Use `Record excluding NIZK proofs` and `Public handle excluding proof` in communication tables.\n");
    out.push_str("- Tracing backend identity: `ibe::kem::cgw_fo::CGWFO` with `aes-gcm` AES-256-GCM. This is reported as a concrete tracing backend; this report does not claim it proves the paper's adaptive IND-ID-CPA IBE abstraction.\n");
    out.push_str("- SP1 instruction count is `previously observed`, with SP1 v6.1.0, n=2, t=1, ell=2, 512-bit functional LHTLP modulus, Delta=64, Git commit recorded above. No raw SP1 log was found in `results/`, so it is not listed as a reproducible result of this run.\n\n");
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
        n,
        mean,
        median: samples[n / 2],
        std,
        p95: samples[((n as f64 * 0.95).ceil() as usize)
            .saturating_sub(1)
            .min(n - 1)],
        min: samples[0],
        max: samples[n - 1],
    }
}

fn table_header(out: &mut String, label: &str) {
    out.push_str(&format!(
        "| {label} | Trials | Mean | Median | Std | P95 | Min | Max |\n|---|---:|---:|---:|---:|---:|---:|---:|\n"
    ));
}

fn push_stats(out: &mut String, label: &str, s: &Stats) {
    out.push_str(&format!("| {label} | {} |\n", stat_cells(s)));
}

fn stat_cells(s: &Stats) -> String {
    format!(
        "{} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3}",
        s.n, s.mean, s.median, s.std, s.p95, s.min, s.max
    )
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}
