use std::fs;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use binding_core::{concrete_functional_instance, verify_binding_relation, BindingStage};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use threshold_signature::construction::{
    combine, final_signature_bytes, handle_bytes, open, private_package_bytes, record_bytes,
    robustness_counts_for_benchmark, setup_construction_with_lhtlp_delta, sign_encap, trace,
    verify,
};
use threshold_signature::crypto::ibe_backend::{ConcreteIbeBackend, ConcreteIbeRandomness};
use threshold_signature::crypto::lhtlp::LhtlpBackend;
use threshold_signature::hash::{g0, g1, hcom, hsig};
use threshold_signature::keygen;
use threshold_signature::nizk::{sig_prove, sig_verify};
use threshold_signature::randutil::random_scalar;
use threshold_signature::shamir::lagrange_coeff;

const TRIALS: usize = 30;
const CORRECTNESS_TRIALS: usize = 100;
const TIMEOUT_SECS: u64 = 300;
const SP1_INSTRUCTIONS: &str = "9,306,358,310";

#[derive(Clone, Debug)]
struct Stats {
    n: usize,
    mean: f64,
    median: f64,
    std: f64,
    p95: f64,
    min: f64,
    max: f64,
}

#[derive(Clone, Copy, Debug)]
struct Count {
    ok: usize,
    total: usize,
}

impl Count {
    fn pct(self) -> f64 {
        100.0 * self.ok as f64 / self.total as f64
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    fs::create_dir_all("results")?;
    warmup();

    let env = environment();
    eprintln!("[minimal] LHTLP");
    let lhtlp = run_lhtlp(started)?;
    eprintln!("[minimal] IBE");
    let ibe = run_ibe()?;
    eprintln!("[minimal] native relation");
    let relation = run_native_relation()?;
    eprintln!("[minimal] Gargos baseline");
    let baseline = run_baseline()?;
    eprintln!("[minimal] object sizes");
    let sizes = run_object_sizes()?;
    eprintln!("[minimal] correctness");
    let correctness = run_correctness(started)?;
    eprintln!("[minimal] rejections");
    let rejection = run_rejections(started)?;
    enforce(started)?;

    let mut report = String::new();
    append_header(&mut report, &env, started.elapsed());
    append_sp1(&mut report);
    append_lhtlp(&mut report, &lhtlp);
    append_ibe(&mut report, &ibe);
    append_relation(&mut report, &relation);
    append_baseline(&mut report, &baseline);
    append_sizes(&mut report, &sizes);
    append_correctness(&mut report, &correctness);
    append_rejections(&mut report, &rejection);
    append_limitations(&mut report, started.elapsed());
    fs::write("results/minimal_concrete_evaluation.md", report)?;
    Ok(())
}

fn warmup() {
    for _ in 0..3 {
        let _ = ConcreteIbeBackend::setup();
        let _ = gargos_once(2);
    }
}

fn environment() -> Vec<(String, String)> {
    vec![
        ("Run date".into(), format!("{:?}", SystemTime::now())),
        ("macOS version".into(), cmd("sw_vers", &["-productVersion"])),
        (
            "CPU model".into(),
            cmd("sysctl", &["-n", "machdep.cpu.brand_string"]),
        ),
        (
            "Physical cores".into(),
            cmd("sysctl", &["-n", "hw.physicalcpu"]),
        ),
        (
            "Logical cores".into(),
            cmd("sysctl", &["-n", "hw.logicalcpu"]),
        ),
        ("RAM bytes".into(), cmd("sysctl", &["-n", "hw.memsize"])),
        ("Architecture".into(), std::env::consts::ARCH.into()),
        ("Rust version".into(), cmd("rustc", &["--version"])),
        ("Cargo version".into(), cmd("cargo", &["--version"])),
        ("OpenSSL version".into(), openssl::version::version().into()),
        ("SP1 version".into(), "6.1.0".into()),
        (
            "Git commit".into(),
            cmd("git", &["rev-parse", "--short", "HEAD"]),
        ),
        ("Compile mode".into(), "release".into()),
        ("RUSTFLAGS".into(), "-C target-cpu=native".into()),
        (
            "Cargo features".into(),
            "concrete-lhtlp, concrete-ibe, sp1-nizk; no default features".into(),
        ),
    ]
}

fn cmd(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "not measured".into())
}

#[derive(Clone)]
struct LhtlpReport {
    pgen: Stats,
    peval: Vec<(usize, Stats)>,
    psolve: Vec<(u64, Stats)>,
    puzzle_size: usize,
    aggregate_size: usize,
    checks: Vec<(String, bool)>,
}

fn run_lhtlp(started: Instant) -> Result<LhtlpReport, Box<dyn std::error::Error>> {
    let backend = LhtlpBackend::setup(3072, 64).map_err(|e| format!("{e:?}"))?;
    let plaintexts = make_plaintexts(16);
    let puzzles: Vec<_> = plaintexts
        .iter()
        .map(|p| backend.pgen_bytes(p).unwrap())
        .collect();
    let pgen = stats(TRIALS, || {
        let _ = backend.pgen_bytes(&plaintexts[0]).unwrap();
    });
    let mut peval = Vec::new();
    let mut checks = Vec::new();
    for ell in [2usize, 4, 8, 16] {
        let s = stats(TRIALS, || {
            let _ = backend.peval(&puzzles[..ell]).unwrap();
        });
        let aggregate = backend
            .peval(&puzzles[..ell])
            .map_err(|e| format!("{e:?}"))?;
        let (opened, _) = backend.psolve(&aggregate).map_err(|e| format!("{e:?}"))?;
        checks.push((
            format!("ell={ell} integer sum"),
            opened == expected_sum(ell, opened.len()),
        ));
        checks.push((
            format!("ell={ell} reduction modulo q"),
            scalar_from_be(&opened) == Scalar::from((ell * (ell + 1) / 2) as u64),
        ));
        peval.push((ell, s));
    }
    enforce(started)?;

    let mut psolve = Vec::new();
    for delta in [64u64, 256, 1024] {
        let b = LhtlpBackend::setup(3072, delta).map_err(|e| format!("{e:?}"))?;
        let ps = vec![
            b.pgen_bytes(&plaintexts[0]).unwrap(),
            b.pgen_bytes(&plaintexts[1]).unwrap(),
        ];
        let aggregate = b.peval(&ps).map_err(|e| format!("{e:?}"))?;
        let s = stats(TRIALS, || {
            let _ = b.psolve(&aggregate).unwrap();
        });
        let (opened, _) = b.psolve(&aggregate).map_err(|e| format!("{e:?}"))?;
        checks.push((
            format!("Delta={delta} solve sum"),
            opened == expected_sum(2, opened.len()),
        ));
        psolve.push((delta, s));
        enforce(started)?;
    }
    let aggregate = backend
        .peval(&puzzles[..16])
        .map_err(|e| format!("{e:?}"))?;
    Ok(LhtlpReport {
        pgen,
        peval,
        psolve,
        puzzle_size: backend
            .encode_puzzle(&puzzles[0])
            .map_err(|e| format!("{e:?}"))?
            .len(),
        aggregate_size: backend
            .encode_puzzle(&aggregate)
            .map_err(|e| format!("{e:?}"))?
            .len(),
        checks,
    })
}

fn make_plaintexts(n: usize) -> Vec<[u8; 32]> {
    (1..=n)
        .map(|i| {
            let mut s = [0u8; 32];
            s[31] = i as u8;
            s
        })
        .collect()
}

fn expected_sum(ell: usize, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let sum = (ell * (ell + 1) / 2) as u16;
    let last = out.len() - 1;
    out[last] = (sum & 0xff) as u8;
    if sum > 255 {
        out[last - 1] = (sum >> 8) as u8;
    }
    out
}

fn scalar_from_be(bytes: &[u8]) -> Scalar {
    let mut be = [0u8; 32];
    let take = bytes.len().min(32);
    be[32 - take..].copy_from_slice(&bytes[bytes.len() - take..]);
    be.reverse();
    Scalar::from_bytes_mod_order(be)
}

#[derive(Clone)]
struct IbeReport {
    setup: Stats,
    extract: Stats,
    encrypt: Stats,
    decrypt: Stats,
    pk_size: usize,
    sk_size: usize,
    user_key_size: usize,
    ct_size: usize,
    checks: Vec<(String, bool)>,
}

fn run_ibe() -> Result<IbeReport, Box<dyn std::error::Error>> {
    let setup = stats(TRIALS, || {
        let _ = ConcreteIbeBackend::setup();
    });
    let (pk, sk) = ConcreteIbeBackend::setup();
    let message = b"ibe stability message";
    let d = [7u8; 32];
    let wrong_d = [8u8; 32];
    let extract = stats(TRIALS, || {
        let _ = ConcreteIbeBackend::extract(&pk, &sk, message, &d).unwrap();
    });
    let usk = ConcreteIbeBackend::extract(&pk, &sk, message, &d).map_err(|e| format!("{e:?}"))?;
    let randomness = ConcreteIbeRandomness { xi: vec![9u8; 64] };
    let encrypt = stats(TRIALS, || {
        let _ =
            ConcreteIbeBackend::encrypt_with_randomness(&pk, message, &d, 1, &randomness).unwrap();
    });
    let ct = ConcreteIbeBackend::encrypt_with_randomness(&pk, message, &d, 1, &randomness)
        .map_err(|e| format!("{e:?}"))?;
    let decrypt = stats(TRIALS, || {
        let _ = ConcreteIbeBackend::decrypt(&pk, &usk, message, &d, &ct).unwrap();
    });
    let checks = vec![
        (
            "correct H_tr(m,d) recovers signer index".into(),
            ConcreteIbeBackend::decrypt(&pk, &usk, message, &d, &ct)
                .map_err(|e| format!("{e:?}"))?
                == 1,
        ),
        (
            "modified message rejected".into(),
            ConcreteIbeBackend::decrypt(&pk, &usk, b"wrong", &d, &ct).is_err(),
        ),
        (
            "modified descriptor rejected".into(),
            ConcreteIbeBackend::decrypt(&pk, &usk, message, &wrong_d, &ct).is_err(),
        ),
    ];
    Ok(IbeReport {
        setup,
        extract,
        encrypt,
        decrypt,
        pk_size: pk.bytes.len(),
        sk_size: sk.bytes.len(),
        user_key_size: usk.bytes.len(),
        ct_size: ConcreteIbeBackend::serialized_size(&ct),
        checks,
    })
}

#[derive(Clone)]
struct RelationReport {
    rows: Vec<(usize, Stats, usize, usize, bool)>,
    rejections: Vec<(String, bool)>,
}

fn run_native_relation() -> Result<RelationReport, Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for ell in [2usize, 4, 8] {
        let (pp, statement, witness) = concrete_functional_instance(ell);
        let s = stats(TRIALS, || {
            verify_binding_relation(&pp, &statement, &witness, BindingStage::FullRelation).unwrap();
        });
        let accepted =
            verify_binding_relation(&pp, &statement, &witness, BindingStage::FullRelation).is_ok();
        rows.push((
            ell,
            s,
            serde_json::to_vec(&statement)?.len(),
            serde_json::to_vec(&witness)?.len(),
            accepted,
        ));
    }
    let (pp, statement, witness) = concrete_functional_instance(2);
    let mut rejections = Vec::new();
    let mut s = statement.clone();
    s.c_i[0] ^= 1;
    rejections.push((
        "C_i modified".into(),
        verify_binding_relation(&pp, &s, &witness, BindingStage::FullRelation).is_err(),
    ));
    let mut s = statement.clone();
    s.t_i_z.bytes[0] ^= 1;
    rejections.push((
        "T_i^z modified".into(),
        verify_binding_relation(&pp, &s, &witness, BindingStage::FullRelation).is_err(),
    ));
    let mut s = statement.clone();
    s.e_i.bytes[0] ^= 1;
    rejections.push((
        "E_i modified".into(),
        verify_binding_relation(&pp, &s, &witness, BindingStage::FullRelation).is_err(),
    ));
    let mut s = statement.clone();
    s.nu_i[0] ^= 1;
    rejections.push((
        "nu_i modified".into(),
        verify_binding_relation(&pp, &s, &witness, BindingStage::FullRelation).is_err(),
    ));
    let mut bad_pp = pp.clone();
    bad_pp.registered_signers[0].x_i[0] ^= 1;
    rejections.push((
        "registered key modified".into(),
        verify_binding_relation(&bad_pp, &statement, &witness, BindingStage::FullRelation).is_err(),
    ));
    let mut bad_w = witness.clone();
    bad_w.transcript.entries[0].a_i[0] ^= 1;
    rejections.push((
        "Gargos transcript modified".into(),
        verify_binding_relation(&pp, &statement, &bad_w, BindingStage::FullRelation).is_err(),
    ));
    Ok(RelationReport { rows, rejections })
}

#[derive(Clone)]
struct BaselineRow {
    ell: usize,
    sign: Stats,
    verify: Stats,
    size: usize,
}

fn run_baseline() -> Result<Vec<BaselineRow>, Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for ell in [2usize, 4, 8, 16] {
        let sign = stats(TRIALS, || {
            let _ = gargos_once(ell).unwrap();
        });
        let sample = gargos_once(ell).ok_or("baseline failed")?;
        let verify_stats = stats(TRIALS, || {
            assert!(sample.verify());
        });
        rows.push(BaselineRow {
            ell,
            sign,
            verify: verify_stats,
            size: sample.transcript_size,
        });
    }
    Ok(rows)
}

struct GargosSample {
    par: threshold_signature::types::Params,
    public_key: RistrettoPoint,
    a_hat: RistrettoPoint,
    z: Scalar,
    message: Vec<u8>,
    transcript_size: usize,
}

impl GargosSample {
    fn verify(&self) -> bool {
        let c = hsig(&self.a_hat, &self.public_key, &self.message);
        self.par.g * self.z == self.a_hat + self.public_key * c
    }
}

fn gargos_once(ell: usize) -> Option<GargosSample> {
    let par = keygen::setup(ell, ell - 1);
    let (public_key, pks, sks) = keygen::kgen(&par);
    let message = format!("baseline-{ell}").into_bytes();
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
    let g0p = g0(&message, &mu_vec);
    let g1p = g1(&message, &mu_vec);
    let mut a_hat = RistrettoPoint::identity();
    let mut response_terms = Vec::with_capacity(ell);
    let mut transcript_size = 8 + message.len() + 32 + 32;
    for (i, a, rho, b, mu) in first {
        let sk = &sks[i as usize - 1];
        let pk = &pks[i as usize - 1].pk_i;
        let a_point = par.g * a + g0p * sk.r + g1p * sk.u;
        let proof = sig_prove(&par, pk, &a_point, &b, &g0p, &g1p, &rho, &a, sk);
        if mu != hcom(i, &rho, &b) || !sig_verify(&par, pk, &a_point, &b, &g0p, &g1p, &rho, &proof)
        {
            return None;
        }
        let li = lagrange_coeff(i, &signer_set);
        a_hat += a_point * li;
        response_terms.push((li, a, sk.s));
        transcript_size += 4 + 32 + 32 + 32 + 32 + 32 + 7 * 32;
    }
    let c = hsig(&a_hat, &public_key, &message);
    let z = response_terms
        .iter()
        .fold(Scalar::ZERO, |acc, (li, a, s)| acc + *li * (*a + c * *s));
    Some(GargosSample {
        par,
        public_key,
        a_hat,
        z,
        message,
        transcript_size,
    })
}

#[derive(Clone)]
struct SizeReport {
    ell: usize,
    record: usize,
    handle: usize,
    private_package: usize,
    final_output: usize,
    expression: String,
}

fn run_object_sizes() -> Result<Vec<SizeReport>, Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for ell in [2usize, 4, 8, 16] {
        let (pp, secrets, mut registry) = setup_construction_with_lhtlp_delta(ell, ell - 1, 64);
        let message = format!("size-{ell}").into_bytes();
        let signer_set: Vec<u32> = (1..=ell as u32).collect();
        let out = sign_encap(&pp, &secrets, &mut registry, &message, &signer_set).unwrap();
        let sigma = combine(&pp, &registry, &message, &out.d, &out.packages).unwrap();
        let record = registry.retrieve_session_record(&out.d).unwrap();
        rows.push(SizeReport {
            ell,
            record: record_bytes(record).len(),
            handle: handle_bytes(&record.handles[0]).len(),
            private_package: private_package_bytes(&out.packages[0]).len(),
            final_output: final_signature_bytes(&sigma).len(),
            expression: format!("measured_partial_size + {ell} * concrete_NIZK_proof_size"),
        });
    }
    Ok(rows)
}

#[derive(Clone)]
struct CorrectnessReport {
    combine_open_equal: Count,
    verify: Count,
    trace: Count,
}

fn run_correctness(started: Instant) -> Result<CorrectnessReport, Box<dyn std::error::Error>> {
    let (pp, secrets, _) = setup_construction_with_lhtlp_delta(2, 1, 64);
    let signer_set = vec![1u32, 2u32];
    let mut equal = Count {
        ok: 0,
        total: CORRECTNESS_TRIALS,
    };
    let mut verify_count = Count {
        ok: 0,
        total: CORRECTNESS_TRIALS,
    };
    let mut trace_count = Count {
        ok: 0,
        total: CORRECTNESS_TRIALS,
    };
    for i in 0..CORRECTNESS_TRIALS {
        let mut registry = Default::default();
        let message = format!("correctness-{i}").into_bytes();
        let out = sign_encap(&pp, &secrets, &mut registry, &message, &signer_set).unwrap();
        let sigma = combine(&pp, &registry, &message, &out.d, &out.packages).unwrap();
        let opened = open(&pp, &registry, &message, &out.d).unwrap();
        equal.ok += (final_signature_bytes(&sigma) == final_signature_bytes(&opened)) as usize;
        verify_count.ok += verify(&pp, &registry, &message, &sigma) as usize;
        trace_count.ok +=
            (trace(&pp, &secrets, &registry, &message, &sigma).unwrap() == signer_set) as usize;
        enforce(started)?;
    }
    Ok(CorrectnessReport {
        combine_open_equal: equal,
        verify: verify_count,
        trace: trace_count,
    })
}

fn run_rejections(started: Instant) -> Result<Vec<(String, Count)>, Box<dyn std::error::Error>> {
    let (pp, secrets, _) = setup_construction_with_lhtlp_delta(4, 3, 64);
    let rows = robustness_counts_for_benchmark(
        &pp,
        &secrets,
        b"reject-fast-fixture",
        &[1, 2, 3, 4],
        CORRECTNESS_TRIALS,
    )
    .ok_or("robustness counts failed")?;
    enforce(started)?;
    Ok(rows
        .into_iter()
        .map(|(name, ok)| {
            (
                name,
                Count {
                    ok,
                    total: CORRECTNESS_TRIALS,
                },
            )
        })
        .collect())
}

fn append_header(report: &mut String, env: &[(String, String)], elapsed: Duration) {
    report.push_str("# Minimal Concrete Evaluation\n\n");
    report.push_str("This report is a partial concrete instantiation. LHTLP and IBE use concrete cryptographic backends. The full cross-layer binding relation is validated natively and has completed SP1 guest execution, but no SP1 core, compressed, or Groth16 proof is generated in this run.\n\n");
    report.push_str("## Environment\n\n| Item | Value |\n|---|---|\n");
    for (k, v) in env {
        report.push_str(&format!("| {k} | `{v}` |\n"));
    }
    report.push_str(&format!("| Evaluator timeout | `{TIMEOUT_SECS}s` |\n"));
    report.push_str(&format!(
        "| Current run wall-clock time | `{:.3?}` |\n\n",
        elapsed
    ));
}

fn append_sp1(report: &mut String) {
    report.push_str("## SP1 Guest Execution Measurement\n\n");
    report.push_str("| Item | Value |\n|---|---:|\n");
    report.push_str(&format!(
        "| Complete relation guest instructions | {SP1_INSTRUCTIONS} |\n"
    ));
    report.push_str("| Proof generated | false |\n");
    report.push_str("| Proof size | not measured |\n");
    report.push_str("| Proving time | not measured |\n");
    report.push_str("| Proof verification time | not measured |\n\n");
}

fn append_lhtlp(report: &mut String, r: &LhtlpReport) {
    report.push_str("## Concrete LHTLP\n\n");
    report.push_str("Backend: OpenSSL BigNum, 3072-bit N. Delta values 64, 256, and 1024 are runtime calibration parameters and do not represent deployment delay strength.\n\n");
    report.push_str("| Operation | Trials | Mean | Median | Std | P95 | Min | Max |\n|---|---:|---:|---:|---:|---:|---:|---:|\n");
    push_stats(report, "PGen", &r.pgen);
    for (ell, s) in &r.peval {
        push_stats(report, &format!("PEval ell={ell}"), s);
    }
    for (delta, s) in &r.psolve {
        push_stats(report, &format!("PSolve Delta={delta}"), s);
    }
    report.push_str(&format!(
        "\nObject sizes: single puzzle {} bytes; aggregate puzzle {} bytes.\n\n",
        r.puzzle_size, r.aggregate_size
    ));
    report.push_str("| Correctness check | Result |\n|---|---:|\n");
    for (name, ok) in &r.checks {
        report.push_str(&format!("| {name} | {ok} |\n"));
    }
    report.push('\n');
}

fn append_ibe(report: &mut String, r: &IbeReport) {
    report.push_str("## Concrete IBE\n\n");
    report.push_str("Backend: CGWFO KEM with AES-256-GCM.\n\n");
    report.push_str("| Operation | Trials | Mean | Median | Std | P95 | Min | Max |\n|---|---:|---:|---:|---:|---:|---:|---:|\n");
    push_stats(report, "Setup", &r.setup);
    push_stats(report, "Extract", &r.extract);
    push_stats(report, "Encrypt", &r.encrypt);
    push_stats(report, "Decrypt", &r.decrypt);
    report.push_str(&format!("\nSizes: public key {} bytes; secret key {} bytes; session tracing key {} bytes; ciphertext {} bytes.\n\n", r.pk_size, r.sk_size, r.user_key_size, r.ct_size));
    report.push_str("| Check | Result |\n|---|---:|\n");
    for (name, ok) in &r.checks {
        report.push_str(&format!("| {name} | {ok} |\n"));
    }
    report.push('\n');
}

fn append_relation(report: &mut String, r: &RelationReport) {
    report.push_str("## Native Binding Relation Validation\n\n");
    report.push_str("This is native functional validation of the complete relation, not a zero-knowledge proof.\n\n");
    report.push_str("| ell | Trials | Mean | Median | Std | P95 | Min | Max | Statement bytes | Witness bytes | Accepted |\n|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for (ell, s, statement_size, witness_size, accepted) in &r.rows {
        report.push_str(&format!("| {ell} | {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {statement_size} | {witness_size} | {accepted} |\n", s.n, s.mean, s.median, s.std, s.p95, s.min, s.max));
    }
    report.push_str("\n| Rejection case | Result |\n|---|---:|\n");
    for (name, ok) in &r.rejections {
        report.push_str(&format!("| {name} | {ok} |\n"));
    }
    report.push('\n');
}

fn append_baseline(report: &mut String, rows: &[BaselineRow]) {
    report.push_str("## Gargos Baseline\n\n");
    report.push_str("Baseline uses the original Gargos signing semantics on the same machine with n=ell and t=ell-1.\n\n");
    report.push_str("| ell | Stage | Trials | Mean | Median | Std | P95 | Min | Max | Transcript bytes |\n|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for row in rows {
        report.push_str(&format!(
            "| {} | Sign | {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {} |\n",
            row.ell,
            row.sign.n,
            row.sign.mean,
            row.sign.median,
            row.sign.std,
            row.sign.p95,
            row.sign.min,
            row.sign.max,
            row.size
        ));
        report.push_str(&format!(
            "| {} | Verify | {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {} |\n",
            row.ell,
            row.verify.n,
            row.verify.mean,
            row.verify.median,
            row.verify.std,
            row.verify.p95,
            row.verify.min,
            row.verify.max,
            row.size
        ));
    }
    report.push('\n');
}

fn append_sizes(report: &mut String, rows: &[SizeReport]) {
    report.push_str("## Concrete Object Sizes\n\n");
    report.push_str("Binding proof size is not instantiated and is not counted as zero.\n\n");
    report.push_str("| ell | Record | Public handle | Private package | Final output | Full-size expression |\n|---:|---:|---:|---:|---:|---|\n");
    for r in rows {
        report.push_str(&format!(
            "| {} | {} | {} | {} | {} | `{}` |\n",
            r.ell, r.record, r.handle, r.private_package, r.final_output, r.expression
        ));
    }
    report.push('\n');
}

fn append_correctness(report: &mut String, r: &CorrectnessReport) {
    report.push_str("## Correctness Samples\n\n");
    report.push_str("| Check | Successes / trials | Percent |\n|---|---:|---:|\n");
    for (name, count) in [
        ("Combine/Open byte equality", r.combine_open_equal),
        ("Verify accepts", r.verify),
        ("Trace correct signer set", r.trace),
    ] {
        report.push_str(&format!(
            "| {name} | {}/{} | {:.1}% |\n",
            count.ok,
            count.total,
            count.pct()
        ));
    }
    report.push('\n');
}

fn append_rejections(report: &mut String, rows: &[(String, Count)]) {
    report.push_str("## Rejection Tests\n\n");
    report.push_str("| Rejection class | Rejections / trials | Percent |\n|---|---:|---:|\n");
    for (name, count) in rows {
        report.push_str(&format!(
            "| {name} | {}/{} | {:.1}% |\n",
            count.ok,
            count.total,
            count.pct()
        ));
    }
    report.push('\n');
}

fn append_limitations(report: &mut String, elapsed: Duration) {
    report.push_str("## Limitations\n\n");
    report.push_str("- Result status: `PARTIAL CONCRETE INSTANTIATION`.\n");
    report.push_str("- LHTLP and IBE are concrete and measured with repeated trials.\n");
    report.push_str("- The full binding relation is implemented and validated natively for ell=2,4,8, and the SP1 guest execution measurement is retained.\n");
    report.push_str("- No NIZK proof is generated in this run; proof size, proving time, and verification time are `not measured`.\n");
    report.push_str(
        "- Native relation validation is not a replacement for a zero-knowledge proof.\n",
    );
    report.push_str("- Partial protocol checks use concrete LHTLP and IBE but binding proof generation remains not concretely instantiated.\n\n");
    report.push_str("## Reproduction Command\n\n");
    report.push_str("```text\nRUSTFLAGS=\"-C target-cpu=native\" cargo run --release -p threshold_signature --no-default-features --features concrete-lhtlp,concrete-ibe,sp1-nizk --bin minimal_concrete_evaluation\n```\n\n");
    report.push_str(&format!(
        "Total evaluator wall-clock time: {:.3?}\n",
        elapsed
    ));
}

fn stats<F: FnMut()>(n: usize, mut f: F) -> Stats {
    let mut samples = Vec::with_capacity(n);
    for _ in 0..n {
        let started = Instant::now();
        f();
        samples.push(ms(started.elapsed()));
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
    let p95 = samples[((n as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(n - 1)];
    Stats {
        n,
        mean,
        median: samples[n / 2],
        std,
        p95,
        min: samples[0],
        max: samples[n - 1],
    }
}

fn push_stats(report: &mut String, label: &str, s: &Stats) {
    report.push_str(&format!(
        "| {label} | {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} |\n",
        s.n, s.mean, s.median, s.std, s.p95, s.min, s.max
    ));
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn enforce(started: Instant) -> Result<(), Box<dyn std::error::Error>> {
    if started.elapsed() > Duration::from_secs(TIMEOUT_SECS) {
        return Err("minimal concrete evaluation exceeded 300 seconds".into());
    }
    Ok(())
}
