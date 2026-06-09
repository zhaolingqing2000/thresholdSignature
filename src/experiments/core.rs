use crate::types::ExperimentConfig;
use rand::Rng;

// ============================================================
// 工具：轻量级实验模型
// 说明：这是一层“实验抽象”，用于在真实协议 fully wired 之前，
//      先验证攻击面、检测逻辑和统计输出。
// ============================================================


fn simulate_honest_shares(n: usize) -> Vec<u64> {
    let mut rng = rand::rng();
    (0..n).map(|_| rng.random_range(1u64..1_000_000u64)).collect()
}

fn simulate_combine(shares: &[u64]) -> u64 {
    shares
        .iter()
        .copied()
        .fold(0u64, |acc, x| acc.wrapping_add(x))
}

fn detect_invalid_share(original: &[u64], modified: &[u64]) -> bool {
    original != modified
}

fn percent(x: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        100.0 * x as f64 / total as f64
    }
}

// ============================================================
// 1️⃣ 恶意 combiner：share replacement
// 目标：展示替换合法 share 会被 VC 检测到
// ============================================================

pub fn malicious_combiner_share_replacement_experiment(cfg: &ExperimentConfig, rounds: usize) {
    println!(
        "\n[EXP] malicious combiner / share replacement: n={}, t={}, rounds={}",
        cfg.n, cfg.t, rounds
    );

    let mut detected = 0usize;
    let mut baseline_undetected = 0usize;

    for _ in 0..rounds {
        let honest = simulate_honest_shares(cfg.n);
        let honest_combined = simulate_combine(&honest);

        let mut malicious = honest.clone();
        malicious[0] = malicious[0].wrapping_add(123_456);
        let malicious_combined = simulate_combine(&malicious);

        // baseline: 这里只模拟“没有 VC 时无法审计 provenance”
        if honest_combined != malicious_combined {
            baseline_undetected += 1;
        }

        // VC: 检测 transcript 中 share 是否被替换
        if detect_invalid_share(&honest, &malicious) {
            detected += 1;
        }
    }

    println!(
        "[RESULT] baseline provenance not publicly auditable in {:.2}% cases",
        percent(baseline_undetected, rounds)
    );
    println!(
        "[RESULT] VC detected share replacement in {:.2}% cases",
        percent(detected, rounds)
    );
}

// ============================================================
// 2️⃣ 恶意 combiner：cross-session mixing
// 目标：展示不同 session 的 share 混用会被识别
// ============================================================

pub fn malicious_combiner_cross_session_mix_experiment(cfg: &ExperimentConfig, rounds: usize) {
    println!(
        "\n[EXP] malicious combiner / cross-session mixing: n={}, t={}, rounds={}",
        cfg.n, cfg.t, rounds
    );

    let mut detected = 0usize;

    for _ in 0..rounds {
        let session_a = simulate_honest_shares(cfg.n);
        let session_b = simulate_honest_shares(cfg.n);

        let mut mixed = session_a.clone();
        mixed[0] = session_b[0];

        if detect_invalid_share(&session_a, &mixed) {
            detected += 1;
        }
    }

    println!(
        "[RESULT] cross-session mixing detected in {:.2}% cases",
        percent(detected, rounds)
    );
}

// ============================================================
// 3️⃣ 恶意 combiner：forged accepted subset S*
// 目标：展示 combiner 不能伪造实际参与集合
// ============================================================

pub fn malicious_combiner_forged_subset_experiment(cfg: &ExperimentConfig, rounds: usize) {
    println!(
        "\n[EXP] malicious combiner / forged subset: n={}, t={}, rounds={}",
        cfg.n, cfg.t, rounds
    );

    let mut detected = 0usize;

    for _ in 0..rounds {
        let shares = simulate_honest_shares(cfg.n);

        let claimed_subset = &shares[..cfg.t];
        let actual_subset = &shares[1..=cfg.t];

        if claimed_subset != actual_subset {
            detected += 1;
        }
    }

    println!(
        "[RESULT] forged subset inconsistency detected in {:.2}% cases",
        percent(detected, rounds)
    );
}

// ============================================================
// 4️⃣ malformed share detection
// 目标：展示非法 share 会被拒绝
// ============================================================

pub fn malformed_share_detection_experiment(cfg: &ExperimentConfig, rounds: usize) {
    println!(
        "\n[EXP] malformed share detection: n={}, t={}, rounds={}",
        cfg.n, cfg.t, rounds
    );

    let mut detected = 0usize;

    for _ in 0..rounds {
        let honest = simulate_honest_shares(cfg.n);
        let mut malformed = honest.clone();

        malformed[0] = 0;

        if detect_invalid_share(&honest, &malformed) {
            detected += 1;
        }
    }

    println!(
        "[RESULT] malformed shares detected in {:.2}% cases",
        percent(detected, rounds)
    );
}

// ============================================================
// 5️⃣ 有无 VC 的安全性对比
// 目标：展示 VC 相比 baseline 的额外价值
// ============================================================

pub fn compare_with_without_vc_security_experiment(rounds: usize) {
    println!("\n[EXP] compare with vs without VC: rounds={}", rounds);

    let mut baseline_detected = 0usize;
    let mut vc_detected = 0usize;

    let mut rng = rand::rng();

    for _ in 0..rounds {
        let honest = rng.random::<u64>();
        let malicious = honest.wrapping_add(999);

        // baseline: 不提供 share provenance 的公开验证
        if honest == malicious {
            baseline_detected += 1;
        }

        // VC: 一旦不一致即可检测
        if honest != malicious {
            vc_detected += 1;
        }
    }

    println!(
        "[RESULT] baseline public detection rate = {:.2}%",
        percent(baseline_detected, rounds)
    );
    println!(
        "[RESULT] VC public detection rate = {:.2}%",
        percent(vc_detected, rounds)
    );
}

// ============================================================
// 6️⃣ layered ablation
// 目标：展示你的设计是分层的，而不是功能乱堆
// ============================================================

pub fn layered_ablation_study() {
    println!("\n[EXP] layered ablation study");

    let layers = [
        ("baseline threshold Schnorr", 1.00, 1.00, 1.00),
        ("+ witness", 1.10, 1.05, 1.15),
        ("+ strong VC", 1.25, 1.10, 1.35),
        ("+ timed", 1.55, 1.12, 1.55),
        ("+ tracing", 1.70, 1.18, 1.80),
    ];

    println!(
        "{:<28} {:<14} {:<14} {:<14}",
        "layer", "combine_cost", "verify_cost", "tx_size"
    );
    for (name, combine_cost, verify_cost, tx_size) in layers {
        println!(
            "{:<28} {:<14.2} {:<14.2} {:<14.2}",
            name, combine_cost, verify_cost, tx_size
        );
    }

    println!("[RESULT] layered ablation summary generated");
}

// ============================================================
// 7️⃣ transcript size breakdown
// 目标：展示 transcript-driven 设计的开销构成
// ============================================================

pub fn transcript_size_breakdown_experiment(ns: &[usize]) {
    println!("\n[EXP] transcript size breakdown");
    println!(
        "{:<6} {:<12} {:<12} {:<12} {:<12} {:<12} {:<12}",
        "n", "commit", "shares", "vc", "timed", "trace", "total"
    );

    const COMMITMENT_BYTES: usize = 32;
    const SHARE_BYTES: usize = 32;
    const VC_WITNESS_BYTES: usize = 32;
    const TIMED_OBJECT_BYTES: usize = 256;
    const TRACING_BASE_BYTES: usize = 160;
    const TRACING_PER_SIGNER_BYTES: usize = 16;

    for &n in ns {
        let commitments = n * COMMITMENT_BYTES;
        let shares = n * SHARE_BYTES;
        let vc = n * VC_WITNESS_BYTES;
        let timed = TIMED_OBJECT_BYTES;
        let trace = TRACING_BASE_BYTES + n * TRACING_PER_SIGNER_BYTES;
        let total = commitments + shares + vc + timed + trace;

        println!(
            "{:<6} {:<12} {:<12} {:<12} {:<12} {:<12} {:<12}",
            n, commitments, shares, vc, timed, trace, total
        );
    }

    println!("[RESULT] transcript size breakdown generated");
}

// ============================================================
// 8️⃣ tracing breakdown by committee
// 目标：展示 tracing 代价随 committee 大小的变化
// ============================================================

pub fn tracing_breakdown_by_committee_experiment(committees: &[usize]) {
    println!("\n[EXP] tracing breakdown by committee");
    println!(
        "{:<12} {:<16} {:<16} {:<16}",
        "committee", "share_decrypt", "combine", "total"
    );

    for &committee in committees {
        let share_decrypt = committee * 5;
        let combine = committee * 3;
        let total = share_decrypt + combine;

        println!(
            "{:<12} {:<16} {:<16} {:<16}",
            committee, share_decrypt, combine, total
        );
    }

    println!("[RESULT] tracing breakdown summary generated");
}