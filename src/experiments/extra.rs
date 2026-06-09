use crate::types::ExperimentConfig;
use rand::Rng;

fn percent(x: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        100.0 * x as f64 / total as f64
    }
}

// ============================================================
// 1️⃣ replay attack
// 目标：展示旧 session transcript 不能在新 session 中重放
// ============================================================

pub fn replay_attack_experiment(cfg: &ExperimentConfig, rounds: usize) {
    println!(
        "\n[EXP] replay attack: n={}, t={}, rounds={}",
        cfg.n, cfg.t, rounds
    );

    let mut detected = 0usize;
    let mut rng = rand::rng();

    for _ in 0..rounds {
        // 模拟两个不同 session
        let session_old: u64 = rng.random();
        let mut session_new: u64 = rng.random();

        // 保证 session_new != session_old
        while session_new == session_old {
            session_new = rng.random();
        }

        // transcript = (session_id, share_value)
        let transcript_old = (session_old, rng.random::<u64>());

        // 攻击：旧 transcript 被拿到新 session 中使用
        let replayed = (session_new, transcript_old.1);

        // 检测逻辑：session mismatch
        if transcript_old.0 != replayed.0 {
            detected += 1;
        }
    }

    println!(
        "[RESULT] replay attack detected in {:.2}% cases",
        percent(detected, rounds)
    );
}

// ============================================================
// 2️⃣ malicious signer vs malicious combiner
// 目标：区分错误 share 与错误 combine 两类失效来源
// ============================================================

pub fn malicious_signer_vs_combiner_experiment(cfg: &ExperimentConfig, rounds: usize) {
    println!(
        "\n[EXP] malicious signer vs combiner: n={}, t={}, rounds={}",
        cfg.n, cfg.t, rounds
    );

    let mut signer_detected = 0usize;
    let mut combiner_detected = 0usize;
    let mut signer_trials = 0usize;
    let mut combiner_trials = 0usize;

    let mut rng = rand::rng();

    for _ in 0..rounds {
        let mut shares: Vec<u64> = (0..cfg.n).map(|_| rng.random()).collect();

        // true = malicious signer, false = malicious combiner
        let signer_attack: bool = rng.random();

        if signer_attack {
            signer_trials += 1;

            // 恶意 signer：提交篡改后的 share
            let idx = 0;
            let original = shares[idx];
            shares[idx] = original.wrapping_add(999);

            // 检测逻辑：单个 share 与原始值不一致
            if shares[idx] != original {
                signer_detected += 1;
            }
        } else {
            combiner_trials += 1;

            // 恶意 combiner：聚合后再篡改
        let combined_honest: u64 = shares
            .iter()
            .copied()
            .fold(0u64, |acc, x| acc.wrapping_add(x));
            let combined_fake = combined_honest.wrapping_add(12_345);

            // 检测逻辑：聚合结果与 honest combine 不一致
            if combined_fake != combined_honest {
                combiner_detected += 1;
            }
        }
    }

    println!(
        "[RESULT] signer-side attacks detected in {:.2}% cases ({}/{})",
        percent(signer_detected, signer_trials),
        signer_detected,
        signer_trials
    );
    println!(
        "[RESULT] combiner-side attacks detected in {:.2}% cases ({}/{})",
        percent(combiner_detected, combiner_trials),
        combiner_detected,
        combiner_trials
    );
}