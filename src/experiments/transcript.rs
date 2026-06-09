pub fn transcript_growth_experiment(ns: &[usize]) {
    println!("\n[EXP] transcript growth experiment");
    println!(
        "{:<6} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10}",
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
            "{:<6} {:<10} {:<10} {:<10} {:<10} {:<10} {:<10}",
            n, commitments, shares, vc, timed, trace, total
        );

        println!(
            "      ratios -> commit: {:>5.1}%, shares: {:>5.1}%, vc: {:>5.1}%, timed: {:>5.1}%, trace: {:>5.1}%",
            100.0 * commitments as f64 / total as f64,
            100.0 * shares as f64 / total as f64,
            100.0 * vc as f64 / total as f64,
            100.0 * timed as f64 / total as f64,
            100.0 * trace as f64 / total as f64,
        );
    }

    println!("[DONE] transcript growth experiment");
}