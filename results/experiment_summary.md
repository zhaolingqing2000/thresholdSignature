# Experiment Summary

Baseline is the Gargos-style threshold Schnorr path implemented by the existing setup, commitment/opening, response aggregation, and final Schnorr verification equation. It skips transcript-level aggregation witnesses, witness proofs, and aggregate-witness verification.

Ours adds each signer's `W_i = g^{z_i}`, the aggregate witness `Y`, and `pi_wit` proving consistency of `W_i` with `X_i`, `B_i`, `A_i`, the challenge, and the Lagrange coefficient. The existing `pi_open` is counted in both baseline and ours because the prototype uses it for the opening relation.

Measured metrics: correctness, signing time, aggregation time, verification time, total online time, and transcript bytes. Setup and key generation are run once per parameter set and are not included in online timing columns. Each row uses 200 measured trials after 20 warmup trials per mode.

Mode order is interleaved across trials, and measured outputs are consumed with `black_box` to avoid fixed-order and dead-code-elimination artifacts.

Post-aggregation delayed opening and controlled disclosure are not implemented in the current prototype experiment path, so they are reported as not implemented rather than approximated.

Build/test commands used: `cargo build --release`, `cargo run --release --bin experiment`, and `cargo test`.

| mode | S | trials | success | failure | signing median ms | total median ms | transcript bytes avg |
|---|---:|---:|---:|---:|---:|---:|---:|
| baseline | 4 | 200 | 200 | 0 | 3.282 | 8.372 | 1564 |
| witness_only | 4 | 200 | 200 | 0 | 3.492 | 8.774 | 1724 |
| full | 4 | 200 | 200 | 0 | 5.660 | 16.445 | 2748 |
| baseline | 8 | 200 | 200 | 0 | 5.950 | 14.924 | 3020 |
| witness_only | 8 | 200 | 200 | 0 | 6.333 | 15.711 | 3308 |
| full | 8 | 200 | 200 | 0 | 10.292 | 30.250 | 5356 |
| baseline | 16 | 200 | 200 | 0 | 11.890 | 29.578 | 5932 |
| witness_only | 16 | 200 | 200 | 0 | 12.449 | 30.917 | 6476 |
| full | 16 | 200 | 200 | 0 | 20.397 | 58.976 | 10572 |
| baseline | 32 | 200 | 200 | 0 | 24.344 | 60.574 | 11756 |
| witness_only | 32 | 200 | 200 | 0 | 25.839 | 63.664 | 12812 |
| full | 32 | 200 | 200 | 0 | 43.105 | 124.320 | 21004 |

For S=32, full signing median is 1.771x baseline and full transcript size is 1.787x baseline.

Final status: experiment binary completed successfully and wrote CSV, summary, profiling, scalability, and plot outputs.
