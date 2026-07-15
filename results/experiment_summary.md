# Experiment Summary

The experiment uses the construction-aligned Rust path: Setup, SignEncap, Combine, Open, Verify, and Trace. Baseline is the unmodified Gargos three-round signing path with standard response aggregation and Schnorr verification. Full construction adds response/randomizer puzzles, Pedersen response commitments, binding-proof checks, canonical registry validation, delayed opening, and message-dependent tracing.

Each row uses 100 measured trials after 10 warmup trials. Setup and key generation are excluded from online timings.

| mode | S | success/trials | signing median ms | combine median ms | open median ms | verify median ms | trace median ms | total median ms | transcript bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline_gargos | 4 | 100/100 | 2.563 | 1.845 | 0.000 | 0.067 | 0.000 | 4.542 | 1564 |
| full_construction | 4 | 100/100 | 4.732 | 0.450 | 0.196 | 0.197 | 0.201 | 5.905 | 3676 |
| baseline_gargos | 8 | 100/100 | 5.052 | 3.631 | 0.000 | 0.068 | 0.000 | 9.380 | 3020 |
| full_construction | 8 | 100/100 | 9.926 | 0.762 | 0.256 | 0.257 | 0.266 | 11.603 | 6812 |
| baseline_gargos | 16 | 100/100 | 10.569 | 8.074 | 0.000 | 0.068 | 0.000 | 18.365 | 5932 |
| full_construction | 16 | 100/100 | 19.346 | 1.410 | 0.376 | 0.375 | 0.394 | 22.082 | 13084 |
| baseline_gargos | 32 | 100/100 | 21.359 | 14.993 | 0.000 | 0.067 | 0.000 | 36.353 | 11756 |
| full_construction | 32 | 100/100 | 38.634 | 2.782 | 0.623 | 0.627 | 0.658 | 43.728 | 25628 |
| baseline_gargos | 64 | 100/100 | 43.557 | 30.165 | 0.000 | 0.068 | 0.000 | 73.671 | 23404 |
| full_construction | 64 | 100/100 | 78.391 | 5.406 | 1.160 | 1.135 | 1.195 | 87.760 | 50716 |

## Overhead ratios

| S | full/baseline total median | extra total ms | extra bytes |
|---:|---:|---:|---:|
| 4 | 1.300x | 1.364 | 2112 |
| 8 | 1.237x | 2.223 | 3792 |
| 16 | 1.202x | 3.717 | 7152 |
| 32 | 1.203x | 7.376 | 13872 |
| 64 | 1.191x | 14.088 | 27312 |

Prototype notes: the HTLP, IBE, and cross-layer binding proof modules implement the interfaces required by the construction for integration testing. They are local prototype primitives rather than production cryptographic backends.
