# Profiling Summary

Profiling is based on the ablation rows produced by the same benchmark harness. `witness_only - baseline` isolates the cost of computing and checking `W_i` and `Y`; `full - witness_only` isolates the added cost of `pi_wit` generation and verification.

| S | witness-only signing delta ms | pi_wit signing delta ms | pi_wit aggregation delta ms | pi_wit verification delta ms |
|---:|---:|---:|---:|---:|
| 4 | 0.2095 | 2.1679 | 2.8675 | 2.7169 |
| 8 | 0.3836 | 3.9585 | 5.2712 | 5.1351 |
| 16 | 0.5600 | 7.9474 | 10.1513 | 9.9924 |
| 32 | 1.4953 | 17.2655 | 21.4860 | 21.2662 |

## Findings

- Full overhead largest source: `pi_wit` generation in signing. At S=32 the median signing delta from witness_only to full is 17.265 ms, while adding only `W_i/Y` changes signing by 1.495 ms.
- Optimization applied: `gargos_sign_and_bind` now computes `A_hat`, challenge `c`, and Lagrange coefficients once for the active signer set instead of recomputing them inside every signer response path.
- Optimized full/baseline signing median ratio at S=32: 1.771x.
- Remaining overhead exists because every signer still performs one full `pi_wit` proof generation, and aggregation/final verification still verify one `pi_wit` per signer. These are required by the paper's full transcript-level aggregation witness layer.
