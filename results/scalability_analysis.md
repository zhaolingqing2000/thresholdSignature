# Scalability Analysis

| S | full/baseline signing median | full/baseline total median | extra signing ms per signer | extra transcript bytes per signer |
|---:|---:|---:|---:|---:|
| 4 | 1.724x | 1.964x | 0.5944 | 296.0 |
| 8 | 1.730x | 2.027x | 0.5428 | 292.0 |
| 16 | 1.716x | 1.994x | 0.5317 | 290.0 |
| 32 | 1.771x | 2.052x | 0.5863 | 289.0 |

The transcript overhead is dominated by one `W_i` and one `pi_wit` per signer plus the aggregate `Y`, so byte growth is linear in `|S|`.
