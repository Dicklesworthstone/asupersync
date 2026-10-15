# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA or incomplete rows are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | perfect | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 0.151 | 0.69 | stable | 7860 | 7300 | 0 | 18128 | 7860 | 18128 | 0 |
| 50M | perfect | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 0.151 | 0.30 | stable | 7860 | 7216 | 0 | 18208 | 7860 | 18208 | 0 |
| tree_big | perfect | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 0.151 | 0.39 | stable | 7880 | 7328 | 0 | 18128 | 7880 | 18128 | 0 |

## Noise warnings

No per-cell wall-time cv_pct exceeded 5.0.

## ATP vs rsync ratios

Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.

| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender peak RSS ratio | sender avg RSS ratio | receiver peak RSS ratio | receiver avg RSS ratio | combined peak RSS ratio | combined avg RSS ratio | ATP feedback rounds |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|

## Per-regime geomean

| regime | geomean wall ratio ATP/rsync |
|---|---:|

## Crypto-symmetry warnings

No crypto-asymmetric ATP/rsync pairs were present.

## Failed or incomplete rows

No failed SHA or incomplete rows were present.
