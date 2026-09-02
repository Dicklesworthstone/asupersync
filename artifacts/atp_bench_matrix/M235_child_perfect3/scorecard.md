# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA or incomplete rows are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | perfect | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 5.518 | 0.30 | stable | 31440 | 37983 | 12468 | 21330 | 31440 | 37983 | 0 |
| 50M | perfect | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 0.714 | 4.99 | stable | 20784 | 25602 | 10488 | 18860 | 20784 | 25602 | 0 |
| tree_big | perfect | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 0.551 | 4.97 | stable | 17116 | 23110 | 17064 | 16402 | 17152 | 23110 | 0 |

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
