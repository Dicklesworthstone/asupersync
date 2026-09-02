# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA or incomplete rows are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 5.516 | 0.65 | stable | 30904 | 39084 | 12228 | 20890 | 30904 | 39084 | 0 |
| 50M | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 0.714 | 0.09 | stable | 20192 | 18696 | 9956 | 18801 | 20192 | 18823 | 0 |
| tree_big | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 0.612 | 6.02 | noisy | 16924 | 26412 | 17140 | 16706 | 17244 | 26412 | 0 |

## Noise warnings

Rows with cv_pct > 5.0 are noisy and should not be treated as clean wins without rerun evidence.

| workload | regime | tier | method | ATP streams | cv_pct | ok/reps |
|---|---|---|---|---:|---:|---:|
| tree_big | perfect | encrypted | atp-quic-tls13 | n/a | 6.02 | 3/3 |

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
