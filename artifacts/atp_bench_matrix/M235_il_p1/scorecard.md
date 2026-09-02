# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA or incomplete rows are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 6.757 | 1.21 | stable | 31868 | 39498 | 9492 | 19574 | 31868 | 39498 | 0 |
| 50M | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 1.451 | 15.31 | noisy | 17260 | 25794 | 9444 | 19081 | 17260 | 25794 | 0 |
| tree_big | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 1.352 | 31.46 | noisy | 16520 | 21876 | 17148 | 19175 | 17148 | 21876 | 0 |

## Noise warnings

Rows with cv_pct > 5.0 are noisy and should not be treated as clean wins without rerun evidence.

| workload | regime | tier | method | ATP streams | cv_pct | ok/reps |
|---|---|---|---|---:|---:|---:|
| 50M | perfect | encrypted | atp-quic-tls13 | n/a | 15.31 | 3/3 |
| tree_big | perfect | encrypted | atp-quic-tls13 | n/a | 31.46 | 3/3 |

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
