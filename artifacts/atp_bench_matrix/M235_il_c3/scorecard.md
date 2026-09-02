# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA or incomplete rows are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 5.516 | 136.51 | noisy | 31412 | 40895 | 13672 | 21486 | 31412 | 40895 | 0 |
| 50M | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 0.712 | 0.21 | stable | 20660 | 19370 | 10976 | 19200 | 20660 | 19370 | 0 |
| tree_big | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 0.551 | 6.34 | noisy | 16424 | 28676 | 17596 | 16475 | 17596 | 28676 | 0 |

## Noise warnings

Rows with cv_pct > 5.0 are noisy and should not be treated as clean wins without rerun evidence.

| workload | regime | tier | method | ATP streams | cv_pct | ok/reps |
|---|---|---|---|---:|---:|---:|
| 500M | perfect | encrypted | atp-quic-tls13 | n/a | 136.51 | 3/3 |
| tree_big | perfect | encrypted | atp-quic-tls13 | n/a | 6.34 | 3/3 |

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
