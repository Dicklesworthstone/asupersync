# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA or incomplete rows are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 7.023 | 2.69 | stable | 31936 | 38227 | 8864 | 19765 | 31936 | 38227 | 0 |
| 50M | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 1.752 | 14.64 | noisy | 20200 | 27308 | 8848 | 19065 | 20200 | 27308 | 0 |
| tree_big | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 1.353 | 16.86 | noisy | 16616 | 21448 | 17076 | 19483 | 17076 | 21448 | 0 |

## Noise warnings

Rows with cv_pct > 5.0 are noisy and should not be treated as clean wins without rerun evidence.

| workload | regime | tier | method | ATP streams | cv_pct | ok/reps |
|---|---|---|---|---:|---:|---:|
| 50M | perfect | encrypted | atp-quic-tls13 | n/a | 14.64 | 3/3 |
| tree_big | perfect | encrypted | atp-quic-tls13 | n/a | 16.86 | 3/3 |

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
