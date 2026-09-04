# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA, incomplete rows, and mismatched current auth postures are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 50M | bad | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 14.470 | 5.53 | noisy | 25116 | 34323 | 21752 | 28827 | 25116 | 34323 | 0 |
| 50M | good | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 3.756 | 4.00 | stable | 23488 | 31957 | 18020 | 23741 | 23488 | 31957 | 0 |
| 50M | wan | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 2.453 | 0.14 | stable | 23100 | 27510 | 13000 | 20282 | 23100 | 27510 | 0 |

## Noise warnings

Rows with cv_pct > 5.0 are noisy and should not be treated as clean wins without rerun evidence.

| workload | regime | tier | method | ATP streams | cv_pct | ok/reps |
|---|---|---|---|---:|---:|---:|
| 50M | bad | encrypted | atp-quic-tls13 | n/a | 5.53 | 3/3 |

## ATP vs rsync ratios

Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.

| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender peak RSS ratio | sender avg RSS ratio | receiver peak RSS ratio | receiver avg RSS ratio | combined peak RSS ratio | combined avg RSS ratio | ATP feedback rounds |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|

## Per-regime geomean

| regime | geomean wall ratio ATP/rsync |
|---|---:|

## Crypto-symmetry warnings

No crypto-asymmetric ATP/rsync pairs were present.

## Auth-posture exclusions

No rows were excluded for missing or mismatched authentication posture.

## Failed or incomplete rows

No failed SHA or incomplete rows were present.
