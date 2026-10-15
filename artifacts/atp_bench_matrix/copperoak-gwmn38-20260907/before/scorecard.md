# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA, incomplete rows, and mismatched current auth postures are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | bad | encrypted | atp-quic-tls13 | n/a | 3 | 0 | no verified reps | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| 500M | good | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 71.095 | 7.19 | noisy | 57756 | 66908 | 27588 | 35756 | 57756 | 66908 | 0 |

## Noise warnings

Rows with cv_pct > 5.0 are noisy and should not be treated as clean wins without rerun evidence.

| workload | regime | tier | method | ATP streams | cv_pct | ok/reps |
|---|---|---|---|---:|---:|---:|
| 500M | good | encrypted | atp-quic-tls13 | n/a | 7.19 | 3/3 |

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

| workload | regime | tier | method | ATP streams | rep | status | sha ok | timed out | status code |
|---|---|---|---|---:|---:|---|---|---|---:|
| 500M | bad | encrypted | atp-quic-tls13 | n/a | 1 | error | False | False | 2 |
| 500M | bad | encrypted | atp-quic-tls13 | n/a | 2 | error | False | False | 2 |
| 500M | bad | encrypted | atp-quic-tls13 | n/a | 3 | error | False | False | 2 |
