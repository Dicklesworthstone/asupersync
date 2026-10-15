# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA, incomplete rows, and mismatched current auth postures are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | bad | encrypted | atp-quic-tls13 | n/a | 2 | 0 | no verified reps | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| 500M | bad | encrypted | rsync-ssh-aes128gcm | n/a | 2 | 2 | sha+status ok | 128.838 | 0.13 | stable | 13022 | 17004 | 17078 | 17004 | 17078 | 17004 | 0 |
| 500M | good | encrypted | atp-quic-tls13 | n/a | 2 | 2 | sha+status ok | 67.709 | 0.69 | stable | 60574 | 68828 | 26744 | 33046 | 60574 | 68828 | 0 |
| 500M | good | encrypted | rsync-ssh-aes128gcm | n/a | 2 | 2 | sha+status ok | 24.933 | 1.93 | stable | 13360 | 17283 | 17496 | 17283 | 17496 | 17283 | 0 |

## Noise warnings

No per-cell wall-time cv_pct exceeded 5.0.

## ATP vs rsync ratios

Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.

| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender peak RSS ratio | sender avg RSS ratio | receiver peak RSS ratio | receiver avg RSS ratio | combined peak RSS ratio | combined avg RSS ratio | ATP feedback rounds |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 500M | good | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 2.716 | 0.368 | 4.534 | 3.982 | 1.529 | 1.912 | 3.462 | 3.982 | 0 |

## Per-regime geomean

| regime | geomean wall ratio ATP/rsync |
|---|---:|
| good | 2.716 |

## Crypto-symmetry warnings

No crypto-asymmetric ATP/rsync pairs were present.

## Auth-posture exclusions

No rows were excluded for missing or mismatched authentication posture.

## Failed or incomplete rows

| workload | regime | tier | method | ATP streams | rep | status | sha ok | timed out | status code |
|---|---|---|---|---:|---:|---|---|---|---:|
| 500M | bad | encrypted | atp-quic-tls13 | n/a | 1 | error | False | False | 2 |
| 500M | bad | encrypted | atp-quic-tls13 | n/a | 2 | error | False | False | 2 |
