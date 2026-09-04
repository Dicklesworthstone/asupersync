# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA, incomplete rows, and mismatched current auth postures are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | bad | encrypted | atp-quic-tls13 | n/a | 2 | 2 | sha+status ok | 133.671 | 0.74 | stable | 36756 | 46251 | 23946 | 32532 | 36756 | 46251 | 0 |
| 500M | bad | encrypted | rsync-ssh-aes128gcm | n/a | 2 | 2 | sha+status ok | 129.501 | 0.16 | stable | 13466 | 17368 | 17454 | 17368 | 17454 | 17368 | 0 |
| 500M | good | encrypted | atp-quic-tls13 | n/a | 2 | 2 | sha+status ok | 42.354 | 3.87 | stable | 38868 | 43111 | 20112 | 27428 | 38868 | 43111 | 0 |
| 500M | good | encrypted | rsync-ssh-aes128gcm | n/a | 2 | 2 | sha+status ok | 24.963 | 1.11 | stable | 13444 | 17125 | 17260 | 17125 | 17260 | 17125 | 0 |

## Noise warnings

No per-cell wall-time cv_pct exceeded 5.0.

## ATP vs rsync ratios

Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.

| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender peak RSS ratio | sender avg RSS ratio | receiver peak RSS ratio | receiver avg RSS ratio | combined peak RSS ratio | combined avg RSS ratio | ATP feedback rounds |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 500M | bad | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 1.032 | 0.969 | 2.730 | 2.663 | 1.372 | 1.873 | 2.106 | 2.663 | 0 |
| 500M | good | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 1.697 | 0.589 | 2.891 | 2.517 | 1.165 | 1.602 | 2.252 | 2.517 | 0 |

## Per-regime geomean

| regime | geomean wall ratio ATP/rsync |
|---|---:|
| bad | 1.032 |
| good | 1.697 |

## Crypto-symmetry warnings

No crypto-asymmetric ATP/rsync pairs were present.

## Auth-posture exclusions

No rows were excluded for missing or mismatched authentication posture.

## Failed or incomplete rows

No failed SHA or incomplete rows were present.
