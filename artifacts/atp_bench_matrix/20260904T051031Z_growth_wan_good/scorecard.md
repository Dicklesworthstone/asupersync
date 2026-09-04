# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA, incomplete rows, and mismatched current auth postures are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | good | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 55.512 | 12.42 | noisy | 50600 | 56154 | 23296 | 29519 | 50600 | 56154 | 0 |
| 500M | good | encrypted | rsync-ssh-aes128gcm | n/a | 3 | 3 | sha+status ok | 24.870 | 0.48 | stable | 13732 | 17342 | 17480 | 17342 | 17480 | 17342 | 0 |
| 500M | wan | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 15.965 | 1.10 | stable | 34988 | 43246 | 15232 | 24064 | 34988 | 43246 | 0 |
| 500M | wan | encrypted | rsync-ssh-aes128gcm | n/a | 3 | 3 | sha+status ok | 27.372 | 1.10 | stable | 13720 | 17224 | 17500 | 17190 | 17500 | 17224 | 0 |

## Noise warnings

Rows with cv_pct > 5.0 are noisy and should not be treated as clean wins without rerun evidence.

| workload | regime | tier | method | ATP streams | cv_pct | ok/reps |
|---|---|---|---|---:|---:|---:|
| 500M | good | encrypted | atp-quic-tls13 | n/a | 12.42 | 3/3 |

## ATP vs rsync ratios

Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.

| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender peak RSS ratio | sender avg RSS ratio | receiver peak RSS ratio | receiver avg RSS ratio | combined peak RSS ratio | combined avg RSS ratio | ATP feedback rounds |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 500M | good | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 2.232 | 0.448 | 3.685 | 3.238 | 1.333 | 1.702 | 2.895 | 3.238 | 0 |
| 500M | wan | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 0.583 | 1.715 | 2.550 | 2.511 | 0.870 | 1.400 | 1.999 | 2.511 | 0 |

## Per-regime geomean

| regime | geomean wall ratio ATP/rsync |
|---|---:|
| good | 2.232 |
| wan | 0.583 |

## Crypto-symmetry warnings

No crypto-asymmetric ATP/rsync pairs were present.

## Auth-posture exclusions

No rows were excluded for missing or mismatched authentication posture.

## Failed or incomplete rows

No failed SHA or incomplete rows were present.
