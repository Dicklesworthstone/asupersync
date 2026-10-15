# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA or incomplete rows are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 50M | good | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 0.151 | 0.24 | stable | 7856 | 7300 | 0 | 18072 | 7856 | 18072 | 0 |
| 50M | good | encrypted | rsync-ssh-aes128gcm | n/a | 5 | 5 | sha+status ok | 1.050 | 15.85 | noisy | 6960 | 11893 | 13404 | 11873 | 13404 | 12161 | 0 |

## Noise warnings

Rows with cv_pct > 5.0 are noisy and should not be treated as clean wins without rerun evidence.

| workload | regime | tier | method | ATP streams | cv_pct | ok/reps |
|---|---|---|---|---:|---:|---:|
| 50M | good | encrypted | rsync-ssh-aes128gcm | n/a | 15.85 | 5/5 |

## ATP vs rsync ratios

Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.

| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender peak RSS ratio | sender avg RSS ratio | receiver peak RSS ratio | receiver avg RSS ratio | combined peak RSS ratio | combined avg RSS ratio | ATP feedback rounds |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 50M | good | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 0.144 | 6.963 | 1.129 | 0.614 | 0.000 | 1.522 | 0.586 | 1.486 | 0 |

## Per-regime geomean

| regime | geomean wall ratio ATP/rsync |
|---|---:|
| good | 0.144 |

## Crypto-symmetry warnings

No crypto-asymmetric ATP/rsync pairs were present.

## Failed or incomplete rows

No failed SHA or incomplete rows were present.
