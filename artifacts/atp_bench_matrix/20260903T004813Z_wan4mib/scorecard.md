# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA, incomplete rows, and mismatched current auth postures are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | wan | encrypted | atp-quic-tls13 | n/a | 2 | 2 | sha+status ok | 15.663 | 0.01 | stable | 33884 | 42260 | 15620 | 24142 | 33884 | 42260 | 0 |
| 500M | wan | encrypted | rsync-ssh-aes128gcm | n/a | 2 | 2 | sha+status ok | 27.170 | 0.52 | stable | 13694 | 17042 | 17218 | 17042 | 17218 | 17042 | 0 |
| 500M | wanqueue | encrypted | atp-quic-tls13 | n/a | 2 | 2 | sha+status ok | 43.500 | 15.98 | noisy | 55308 | 61381 | 23066 | 28265 | 55308 | 61381 | 0 |
| 500M | wanqueue | encrypted | rsync-ssh-aes128gcm | n/a | 2 | 2 | sha+status ok | 46.808 | 6.01 | noisy | 8600 | 8588 | 9494 | 8594 | 9522 | 8594 | 0 |

## Noise warnings

Rows with cv_pct > 5.0 are noisy and should not be treated as clean wins without rerun evidence.

| workload | regime | tier | method | ATP streams | cv_pct | ok/reps |
|---|---|---|---|---:|---:|---:|
| 500M | wanqueue | encrypted | atp-quic-tls13 | n/a | 15.98 | 2/2 |
| 500M | wanqueue | encrypted | rsync-ssh-aes128gcm | n/a | 6.01 | 2/2 |

## ATP vs rsync ratios

Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.

| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender peak RSS ratio | sender avg RSS ratio | receiver peak RSS ratio | receiver avg RSS ratio | combined peak RSS ratio | combined avg RSS ratio | ATP feedback rounds |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 500M | wan | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 0.576 | 1.735 | 2.474 | 2.480 | 0.907 | 1.417 | 1.968 | 2.480 | 0 |
| 500M | wanqueue | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 0.929 | 1.076 | 6.431 | 7.147 | 2.430 | 3.289 | 5.808 | 7.143 | 0 |

## Per-regime geomean

| regime | geomean wall ratio ATP/rsync |
|---|---:|
| wan | 0.576 |
| wanqueue | 0.929 |

## Crypto-symmetry warnings

No crypto-asymmetric ATP/rsync pairs were present.

## Auth-posture exclusions

No rows were excluded for missing or mismatched authentication posture.

## Failed or incomplete rows

No failed SHA or incomplete rows were present.
