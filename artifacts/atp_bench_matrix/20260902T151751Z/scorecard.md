# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA, incomplete rows, and mismatched current auth postures are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 50M | bad | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 13.959 | 1.89 | stable | 25768 | 34512 | 23764 | 29827 | 25768 | 34512 | 0 |
| 50M | bad | encrypted | rsync-ssh-aes128gcm | n/a | 3 | 3 | sha+status ok | 17.346 | 2.32 | stable | 13828 | 16776 | 17244 | 16776 | 17244 | 16776 | 0 |
| 50M | good | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 3.353 | 1.71 | stable | 23128 | 31952 | 19504 | 24935 | 23128 | 31952 | 0 |
| 50M | good | encrypted | rsync-ssh-aes128gcm | n/a | 3 | 3 | sha+status ok | 3.838 | 2.60 | stable | 13700 | 16668 | 17344 | 16668 | 17344 | 16668 | 0 |
| 50M | perfect | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 0.651 | 0.01 | stable | 21304 | 31232 | 15020 | 17610 | 21304 | 31232 | 0 |
| 50M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 3 | 3 | sha+status ok | 0.837 | 18.52 | noisy | 13540 | 15936 | 17244 | 15936 | 17244 | 15936 | 0 |
| tree_small | bad | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 5.956 | 1.40 | stable | 25832 | 34012 | 34460 | 30122 | 34460 | 34012 | 0 |
| tree_small | bad | encrypted | rsync-ssh-aes128gcm | n/a | 5 | 5 | sha+status ok | 7.341 | 13.20 | noisy | 12296 | 16511 | 18120 | 16511 | 18120 | 16511 | 0 |
| tree_small | good | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 3.553 | 1.52 | stable | 24596 | 33186 | 32208 | 29130 | 32208 | 33186 | 0 |
| tree_small | good | encrypted | rsync-ssh-aes128gcm | n/a | 5 | 5 | sha+status ok | 2.037 | 2.76 | stable | 11692 | 15929 | 18244 | 15929 | 18244 | 15929 | 0 |
| tree_small | perfect | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 2.953 | 0.87 | stable | 23540 | 32827 | 31248 | 27578 | 31248 | 32827 | 0 |
| tree_small | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 5 | 5 | sha+status ok | 0.736 | 0.38 | stable | 11024 | 11617 | 13696 | 11617 | 13696 | 11617 | 0 |

## Noise warnings

Rows with cv_pct > 5.0 are noisy and should not be treated as clean wins without rerun evidence.

| workload | regime | tier | method | ATP streams | cv_pct | ok/reps |
|---|---|---|---|---:|---:|---:|
| 50M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 18.52 | 3/3 |
| tree_small | bad | encrypted | rsync-ssh-aes128gcm | n/a | 13.20 | 5/5 |

## ATP vs rsync ratios

Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.

| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender peak RSS ratio | sender avg RSS ratio | receiver peak RSS ratio | receiver avg RSS ratio | combined peak RSS ratio | combined avg RSS ratio | ATP feedback rounds |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 50M | bad | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 0.805 | 1.243 | 1.863 | 2.057 | 1.378 | 1.778 | 1.494 | 2.057 | 0 |
| 50M | good | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 0.874 | 1.145 | 1.688 | 1.917 | 1.125 | 1.496 | 1.333 | 1.917 | 0 |
| 50M | perfect | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 0.778 | 1.285 | 1.573 | 1.960 | 0.871 | 1.105 | 1.235 | 1.960 | 0 |
| tree_small | bad | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 0.811 | 1.233 | 2.101 | 2.060 | 1.902 | 1.824 | 1.902 | 2.060 | 0 |
| tree_small | good | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 1.744 | 0.573 | 2.104 | 2.083 | 1.765 | 1.829 | 1.765 | 2.083 | 0 |
| tree_small | perfect | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 4.013 | 0.249 | 2.135 | 2.826 | 2.282 | 2.374 | 2.282 | 2.826 | 0 |

## Per-regime geomean

| regime | geomean wall ratio ATP/rsync |
|---|---:|
| bad | 0.808 |
| good | 1.234 |
| perfect | 1.767 |

## Crypto-symmetry warnings

No crypto-asymmetric ATP/rsync pairs were present.

## Auth-posture exclusions

No rows were excluded for missing or mismatched authentication posture.

## Failed or incomplete rows

No failed SHA or incomplete rows were present.
