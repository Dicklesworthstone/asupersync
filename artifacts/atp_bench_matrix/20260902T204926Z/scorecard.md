# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA, incomplete rows, and mismatched current auth postures are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | wan | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 26.173 | 0.78 | stable | 32544 | 40057 | 14072 | 23202 | 32544 | 40057 | 0 |
| 500M | wan | encrypted | rsync-ssh-aes128gcm | n/a | 3 | 3 | sha+status ok | 27.267 | 1.27 | stable | 13556 | 16997 | 17280 | 16978 | 17280 | 17010 | 0 |
| 500M | wan | nocrypto | atp-rq-lab | 1 | 3 | 3 | sha+status ok | 16.061 | 0.02 | stable | 11876 | 21371 | 12016 | 21162 | 12016 | 21371 | 0 |
| 500M | wan | nocrypto | rsyncd | n/a | 3 | 3 | sha+status ok | 20.638 | 0.02 | stable | 7996 | 29788 | 30836 | 29925 | 30836 | 29925 | 0 |
| 50M | wan | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 3.154 | 1.85 | stable | 20452 | 27697 | 13276 | 21572 | 20452 | 27697 | 0 |
| 50M | wan | encrypted | rsync-ssh-aes128gcm | n/a | 3 | 3 | sha+status ok | 4.853 | 3.52 | stable | 13496 | 16345 | 17400 | 15941 | 17400 | 16468 | 0 |
| 50M | wan | nocrypto | atp-rq-lab | 1 | 3 | 3 | sha+status ok | 2.556 | 0.87 | stable | 12172 | 21430 | 12216 | 19535 | 12216 | 21430 | 0 |
| 50M | wan | nocrypto | rsyncd | n/a | 3 | 3 | sha+status ok | 4.319 | 1.38 | stable | 8112 | 25977 | 30760 | 25977 | 30760 | 25977 | 0 |

## Noise warnings

No per-cell wall-time cv_pct exceeded 5.0.

## ATP vs rsync ratios

Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.

| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender peak RSS ratio | sender avg RSS ratio | receiver peak RSS ratio | receiver avg RSS ratio | combined peak RSS ratio | combined avg RSS ratio | ATP feedback rounds |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 500M | wan | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 0.960 | 1.042 | 2.401 | 2.357 | 0.814 | 1.367 | 1.883 | 2.355 | 0 |
| 500M | wan | nocrypto | atp-rq-lab | 1 | rsyncd | 0.778 | 1.285 | 1.485 | 0.717 | 0.390 | 0.707 | 0.390 | 0.714 | 0 |
| 50M | wan | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 0.650 | 1.539 | 1.515 | 1.695 | 0.763 | 1.353 | 1.175 | 1.682 | 0 |
| 50M | wan | nocrypto | atp-rq-lab | 1 | rsyncd | 0.592 | 1.690 | 1.500 | 0.825 | 0.397 | 0.752 | 0.397 | 0.825 | 0 |

## Per-regime geomean

| regime | geomean wall ratio ATP/rsync |
|---|---:|
| wan | 0.732 |

## Crypto-symmetry warnings

No crypto-asymmetric ATP/rsync pairs were present.

## Auth-posture exclusions

No rows were excluded for missing or mismatched authentication posture.

## Failed or incomplete rows

No failed SHA or incomplete rows were present.
