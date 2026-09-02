# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA, incomplete rows, and mismatched current auth postures are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | wanloss | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 28.268 | 1.13 | stable | 32688 | 40358 | 20672 | 28003 | 32688 | 40358 | 0 |
| 500M | wanloss | encrypted | rsync-ssh-aes128gcm | n/a | 3 | 3 | sha+status ok | 27.152 | 1.18 | stable | 13544 | 17161 | 17428 | 17161 | 17428 | 17161 | 0 |
| 500M | wanloss | nocrypto | atp-rq-lab | 1 | 3 | 3 | sha+status ok | 16.118 | 0.50 | stable | 12452 | 22100 | 12728 | 21731 | 12728 | 22100 | 0 |
| 500M | wanloss | nocrypto | rsyncd | n/a | 3 | 3 | sha+status ok | 20.745 | 0.07 | stable | 8132 | 30036 | 30828 | 30036 | 30828 | 30036 | 0 |
| 50M | wanloss | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 3.454 | 6.15 | noisy | 20856 | 29526 | 17552 | 23267 | 20856 | 29526 | 0 |
| 50M | wanloss | encrypted | rsync-ssh-aes128gcm | n/a | 3 | 3 | sha+status ok | 4.839 | 2.33 | stable | 13616 | 16336 | 17232 | 16336 | 17232 | 16336 | 0 |
| 50M | wanloss | nocrypto | atp-rq-lab | 1 | 3 | 3 | sha+status ok | 2.552 | 0.98 | stable | 12536 | 21589 | 11940 | 19102 | 12536 | 21589 | 0 |
| 50M | wanloss | nocrypto | rsyncd | n/a | 3 | 3 | sha+status ok | 4.418 | 1.29 | stable | 8012 | 26887 | 30800 | 26888 | 30800 | 26888 | 0 |

## Noise warnings

Rows with cv_pct > 5.0 are noisy and should not be treated as clean wins without rerun evidence.

| workload | regime | tier | method | ATP streams | cv_pct | ok/reps |
|---|---|---|---|---:|---:|---:|
| 50M | wanloss | encrypted | atp-quic-tls13 | n/a | 6.15 | 3/3 |

## ATP vs rsync ratios

Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.

| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender peak RSS ratio | sender avg RSS ratio | receiver peak RSS ratio | receiver avg RSS ratio | combined peak RSS ratio | combined avg RSS ratio | ATP feedback rounds |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 500M | wanloss | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 1.041 | 0.961 | 2.413 | 2.352 | 1.186 | 1.632 | 1.876 | 2.352 | 0 |
| 500M | wanloss | nocrypto | atp-rq-lab | 1 | rsyncd | 0.777 | 1.287 | 1.531 | 0.736 | 0.413 | 0.723 | 0.413 | 0.736 | 0 |
| 50M | wanloss | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 0.714 | 1.401 | 1.532 | 1.807 | 1.019 | 1.424 | 1.210 | 1.807 | 0 |
| 50M | wanloss | nocrypto | atp-rq-lab | 1 | rsyncd | 0.578 | 1.731 | 1.565 | 0.803 | 0.388 | 0.710 | 0.407 | 0.803 | 0 |

## Per-regime geomean

| regime | geomean wall ratio ATP/rsync |
|---|---:|
| wanloss | 0.760 |

## Crypto-symmetry warnings

No crypto-asymmetric ATP/rsync pairs were present.

## Auth-posture exclusions

No rows were excluded for missing or mismatched authentication posture.

## Failed or incomplete rows

No failed SHA or incomplete rows were present.
