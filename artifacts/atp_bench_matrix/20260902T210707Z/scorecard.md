# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA, incomplete rows, and mismatched current auth postures are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | wanqueue | encrypted | atp-quic-tls13 | n/a | 3 | 3 | sha+status ok | 42.195 | 3.19 | stable | 35808 | 44848 | 19348 | 27369 | 35808 | 44848 | 0 |
| 500M | wanqueue | encrypted | rsync-ssh-aes128gcm | n/a | 3 | 3 | sha+status ok | 27.060 | 1.37 | stable | 13436 | 16972 | 17176 | 16972 | 17176 | 16972 | 0 |
| 500M | wanqueue | nocrypto | atp-rq-lab | 1 | 3 | 3 | sha+status ok | 16.031 | 0.16 | stable | 12564 | 22056 | 12324 | 21465 | 12564 | 22107 | 0 |
| 500M | wanqueue | nocrypto | rsyncd | n/a | 3 | 3 | sha+status ok | 20.650 | 0.27 | stable | 7992 | 30051 | 30836 | 30051 | 30836 | 30051 | 0 |

## Noise warnings

No per-cell wall-time cv_pct exceeded 5.0.

## ATP vs rsync ratios

Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.

| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender peak RSS ratio | sender avg RSS ratio | receiver peak RSS ratio | receiver avg RSS ratio | combined peak RSS ratio | combined avg RSS ratio | ATP feedback rounds |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 500M | wanqueue | encrypted | atp-quic-tls13 | n/a | rsync-ssh-aes128gcm | 1.559 | 0.641 | 2.665 | 2.642 | 1.126 | 1.613 | 2.085 | 2.642 | 0 |
| 500M | wanqueue | nocrypto | atp-rq-lab | 1 | rsyncd | 0.776 | 1.288 | 1.572 | 0.734 | 0.400 | 0.714 | 0.407 | 0.736 | 0 |

## Per-regime geomean

| regime | geomean wall ratio ATP/rsync |
|---|---:|
| wanqueue | 1.100 |

## Crypto-symmetry warnings

No crypto-asymmetric ATP/rsync pairs were present.

## Auth-posture exclusions

No rows were excluded for missing or mismatched authentication posture.

## Failed or incomplete rows

No failed SHA or incomplete rows were present.
