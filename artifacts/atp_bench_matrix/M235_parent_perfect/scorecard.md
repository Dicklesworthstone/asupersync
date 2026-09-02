# ATP vs rsync matrix scorecard

Integrity policy: ratios compare ATP only against optimally tuned rsync in the same workload, regime, and crypto tier. Failed SHA or incomplete rows are not admitted to headline ratios.

## Per-cell method medians

| workload | regime | tier | method | ATP streams | reps | ok | correctness | median wall s | cv_pct | cv flag | sender peak RSS KB | sender avg RSS KB | receiver peak RSS KB | receiver avg RSS KB | combined peak RSS KB | combined avg RSS KB | feedback rounds |
|---|---|---|---|---:|---:|---:|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 500M | perfect | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 6.856 | 2.72 | stable | 32344 | 38867 | 10012 | 19729 | 32344 | 38867 | 0 |
| 500M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 5 | 0 | no verified reps | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| 50M | perfect | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 1.715 | 15.10 | noisy | 18548 | 25377 | 9416 | 18886 | 18548 | 25377 | 0 |
| 50M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 5 | 0 | no verified reps | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| tree_big | perfect | encrypted | atp-quic-tls13 | n/a | 5 | 5 | sha+status ok | 1.115 | 23.79 | noisy | 14356 | 22572 | 18064 | 19108 | 18064 | 22572 | 0 |
| tree_big | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 5 | 0 | no verified reps | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |

## Noise warnings

Rows with cv_pct > 5.0 are noisy and should not be treated as clean wins without rerun evidence.

| workload | regime | tier | method | ATP streams | cv_pct | ok/reps |
|---|---|---|---|---:|---:|---:|
| 50M | perfect | encrypted | atp-quic-tls13 | n/a | 15.10 | 5/5 |
| tree_big | perfect | encrypted | atp-quic-tls13 | n/a | 23.79 | 5/5 |

## ATP vs rsync ratios

Only crypto-symmetric, same-cell ATP-vs-rsync pairs are admitted here.

| workload | regime | tier | ATP method | ATP streams | rsync method | wall ratio ATP/rsync | speedup rsync/ATP | sender peak RSS ratio | sender avg RSS ratio | receiver peak RSS ratio | receiver avg RSS ratio | combined peak RSS ratio | combined avg RSS ratio | ATP feedback rounds |
|---|---|---|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|

## Per-regime geomean

| regime | geomean wall ratio ATP/rsync |
|---|---:|

## Crypto-symmetry warnings

No crypto-asymmetric ATP/rsync pairs were present.

## Failed or incomplete rows

| workload | regime | tier | method | ATP streams | rep | status | sha ok | timed out | status code |
|---|---|---|---|---:|---:|---|---|---|---:|
| 50M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 1 | error | False | False | 11 |
| 50M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 2 | error | False | False | 11 |
| 50M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 3 | error | False | False | 11 |
| 50M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 4 | error | False | False | 11 |
| 50M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 5 | error | False | False | 11 |
| 500M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 1 | error | False | False | 11 |
| 500M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 2 | error | False | False | 11 |
| 500M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 3 | error | False | False | 11 |
| 500M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 4 | error | False | False | 11 |
| 500M | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 5 | error | False | False | 11 |
| tree_big | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 1 | error | False | False | 11 |
| tree_big | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 2 | error | False | False | 11 |
| tree_big | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 3 | error | False | False | 11 |
| tree_big | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 4 | error | False | False | 11 |
| tree_big | perfect | encrypted | rsync-ssh-aes128gcm | n/a | 5 | error | False | False | 11 |
