# ATP vs rsync — real-internet benchmark report

- **Date**: 2026-06-13T01:35:37Z
- **Sender → Receiver**: `root@87.99.133.171` → `root@178.18.254.243` (open internet)
- **RTT**: rtt min/avg/max/mdev = 92.997/93.322/94.399/0.430 ms
- **Cores**: sender 8, receiver 8
- **Runs per cell**: 3 measured + 1 warmup (warmup excluded from aggregates)

Note: the current `atp` TCP transport is plaintext, so `rsyncd` (plaintext)
is the apples-to-apples row; `rsync-ssh` is the realistic-usage row.

## Wall clock / throughput (mean of measured runs)

| Payload | Size | atp-tcp wall (s) | atp-tcp MB/s | rsync-ssh wall (s) | rsync-ssh MB/s | rsyncd wall (s) | rsyncd MB/s |
|---|---|---|---|---|---|---|---|
| 512k | 512 KB | 0.88 ±0.02 | 0.6 | 2.78 ±0.41 | 0.2 | 1.77 ±0.02 | 0.3 |
| 1m | 1 MB | 1.12 ±0.04 | 0.9 | 2.68 ±0.05 | 0.4 | 1.97 ±0.01 | 0.5 |
| 10m | 10 MB | 1.91 ±0.03 | 5.2 | 3.43 ±0.03 | 2.9 | 2.61 ±0.05 | 3.8 |
| 100m | 100 MB | 5.45 ±0.61 | 18.3 | 7.81 ±0.01 | 12.8 | 5.88 ±0.16 | 17.0 |
| 1g | 1 GB | 49.73 ±5.32 | 20.6 | 54.71 ±0.33 | 18.7 | 39.68 ±0.86 | 25.8 |
| tree | 719 MB | 37.73 ±3.75 | 19.1 | 38.97 ±0.09 | 18.5 | 28.77 ±0.51 | 25.0 |

## Resources (mean of measured runs)

| Payload | Tool | Sender peak RSS | Recv peak RSS | Sender CPU s (u+s) | Cycles (G) | Instr (G) | Avg core util % | Peak load1 (recv) |
|---|---|---|---|---|---|---|---|---|
| 512k | atp-tcp | 7 MB | 7 MB | 0.06 | — | — | — | 0.26 |
| 512k | rsync-ssh | 59 MB | 2156 MB | 0.06 | 0.07 | 0.11 | 56 | 3.67 |
| 512k | rsyncd | 59 MB | 16 MB | 0.03 | 0.02 | 0.01 | 47 | 1.85 |
| 1m | atp-tcp | 25 MB | 9 MB | 0.13 | 0.24 | 0.12 | 82 | 0.55 |
| 1m | rsync-ssh | 59 MB | 2916 MB | 0.07 | 0.11 | 0.13 | 68 | 2.55 |
| 1m | rsyncd | 59 MB | 16 MB | 0.03 | 0.02 | 0.01 | 87 | 1.20 |
| 10m | atp-tcp | 60 MB | 37 MB | 0.40 | 0.50 | 0.31 | 59 | 0.56 |
| 10m | rsync-ssh | 59 MB | 4036 MB | 0.22 | 0.32 | 0.26 | 54 | 2.06 |
| 10m | rsyncd | 59 MB | 16 MB | 0.06 | 0.07 | 0.03 | 53 | 0.94 |
| 100m | atp-tcp | 206 MB | 307 MB | 1.73 | 3.19 | 2.02 | 90 | 0.68 |
| 100m | rsync-ssh | 59 MB | 15 MB | 1.08 | 1.13 | 0.80 | 32 | 1.55 |
| 100m | rsyncd | 59 MB | 16 MB | 0.38 | 0.55 | 0.21 | 59 | 0.66 |
| 1g | atp-tcp | 2053 MB | 3079 MB | 14.97 | 28.61 | 19.87 | 67 | 3.53 |
| 1g | rsync-ssh | 59 MB | 15 MB | 12.72 | 11.42 | 6.52 | 47 | 0.94 |
| 1g | rsyncd | 59 MB | 16 MB | 3.45 | 5.61 | 2.07 | 54 | 1.07 |
| tree | atp-tcp | 1445 MB | 2166 MB | 10.06 | 16.78 | 11.93 | 58 | 3.77 |
| tree | rsync-ssh | 59 MB | 16 MB | 8.49 | 6.89 | 4.68 | 39 | 1.17 |
| tree | rsyncd | 59 MB | 17 MB | 2.32 | 3.28 | 1.56 | 66 | 0.80 |

## Speedup (rsync wall / atp wall; >1 means atp is faster)

| Payload | atp-tcp vs rsync-ssh | atp-tcp vs rsyncd |
|---|---|---|
| 512k | 3.17x | 2.02x |
| 1m | 2.40x | 1.76x |
| 10m | 1.79x | 1.37x |
| 100m | 1.43x | 1.08x |
| 1g | 1.10x | 0.80x |
| tree | 1.03x | 0.76x |

## Verification

- Measured transfers: 54; bit-for-bit SHA-256 verified: 54.
- Zero verification failures.

---

## Addendum: ATP-RQ (RaptorQ/UDP) transport — cross-machine status (2026-06-13)

The RaptorQ-over-UDP transport (`--transport rq`, `br-asupersync-mixdaw`) is
**loopback-proven** (5/5 e2e incl. 1-in-7 loss recovery) but is **not yet
viable cross-machine**, so it is excluded from the comparison table above. Fleet
bring-up (hz1 → vmi1156319, 93 ms RTT) surfaced two precise, reproducible bugs:

1. **Multi-block param mismatch** (`asupersync-c8m8ha`): any entry spanning >1
   source block fails at `set_object_params` (reproduced in-process). Single-block
   coding is correct (K=64 and K=512 in-process roundtrips pass).
2. **Single-block network convergence** (`asupersync-ro853b`): a K=512 transfer
   decodes in-process but not over the real path — round 0's 589 symbols all
   arrive (zero loss) yet the block never decodes, accumulating 2637+ accepted
   symbols before failing closed after 17 feedback rounds. The same symbol set
   decodes in-process, so the defect is in the network feed/protocol path (a
   `feed_symbol` reconstruction subtlety and/or the `ObjectComplete`-vs-in-flight
   -UDP race), not the coding layer.

Honest posture: ATP-RQ **fails closed** (no corruption, no hang, no fake
success) — it never reports a transfer it did not complete. The fixes are
well-scoped (multi-block param alignment; a two-task receiver that decouples UDP
drain from CPU-bound decode + a grace-drain after `ObjectComplete`). The
adaptive layer (`docs/atp_rq_adaptive_design.md`) would additionally pick small,
fast-decoding blocks on real paths. Until those land, **atp-tcp is the working
ATP transport** and the comparison above stands: atp-tcp wins on small/medium
files, trails plaintext rsyncd on bulk.
