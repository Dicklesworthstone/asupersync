# ATP vs rsync — real-internet benchmark harness (br-asupersync-iiz6jk)

Measures `atp` against a **maximally tuned** rsync transferring real payloads
between real fleet machines over the open internet (Hetzner → Contabo), with
bit-for-bit SHA-256 verification of every single transfer.

## Methodology (gauntlet rules)

- **Honest baseline first**: every number is reported, including losses. No
  cherry-picking. Network conditions (RTT, optional iperf3 throughput ceiling)
  are recorded alongside results.
- **Toughest-possible rsync**: random payloads are incompressible and the
  destination is always empty, so rsync is configured to skip everything that
  would slow it down:
  - `-aW --inplace` — archive mode, **whole-file** (delta algorithm off — it
    can only lose on fresh random data), in-place writes (no tmp-copy rename).
  - **No `-z`** — compression strictly hurts on `/dev/urandom` payloads.
  - ssh transport tuned: `-T -x -o Compression=no -c aes128-gcm@openssh.com`
    (fastest AEAD cipher commonly available; no TTY, no X11).
  - **`rsyncd` daemon mode** is also measured: plaintext TCP, no ssh crypto at
    all. The current `atp` TCP transport is also plaintext, so `rsyncd` is the
    apples-to-apples row; rsync-over-ssh is the realistic-usage row. This is
    stated in the report rather than hidden.
- **3 measured runs + 1 warmup** per (tool × payload), receiver destination
  wiped between runs.
- **Verification**: a SHA-256 manifest is generated at payload creation; after
  EVERY transfer the receiver runs `sha256sum -c` over the manifest. A failed
  verification fails the run (recorded, not discarded).

## Metrics captured

| Metric | Source | Side |
|--------|--------|------|
| Wall clock | `/usr/bin/time -v` | sender + receiver (atp `--once`) |
| Peak RSS | `/usr/bin/time -v` MaxRSS | sender + receiver |
| Avg RSS / %CPU | `sampler.sh` (0.5s `ps` samples) | sender + receiver |
| CPU cycles / instructions | `perf stat` when available, else omitted | sender |
| Per-core utilization | `mpstat -P ALL 1` during run | sender |
| Responsiveness guard | 1-min loadavg sampled; run flagged if > 1.5×cores | both |
| Throughput | payload bytes / wall | derived |

## Files

- `gen_payloads.sh` — run on the **sender**: builds `/root/atp-bench/payloads`
  (512KB/1MB/10MB/100MB/1GB urandom files + heterogeneous nested tree) and
  SHA-256 manifests. Idempotent.
- `sampler.sh` — background process sampler (`ps`/loadavg → JSONL).
- `run_one.sh` — runs one sender command under `/usr/bin/time -v` (+ `perf
  stat` if present), emits a JSON result line.
- `run_bench.sh` — orchestrator (run from the dev box): deploys binaries +
  scripts, iterates payload × tool × run, collects sender+receiver metrics,
  verifies hashes, writes `results.jsonl`.
- `report.py` — aggregates `results.jsonl` → markdown comparison report.

## Usage

```bash
# from the repo root on the dev box
scripts/atp_bench/run_bench.sh \
  --sender root@87.99.133.171 --sender-key ~/.ssh/contabo_vps_ed25519 \
  --receiver root@178.18.254.243 --receiver-key ~/.ssh/contabo_vps_ed25519 \
  --atp-binary target/release/atp \
  --payloads 512k,1m,10m,100m,1g,tree \
  --tools atp-tcp,rsync-ssh,rsyncd \
  --runs 3 \
  --out artifacts/atp_bench/$(date +%Y-%m-%d)

python3 scripts/atp_bench/report.py artifacts/atp_bench/<date>/results.jsonl \
  > artifacts/atp_bench/<date>/report.md
```

Fleet etiquette: prefer `hz1` as sender (hz2 is the highest-priority rch build
worker); the responsiveness guard aborts a run series if either machine's
loadavg exceeds 1.5× its core count.
