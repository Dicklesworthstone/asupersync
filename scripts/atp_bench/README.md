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
    all. `atp-quic` is the QUIC/TLS ATP row, `atp-rq` is the authenticated
    RaptorQ/UDP ATP row, `atp-tcp` is the plaintext legacy ATP control row,
    `rsyncd` is the plaintext rsync ceiling, and rsync-over-ssh is the
    authenticated/encrypted rsync row. This is stated in the report rather than
    hidden.
- **3 measured runs + 1 warmup** per (tool × payload). Each cell writes to a
  unique receiver directory under `/root/atp-bench/recv/<run-id>/...`; the
  harness retains artifacts instead of deleting prior runs.
- **Verification**: a SHA-256 manifest is generated at payload creation; after
  EVERY transfer the receiver runs `sha256sum -c` over the manifest. A failed
  verification fails the run (recorded, not discarded).
- **RQ/QUIC symbol authentication**: `atp-rq` and `atp-quic` use a 32-byte
  symbol-auth key. The harness generates one with `atp rq-keygen` per run unless
  `--atp-rq-auth-key-hex` is supplied; the key is injected through
  `ATP_RQ_AUTH_KEY_HEX` and is not written to `conditions.json`.
- **Crypto-symmetric reporting**: `report.py` only headlines apples-to-apples
  speedup pairs: `atp-quic`/`atp-rq` against rsync-over-ssh, and the plaintext
  `atp-tcp` control against `rsyncd`.

## Metrics captured

| Metric | Source | Side |
|--------|--------|------|
| Wall clock | `/usr/bin/time -v` | sender + receiver (atp `--once`) |
| Peak RSS | `/usr/bin/time -v` MaxRSS | sender + receiver |
| Avg RSS / %CPU | `sampler.sh` (0.5s `ps` samples) | sender + receiver |
| CPU cycles / instructions | `perf stat` when available, else omitted | sender |
| Per-core utilization | `mpstat -P ALL 1` during run | sender |
| Responsiveness guard | 1-min loadavg sampled; run fails if > configured cap × cores | both |
| Throughput | payload bytes / wall | derived |
| feedback_rounds | ATP sender JSON | ATP rows |

## Files

- `gen_payloads.sh` — run on the **sender**: builds `/root/atp-bench/payloads`
  (512KB/1MB/10MB/100MB/1GB urandom files + heterogeneous nested tree) and
  SHA-256 manifests. Idempotent; if an existing payload does not match its
  manifest, the script fails closed rather than overwriting it.
- `collect_metrics.sh` — background process sampler (`ps`/loadavg → JSONL).
- `run_one.sh` — runs one sender command under `/usr/bin/time -v` (+ `perf
  stat` if present), emits a JSON result line, and retains its temp directory
  path in the `tmp_dir` field.
- `run_bench.sh` — orchestrator (run from the dev box): deploys binaries +
  scripts, iterates payload × tool × run, collects sender+receiver metrics,
  verifies hashes, writes `results.jsonl`.
- `report.py` — aggregates `results.jsonl` → markdown comparison report.

## ATP RQ/QUIC knobs

`atp-quic` and `atp-rq` are included by default. The TCP row remains useful as a
plaintext regression/control comparison while RQ/QUIC work continues.

```bash
--atp-rq-streams 8
--atp-rq-symbol-size 1024
--atp-rq-repair-overhead 1.15
--atp-rq-tail-drain-ms 2
--atp-rq-auth-key-hex <64-char-hex> # optional; default is per-run generated
--atp-quic-server-name <name-or-ip> # optional; default is receiver host/IP
--atp-quic-handshake-timeout-ms 30000
```

Those values are recorded in `conditions.json` for every run. `atp-quic` reuses
the RQ symbol size, repair overhead, tail-drain, and symbol-auth key so the
encrypted ATP row exercises the same FEC/auth posture under QUIC/TLS. Sweep them
when working on throughput: larger symbols reduce coding overhead, more streams
can help fill the RQ path, and repair overhead trades network bytes for fewer
decode round trips. Tail drain is the receiver-side quiet window after each
fountain round marker; increasing it can prevent false `NeedMore` rounds on
high-RTT paths where control traffic beats queued symbols to user space.

When `atp-quic` is requested, `run_bench.sh` generates a short-lived self-signed
certificate/key on the receiver under `<base>/runs/<run-id>/quic_tls/`, copies
the certificate to the sender as the CA trust root, and passes `--server-cert`,
`--server-key`, `--ca`, and `--server-name` explicitly. The key is never copied
off the receiver.

`run_bench.sh` also accepts `--run-id <A-Za-z0-9._->` and
`--base <remote-dir>`. Supplying a run id makes reruns easy to correlate across
sender, receiver, and local artifacts. Use `--base` when the sender is not
`root`; the directory must be writable on both machines. Cleanup is
intentionally manual: inspect or archive `<base>/recv/<run-id>` and
`<base>/runs/<run-id>` on the receiver before removing anything.

## Resource Guard

Every benchmark row records a `resource_guard` object with schema
`atp-bench-resource-guard-v1`. The guard evaluates sampled load and optional
RSS caps as a pass/fail artifact, so the G3 responsiveness claim is not inferred
from prose in `report.md`.

```bash
--max-load-per-core 1.5     # default; applies to sender and receiver load1
--max-sender-rss-mb 0       # 0 disables the sender RSS cap
--max-receiver-rss-mb 0     # 0 disables the receiver RSS cap
```

The load cap is enforced before each series and after each measured run. RSS
caps are opt-in because valid ceilings depend on payload/profile size; when set,
the row fails closed if `/usr/bin/time -v` or sampler evidence crosses the cap.

## Usage

```bash
# from the repo root on the dev box
scripts/atp_bench/run_bench.sh \
  --sender hz1 --sender-key ~/.ssh/contabo_vps_ed25519 \
  --receiver vmi1156319 --receiver-key ~/.ssh/contabo_vps_ed25519 \
  --base /home/ubuntu/atp-bench \
  --atp-binary target/release/atp \
  --payloads 512k,1m,10m,100m,1g,tree \
  --tools atp-quic,atp-rq,atp-tcp,rsync-ssh,rsyncd \
  --atp-rq-streams 8 \
  --atp-rq-symbol-size 1024 \
  --atp-rq-repair-overhead 1.15 \
  --atp-rq-tail-drain-ms 2 \
  --run-id atp-rq-open-internet-$(date -u +%Y%m%dT%H%M%SZ) \
  --runs 3 \
  --out artifacts/atp_bench/$(date +%Y-%m-%d)

python3 scripts/atp_bench/report.py artifacts/atp_bench/<date>/results.jsonl \
  > artifacts/atp_bench/<date>/report.md
```

Fleet etiquette: prefer `hz1` as sender (hz2 is the highest-priority rch build
worker); the responsiveness guard aborts a run series if either machine's
loadavg exceeds 1.5× its core count.
