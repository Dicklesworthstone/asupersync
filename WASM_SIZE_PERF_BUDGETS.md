# WASM Size and Performance Budgets (asupersync-umelq.13.1)

Generated: `2026-02-28T06:53:00Z`  
Bead: `asupersync-umelq.13.1`  
Depends on: `asupersync-umelq.18.1`

Purpose: define hard, CI-enforceable budgets for browser-targeted Asupersync
artifacts and runtime behavior (size, init latency, steady-state memory, and
critical-path p95 latency), with deterministic measurement rules.

## 1. Scope and Non-Negotiables

These budgets are for the wasm browser program (`asupersync-umelq.*`) and do
not relax semantic invariants:

1. Structured concurrency ownership is preserved (no orphan task/fiber flows).
2. Cancellation remains `request -> drain -> finalize`.
3. Obligation accounting remains commit-or-abort (no permit/ack/lease leaks).
4. Region close still implies quiescence.

No optimization is valid if it violates any invariant above.

## 2. Budgeted Artifact Profiles

The program tracks three profiles:

1. `core-min`: semantic core for browser runtime without optional diagnostics.
2. `core-trace`: core runtime plus deterministic trace/replay envelope.
3. `full-dev`: browser developer profile with diagnostics and richer tooling.

All size budgets are tracked as both uncompressed `.wasm` bytes and gzip bytes.

## 3. Hard Budgets (Release-Blocking)

| Metric ID | Metric | `core-min` | `core-trace` | `full-dev` | Gate type |
|---|---|---:|---:|---:|---|
| `M-PERF-01A` | wasm size (raw bytes) | <= 650 KiB | <= 900 KiB | <= 1300 KiB | hard fail |
| `M-PERF-01B` | wasm size (gzip bytes) | <= 220 KiB | <= 320 KiB | <= 480 KiB | hard fail |
| `M-PERF-02A` | cold init p95 (desktop Chromium baseline) | <= 60 ms | <= 85 ms | <= 130 ms | hard fail |
| `M-PERF-02B` | cold init p95 (mid-tier mobile baseline) | <= 160 ms | <= 220 ms | <= 320 ms | hard fail |
| `M-PERF-03A` | steady-state heap after warmup p95 | <= 24 MiB | <= 32 MiB | <= 48 MiB | hard fail |
| `M-PERF-03B` | cancellation response p95 (checkpoint to observable cancel) | <= 2.5 ms | <= 3.5 ms | <= 5.0 ms | hard fail |

## 4. Operational Budgets (Warn-Then-Block)

| Metric ID | Metric | Target | Warn threshold | Hard threshold |
|---|---|---:|---:|---:|
| `M-PERF-04A` | `tx.reserve()+send()` p95 (single producer/consumer harness) | <= 8 us | > 8 us | > 12 us |
| `M-PERF-04B` | timeout arm+cancel p95 (timer wheel adapter harness) | <= 15 us | > 15 us | > 24 us |
| `M-PERF-04C` | `scope.spawn()+join()` p95 (small task body) | <= 40 us | > 40 us | > 65 us |
| `M-PERF-04D` | deterministic replay load+step overhead vs baseline | <= +12% | > +12% | > +20% |

Policy:

1. First breach in warn band marks CI warning and opens/links a bead.
2. Two consecutive breaches in warn band escalate to hard fail.
3. Any hard-threshold breach fails immediately.

## 5. Measurement Matrix

Reference environments (pinned for trend stability):

1. `desktop-chromium`: Linux x86_64, pinned Chromium major version.
2. `desktop-firefox`: Linux x86_64, pinned Firefox major version.
3. `mobile-android`: mid-tier ARM Android device class via CI farm.

Each metric sample must include:

1. git commit SHA
2. profile (`core-min`/`core-trace`/`full-dev`)
3. browser target + version
4. seed/corpus ID
5. command provenance (exact command line)
6. artifact paths (wasm binary, traces, logs, summary JSON)

## 6. Deterministic Measurement Protocol

1. Run each scenario with fixed seed set: `11, 29, 42, 73, 101`.
2. For latency metrics, use at least 2000 iterations per seed.
3. Compute per-seed p95, then report median-of-seed-p95 as gate value.
4. Size metrics are single-sample deterministic per profile build.
5. Memory metric samples after warmup window (`N=200` operations) and then over
   fixed interval samples (`N=500`), reporting p95.

## 7. CI Gate Contract

The CI gate emits a single JSON summary file:

- path: `artifacts/wasm_budget_summary.json`
- schema fields:
  - `commit`
  - `profile`
  - `environment`
  - `metric_id`
  - `value`
  - `unit`
  - `threshold_warn`
  - `threshold_hard`
  - `status` (`pass|warn|fail`)
  - `seed_set`
  - `commands`
  - `artifact_paths`

`asupersync-umelq.13.2` and `asupersync-umelq.13.3` must consume this schema
without format drift.

## 8. Canonical Command Envelope

All cargo-heavy checks must be offloaded.

Current gating note (as of 2026-02-28):

1. `wasm32-unknown-unknown` compilation for `asupersync` remains preview-gated and
   still has unresolved native-surface imports on this branch.
2. CI should still run the preview command (below) and record the exact failure
   signature until the wasm profile-closure beads land.
3. Native correctness/lint gates (`cargo check --all-targets`,
   `cargo clippy --all-targets -- -D warnings`) remain mandatory hard gates.

Preview wasm compilation command (expected to become green as profile-closure
work lands):

```bash
rch exec -- cargo check -p asupersync \
  --target wasm32-unknown-unknown \
  --no-default-features \
  --features wasm-browser-preview,getrandom/wasm_js
rch exec -- cargo build -p asupersync \
  --target wasm32-unknown-unknown \
  --release \
  --no-default-features \
  --features wasm-browser-preview,getrandom/wasm_js
```

Recommended size capture:

```bash
# raw size
stat -c '%s' target/wasm32-unknown-unknown/release/asupersync.wasm

# gzip size
gzip -9 -c target/wasm32-unknown-unknown/release/asupersync.wasm | wc -c
```

Recommended benchmark envelope (to be implemented by `umelq.13.2`):

```bash
rch exec -- cargo test -p asupersync --test wasm_perf_budget -- --nocapture
```

## 8.1 Optimization Pipeline Contract (`asupersync-umelq.13.3`)

Optimization variants are now canonicalized in:

- policy: `.github/wasm_optimization_policy.json`
- validator: `scripts/check_wasm_optimization_policy.py`
- summary artifact: `artifacts/wasm_optimization_pipeline_summary.json`

Profile mapping (must remain aligned with Section 2 budget profiles):

| Variant ID | Policy profile | Budget profile | Intent | Optimization posture |
|---|---|---|---|---|
| `dev` | `wasm-browser-dev` | `full-dev` | fast local debugging | low optimization, richer debug info, no `wasm-opt` |
| `canary` | `wasm-browser-canary` | `core-trace` | staging/canary signal quality | balanced `-C opt-level=s` + moderate `wasm-opt` passes |
| `release` | `wasm-browser-release` | `core-min` | production shipment | maximal size reduction (`-C opt-level=z`, LTO, aggressive `wasm-opt`) |

Contract rules:

1. The optimization policy may tune compiler flags and `wasm-opt` passes only.
2. Threshold values in Section 3/4 remain governance-controlled and cannot be
   changed by optimization-pipeline edits.
3. Every profile must keep `wasm-browser-preview,getrandom/wasm_js` enabled and
   keep wasm-forbidden features disabled.
4. CI must validate policy shape and emit the summary artifact for downstream
   gates (`13.5`, `18.5`) even while wasm compilation remains preview-gated.

Deterministic validator commands:

```bash
python3 scripts/check_wasm_optimization_policy.py --self-test
python3 scripts/check_wasm_optimization_policy.py \
  --policy .github/wasm_optimization_policy.json
```

## 8.2 Benchmark Corpus Contract (`asupersync-umelq.13.2`)

Representative browser workload coverage is now canonicalized in:

- policy: `.github/wasm_benchmark_corpus.json`
- validator: `scripts/check_wasm_benchmark_corpus.py`
- summary artifact: `artifacts/wasm_benchmark_corpus_summary.json`

The corpus contract maps scenarios to explicit user journeys and budget metrics:

1. Framework coverage: `vanilla-js`, `typescript-sdk`, `react`, `nextjs`.
2. Workload coverage: `cold-start`, `steady-throughput`, `cancellation-storm`,
   `streaming-io`, `memory-pressure`.
3. Deterministic seed set (per scenario): `11, 29, 42, 73, 101`.
4. Metric mapping must use the budget metric IDs defined in this document
   (`M-PERF-01*` through `M-PERF-04*`).
5. Scenario commands must use the canonical perf runner envelope:
   `rch exec -- ./scripts/run_perf_e2e.sh ...`

CI policy:

1. Validate corpus schema + coverage and emit summary artifact.
2. Treat missing framework/workload/browser coverage as a gate failure.
3. Keep summary schema stable for downstream gates (`13.4`, `13.5`, `15.1`).

Deterministic validator commands:

```bash
python3 scripts/check_wasm_benchmark_corpus.py --self-test
python3 scripts/check_wasm_benchmark_corpus.py \
  --policy .github/wasm_benchmark_corpus.json
```

## 8.3 Continuous Perf Regression Gate (`asupersync-umelq.13.5`)

Automated regression detection is now enforced via:

- budget policy: `.github/wasm_perf_budgets.json`
- gate script: `scripts/check_perf_regression.py`
- report artifact: `artifacts/wasm_perf_regression_report.json`
- event log: `artifacts/wasm_perf_gate_events.ndjson`

Gate logic:

1. **Hard budget checks** (Section 3): Any measurement exceeding the profile
   threshold triggers immediate CI failure.
2. **Operational budget checks** (Section 4): First breach in warn band emits
   warning. Two consecutive breaches escalate to hard failure.
3. **Baseline regression detection**: Compares current benchmark run against
   `baselines/baseline_latest.json`. Any benchmark regressing beyond
   `max_regression_pct` (default 10%) triggers CI failure.

The gate runs in the `check` CI job after benchmark corpus validation. When no
measurements are available (e.g., before WASM compilation is green), all budget
checks report `skip` and the gate passes. This ensures the gate infrastructure
is validated even while the measurement pipeline is being built.

Deterministic validator commands:

```bash
python3 scripts/check_perf_regression.py --self-test
python3 scripts/check_perf_regression.py \
  --budgets .github/wasm_perf_budgets.json \
  --profile core-min
```

With baseline comparison:

```bash
python3 scripts/check_perf_regression.py \
  --budgets .github/wasm_perf_budgets.json \
  --baseline baselines/baseline_latest.json \
  --current baselines/baseline_current.json
```

## 9. Rationale for Threshold Values

1. `core-min` budget targets CDN-friendly first payloads while leaving room for
   explicit capability and cancellation semantics.
2. `core-trace` allows deterministic replay metadata overhead without enabling
   unbounded growth.
3. `full-dev` budgets preserve a practical local-debug profile while forcing
   tool/diagnostic bloat discipline.
4. Mobile thresholds are intentionally stricter than "it works eventually" to
   keep browser adoption viable for real production interfaces.

## 10. Downstream Bead Interfaces

This budget contract is an input artifact for:

1. `asupersync-umelq.13.2` (benchmark corpus/scenario design): must map each
   scenario to one or more metric IDs above.
2. `asupersync-umelq.13.3` (optimization pipeline): may tune compilers and
   artifact variants but cannot alter thresholds without governance update.
3. `asupersync-umelq.13.5` (continuous perf regression gate): enforces hard/
   operational budgets and baseline regression detection in CI.
4. `asupersync-umelq.18.4` (CI verification pipelines): must enforce pass/fail
   semantics and artifact schema contract.

## 11. Change-Control Rules

Threshold changes require:

1. linked bead updating rationale and affected scenarios,
2. before/after evidence bundle with the same seed set,
3. governance approval note in the commit or bead thread.

Without all three, threshold changes are invalid.

## 12. Completion Checklist for `asupersync-umelq.13.1`

1. Budget thresholds explicitly defined (this document).
2. Measurement protocol deterministic and reproducible.
3. Command provenance contract defined for CI artifacts.
4. Downstream integration points (`13.2`, `13.3`, `18.4`) explicitly declared.
5. Release-blocking vs warning semantics defined.
