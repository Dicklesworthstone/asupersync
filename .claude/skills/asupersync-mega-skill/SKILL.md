---
name: asupersync-mega-skill
description: >-
  Build, migrate, debug, and maintain Asupersync. Use when working with Tokio
  migration, Cx/Scope/cancellation, local tasks, Lab replay, browser/Wasm,
  protocols, databases, OTLP, or repository proof.
---

# Asupersync Mega Skill

Asupersync is a spec-first runtime for structured concurrency, cancel-correct
effects, obligations, deterministic testing, and capability security—not a
Tokio wrapper. Verify against live evidence.

For release, live-support, or open-boundary questions, start with the
current-status card in
[SOURCE-MAP.md](references/SOURCE-MAP.md#release-and-live-head-status).
Otherwise load the single task lane below first. Live source, tags, registry
state, and terminal proof receipts outrank examples or stale tracker labels.

## Table of Contents

- [Bootstrap](#bootstrap)
- [Choose One Lane](#choose-one-lane)
- [Non-Negotiables](#non-negotiables)
- [Migration Workflow](#migration-workflow)
- [Proof and Repository Rules](#proof-and-repository-rules)
- [Skill Validation](#skill-validation)

## Bootstrap

Use `#[asupersync::main]` when the application does not need to own the runtime:

```rust
#[asupersync::main]
async fn main() {
    println!("hello from asupersync");
}
```

Use `RuntimeBuilder` when it does. Runtime-spawned tasks receive a runtime-owned
`Cx`; pass `&Cx` into application code. Use production request-context APIs,
explicit spawn admission, and checked joins rather than test constructors or
implicit authority. For handle-only request contexts and caller-owned blocking
pools, read [RUNTIME-CONTROLS](references/RUNTIME-CONTROLS.md); attaching a pool
does not install a scheduler or a worker-local lane.

## Choose One Lane

Load one primary reference first. Follow its links only when the task reaches
that boundary; do not preload whole clusters.

| Task | Read first |
|---|---|
| Native greenfield service | [NATIVE-GREENFIELD](references/NATIVE-GREENFIELD.md) |
| Brownfield Tokio migration | [BROWNFIELD-MIGRATION](references/BROWNFIELD-MIGRATION.md) |
| Exact Tokio compatibility or quarantine boundary | [COMPAT-BOUNDARY](references/COMPAT-BOUNDARY.md) |
| Cx-aware high-level web handler patterns | [GREENFIELD-PATTERNS](references/GREENFIELD-PATTERNS.md) |
| Runtime, cancellation, shutdown, or local tasks | [RUNTIME-CONTROLS](references/RUNTIME-CONTROLS.md) |
| Channels, locks, or combinators | [PRIMITIVES-AND-ORCHESTRATION-CHOOSER](references/PRIMITIVES-AND-ORCHESTRATION-CHOOSER.md) |
| Observability, diagnostics, metrics, or OTLP | [OBSERVABILITY-FORENSICS](references/OBSERVABILITY-FORENSICS.md) |
| HTTP, gRPC, or high-level web routing | [WEB-GRPC-HTTP](references/WEB-GRPC-HTTP.md) |
| Database, messaging, filesystem, process, or signal work | [DB-MESSAGING-FS-PROCESS](references/DB-MESSAGING-FS-PROCESS.md) |
| Protocol or low-level networking work | [NETWORKING-PROTOCOL-STACK](references/NETWORKING-PROTOCOL-STACK.md) |
| Lab replay, DPOR, or escaped concurrency defect | [TESTING-FORENSICS](references/TESTING-FORENSICS.md) |
| Supervision or OTP-style components | [SUPERVISION-OTP](references/SUPERVISION-OTP.md) |
| Browser or Wasm integration | [BROWSER-WASM](references/BROWSER-WASM.md) |
| Distributed execution or rigor | [DISTRIBUTED-AND-RIGOR](references/DISTRIBUTED-AND-RIGOR.md) |
| RaptorQ or ATP security, transfer, or benchmark evidence | [RAPTORQ-DISTRIBUTED](references/RAPTORQ-DISTRIBUTED.md) |
| Work inside Asupersync, release it, or assess API compatibility | [REPO-CONTRIBUTOR-GUIDE](references/REPO-CONTRIBUTOR-GUIDE.md) |
| Diagnose an error or uncertain support claim | [TROUBLESHOOTING](references/TROUBLESHOOTING.md) |

Use browser/Wasm, QUIC/H3, messaging, distributed, or RaptorQ lanes only when
requirements call for them.

## Non-Negotiables

- Do **not** treat Asupersync as an executor swap.
- Put `&Cx` first in async APIs you control.
- Use `Scope` and child regions for owned work. Avoid detached background tasks.
- Use `Cx::spawn` / `Cx::spawn_in` for ordinary region-owned task creation.
  `Scope::spawn_registered` is a lower-level boot/test path for callers already
  holding `&mut RuntimeState`.
- Add `cx.checkpoint()` in loops, retry bodies, long handlers, and shutdown-sensitive code.
- Prefer cancel-aware primitives and two-phase effects.
- State the layered v0.4.4-v0.4.9 cancellation contract precisely: ordinary `Cx::spawn*`
  preserves a typed result returned after cancellation acknowledgement (a
  concurrent abort no longer erases it), but pre-first-poll cancellation and
  cancellation-blind late values keep v0.4.3 task-level cancellation, and
  `JoinSet`, cancellation-dominant combinators, blocking wrappers, and
  low-level state tasks retain their separately tested policies. Neither
  "abort always wins" nor "the value always survives" is correct. Explicit
  cancellation wakes timer-parked native tasks; `Sleep` retires its registration
  and completes with `()` while timeout/deadline combinators retain outcome
  classification. Native worker tests, not Lab-only models, prove this boundary.
- `Cx::spawn_local` requires a worker-local lane owned by the same runtime. A
  direct `Runtime::block_on`, entry-macro body, `run_test`, or
  `run_test_with_cx` does not by itself install that lane and may return
  `LocalSchedulerUnavailable` (ASUP-E004). Enter a real worker with
  `runtime.block_on(runtime.handle().spawn(async { ... }))`, obtain
  `Cx::current()` there, then spawn the `!Send` future and prove it reached the
  parked state before aborting it.
- Use deterministic tests as part of normal development, not as optional polish.
- Treat `Cx::for_testing()` and `Cx::for_request()` as test/internal harness
  paths, not production architecture.
- Keep Tokio and Tokio-only crates behind explicit adapter modules if you must keep them at all.
- `asupersync-tokio-compat` adapts selected traits and context; it does not install a Tokio runtime
  or prove `Handle::current()`-dependent frameworks.
  Require downstream compile and runtime evidence for every bridge.

## Migration Workflow

1. Inventory direct and transitive Tokio-ecosystem dependencies.
2. Classify each as native replacement, explicit compat holdout, or deliberate
   workaround.
3. Use the repository's migration readiness planner when available; do not
   confuse a `cargo tree` grep with a plan.
4. Replace bootstrap, thread `&Cx` through owned APIs, then replace detached
   spawning with region-owned work.
5. Migrate time, sync, I/O, channel, web, database, and protocol slices one at
   a time.
6. Add deterministic and native cancellation tests during the migration.
7. Compile actual external-consumer feature profiles; `cfg(test)` access and
   repo-internal tests are not downstream API evidence.
8. Remove each compat boundary when its last justified dependency is gone.

The planner's `summary.final_verdict`, `proof_pack.proof_commands`,
`semantic_map.recommendations`, and `operator_report.phase_plan` are inputs to
the decision. `scripts/audit-target.sh` is only bounded inventory; its optional
Cargo graph probe is explicit and can touch Cargo state.

For more-than-parity design:
[LEVERAGE-PLAYBOOK](references/LEVERAGE-PLAYBOOK.md),
[BUDGET-OUTCOME-CAPABILITIES](references/BUDGET-OUTCOME-CAPABILITIES.md),
[SUPERVISION-OTP](references/SUPERVISION-OTP.md), and
[ADVANCED-FEATURES](references/ADVANCED-FEATURES.md).

Other routers: [adoption](references/ADOPTION-LANES.md),
[anti-patterns](references/ANTI-PATTERNS.md),
[compat bridge](references/COMPAT-BRIDGE.md),
[replacement matrix](references/TOKIO-REPLACEMENT-MATRIX.md),
[performance](references/PERFORMANCE-AND-SCHEDULING.md),
[browser frameworks](references/BROWSER-FRAMEWORKS.md), and
[mathematics](references/MATHEMATICAL-FOUNDATIONS.md).

Secondary deep dives, only when a primary card routes there (except the two
direct routes named above):
[greenfield patterns](references/GREENFIELD-PATTERNS.md),
[Tokio mappings](references/TOKIO-MAPPING.md),
[compat limits](references/COMPAT-BOUNDARY.md),
[scheduler internals](references/SCHEDULER-INTERNALS.md),
[channel/sync internals](references/CHANNELS-SYNC-INTERNALS.md),
[lock ordering](references/LOCK-ORDERING.md),
[support classes](references/STACK-SURFACES.md),
[Lab/DPOR](references/LAB-TRACE-DPOR.md), and
[error taxonomy](references/ERROR-TAXONOMY.md).

## Proof and Repository Rules

- Run the host formatter, compiler, linter, and tests; verify cancellation,
  shutdown, and resource release, not compilation alone.
- For an escaped concurrency defect, reproduce the same public API sequence on
  the native runtime, prove the formerly failing parked/owned state, assert the
  exact nested result and cleanup, and retain old-red/new-green evidence. A
  Lab-only or compile-only test is not a substitute.
- RCH pre-admission refusal, exit 103, worker assignment, a job id, a PID, or
  local fallback means **zero admissible executed tests**. Green proof requires
  terminal output naming the target and nonzero pass counts from the required
  environment.
- Do not key source or evidence authority to `/dp`, `/data/projects`, or an RCH
  checkout prefix. Identify the repository by content and declared root.
- Never invoke a waker, user callback, observer, or extension hook while a
  runtime-state lock is held. Treat unresolved tracker rows as unshipped
  boundaries, not capability claims; refresh them from the status card and live
  tracker before reporting current state.
- Exact `ForcedSchedule` files are bounded Lab replay evidence, not production
  scheduler control, authenticity proof, or automatic minimization.
- Support classes come from live implementation and proof: default production,
  optional production, experimental/guarded, compat-only, test/fuzz-only, or
  planned. Do not promote a class from prose alone.

Inside Asupersync, follow live `AGENTS.md` and `TESTING_FOR_AGENTS.md`; work on
`main`, do not delete files without permission, and preserve the v0.4.3 public
API and documented behavior throughout 0.4.x. Classify proof through
`artifacts/proof_lane_manifest_v1.json` and
`artifacts/proof_status_snapshot_v1.json`: manifest = command/claim/envelope;
snapshot = freshness/blockers; only a terminal receipt proves execution.
Preserve build id, target/artifact roots, and dirty-tree state. Use Beads and
CASS for rationale, corroborated by tagged source and focused evidence.

ATP performance claims require live ledger/matrix artifacts, tuned rsync,
release `atp`, symmetric crypto, caps, and SHA/tamper checks. A cell proves only
its scope; compilation or `sha_ok` is not a benchmark win.

## Skill Validation

After editing this package run:

```bash
./scripts/validate.sh
ASUPERSYNC_SOURCE_ROOT=/path/to/asupersync ./scripts/validate.sh
```

The second form also validates referenced repository paths and release-sensitive
source anchors. It does not compile Asupersync or replace RCH proof.
