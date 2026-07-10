---
name: asupersync-mega-skill
description: >-
  Replace Tokio stacks with Asupersync. Use when migrating Tokio/axum/hyper/tonic apps, designing Cx/region services, debugging internals, or classifying proof/ATP evidence.
---

# Asupersync Mega Skill

Asupersync is a spec-first, cancel-correct, capability-secure async runtime for Rust. Not a Tokio wrapper -- a broad, support-class-scoped replacement for native Asupersync designs, with stronger guarantees around structured concurrency, obligation tracking, deterministic testing, and capability security. Exact adapter, web, browser, protocol, and benchmark parity must still be checked against live docs and proof artifacts.

This skill is primarily for agents integrating Asupersync into other projects or extracting maximum architectural leverage from it in greenfield systems. It also covers repo-internal work when that is the actual task.

For codebase orientation, types, module map, and workspace layout see [SOURCE-MAP.md](references/SOURCE-MAP.md).

## Quick Orient

Minimal bootstrap:

```rust
use asupersync::{Cx, Error};
use asupersync::runtime::RuntimeBuilder;

async fn main_task(cx: &Cx) -> Result<(), Error> {
    cx.trace("running");
    cx.checkpoint()?;
    Ok(())
}

fn main() -> Result<(), Error> {
    let runtime = RuntimeBuilder::current_thread().build()?;
    let result = runtime.block_on(runtime.handle().spawn(async {
        let cx = Cx::current().expect("runtime task Cx");
        main_task(&cx).await
    }));
    result?;
    Ok(())
}
```

This is the current production teaching seam: `RuntimeBuilder` creates the
runtime, `block_on` installs an ambient runtime context, runtime-spawned tasks
run with a runtime-owned `Cx`, and app code receives `&Cx`. Do not teach
`Cx::for_request()` as production bootstrap; it is test/internal-harness
material. For services, prefer request/call regions at boundaries, then
graduate to `AppSpec` + supervision when the topology is long-lived. For
admission-sensitive bootstrap, use `try_spawn` / `try_spawn_with_cx` and handle
`SpawnError` explicitly.

Where to focus first:

- Lead with core runtime, `Cx`/`Scope`, cancellation, obligations, channels, sync, time, lab/DPOR, and observability
- For ordinary services, build next on native `service`, `web`, `grpc`, database, and supervision surfaces
- Treat Browser Edition, QUIC/H3, messaging, remote/distributed, and RaptorQ as requirement-driven lanes, not default starting points

Default recommendation order for most real projects:

- core runtime + `Cx` + `Scope`
- native `service` / `web` / `grpc` boundaries
- native database and actor/supervision surfaces as needed
- deterministic tests and diagnostics from the start

Do **not** lead with Browser Edition, QUIC/H3, messaging, remote/distributed, or RaptorQ unless the target project explicitly needs those capabilities.

Full surface guidance: [STACK-SURFACES.md](references/STACK-SURFACES.md).

## Start Here

Choose one lane before touching code:

1. **Native greenfield**
   Build directly on `RuntimeBuilder`, `Cx`, `Scope`, `LabRuntime`, and optional `AppSpec`.
2. **Brownfield native migration**
   Rewrite your app's async seams around `&Cx`, region-owned tasks, cancel-aware primitives, and deterministic tests.
   For serious migrations, run the repo's read-only migration readiness planner
   and use its verdict, proof commands, semantic recommendations, and operator
   phase plan as inputs rather than treating `cargo tree` grep output as a plan.
3. **Boundary interop**
   Use `asupersync-tokio-compat` only for crates you cannot remove yet. Keep Tokio out of core business logic.

Default rule:

- prefer native Asupersync surfaces,
- use compat only as a quarantine boundary,
- plan to remove compat once the stubborn dependency is gone.

## Non-Negotiables

- Do **not** treat Asupersync as an executor swap.
- Put `&Cx` first in async APIs you control.
- Use `Scope` and child regions for owned work. Avoid detached background tasks.
- Use `Cx::spawn` / `Cx::spawn_in` for ordinary region-owned task creation.
  `Scope::spawn_registered` is a lower-level boot/test path for callers already
  holding `&mut RuntimeState`.
- Add `cx.checkpoint()` in loops, retry bodies, long handlers, and shutdown-sensitive code.
- Prefer cancel-aware primitives and two-phase effects.
- Use deterministic tests as part of normal development, not as optional polish.
- Treat `Cx::for_testing()` and `Cx::for_request()` as test/internal harness
  paths, not production architecture.
- Keep Tokio and Tokio-only crates behind explicit adapter modules if you must keep them at all.

## Leverage, Not Just Migration

If the target system is doing real work, do not stop after "the code compiles on Asupersync."

- `Budget`, `Outcome`, and capability narrowing are part of the application's semantic contract, not optional polish. See [BUDGET-OUTCOME-CAPABILITIES.md](references/BUDGET-OUTCOME-CAPABILITIES.md).
- Runtime controls are part of the architecture. See [RUNTIME-CONTROLS.md](references/RUNTIME-CONTROLS.md).
- Long-lived state belongs in supervised structures. See [SUPERVISION-OTP.md](references/SUPERVISION-OTP.md).
- Treat the lab runtime and operator diagnostics as part of the normal development loop. See [OBSERVABILITY-FORENSICS.md](references/OBSERVABILITY-FORENSICS.md).
- Prefer native combinators over ad hoc `select!`-style orchestration. See [ADVANCED-FEATURES.md](references/ADVANCED-FEATURES.md).
- Primitive choice and scheduler cooperation materially affect leverage. See [PRIMITIVES-AND-ORCHESTRATION-CHOOSER.md](references/PRIMITIVES-AND-ORCHESTRATION-CHOOSER.md) and [PERFORMANCE-AND-SCHEDULING.md](references/PERFORMANCE-AND-SCHEDULING.md).

## Canonical Spine

- Bootstrap: `runtime::RuntimeBuilder`, `Runtime`, `RuntimeHandle`
- App code: `Cx`, `Cx::spawn`, `Cx::spawn_in`, `Scope` child regions
- Tests: `test_utils::{run_test, run_test_with_cx}`, `LabRuntime`, `LabConfig`,
  `LabRunReport`
- Service boundaries: `web::request_region::{RequestRegion, RequestContext}`, `grpc::CallContext::with_cx(...)`
- Higher-level apps: `app::AppSpec`, `actor`, `gen_server`, `supervision`, `spork`

Start with RuntimeBuilder + Cx + Scope. Graduate to AppSpec + supervision when you need restart policy, named workers, or explicit application topology.

Macro guidance: `scope!` binds the current-region scope; it does not create a
fresh child-region boundary. `spawn!` needs runtime state. Manual APIs are still
the safest authoritative path when semantics matter.

Current generated API-map anchors to remember:

- outbound HTTP: `http::Client` / `http::HttpClient` fluent request builders,
- deterministic lab: `lab::ScenarioRunner` and `lab::CancellationInjector`,
- web metadata and middleware: `web::Router::routes`, `web::RouteInfo`,
  `web::middleware::{CatchPanicLayer, CompressionLayer, RequestTraceLayer,
  TimeoutLayer}`, plus `web::Router::layer`,
- ATP/daemon, RaptorQ, observability, Spork, `runtime::RuntimeBuilder`, and
  `Cx + Scope`.

Refresh these from `/data/projects/asupersync/artifacts/api_surface_map_v1.json`
before making precise public-surface claims.

## Standard Workflow

- Inventory all `tokio::*`, `tokio-util`, `hyper`, `axum`, `tonic`, `reqwest`, `sqlx`, `quinn`, `h3`, `rdkafka`, and related dependencies.
- Classify each dependency as: native replacement, compat holdout, or deliberate workaround.
- Replace runtime bootstrap first.
- Thread `&Cx` through your own async APIs.
- Replace detached spawning with region-owned work.
- Replace sync/time/net/io/channel/web/db/messaging surfaces domain by domain.
- Add deterministic tests while migrating, not after.
- Remove compat boundaries as soon as the underlying dependency no longer needs them.

## Reference Index

### Quick Router: Start Here For Your Task

| I need to... | Read (in order) |
|---|---|
| Migrate a Tokio HTTP/gRPC service | [BROWNFIELD-MIGRATION](references/BROWNFIELD-MIGRATION.md) → [TOKIO-MAPPING](references/TOKIO-MAPPING.md) → [WEB-GRPC-HTTP](references/WEB-GRPC-HTTP.md) |
| Build a new service from scratch | [NATIVE-GREENFIELD](references/NATIVE-GREENFIELD.md) → [GREENFIELD-PATTERNS](references/GREENFIELD-PATTERNS.md) |
| Get more than parity and maximize Asupersync leverage | [LEVERAGE-PLAYBOOK](references/LEVERAGE-PLAYBOOK.md) → [BUDGET-OUTCOME-CAPABILITIES](references/BUDGET-OUTCOME-CAPABILITIES.md) → [SUPERVISION-OTP](references/SUPERVISION-OTP.md) → [TESTING-FORENSICS](references/TESTING-FORENSICS.md) |
| Design a supervised long-lived service | [SUPERVISION-OTP](references/SUPERVISION-OTP.md) → [LEVERAGE-PLAYBOOK](references/LEVERAGE-PLAYBOOK.md) |
| Choose the right channel/sync/combinator | [PRIMITIVES-AND-ORCHESTRATION-CHOOSER](references/PRIMITIVES-AND-ORCHESTRATION-CHOOSER.md) |
| Add deterministic tests | [TESTING-FORENSICS](references/TESTING-FORENSICS.md) → [LAB-TRACE-DPOR](references/LAB-TRACE-DPOR.md) |
| Assess migration readiness with the repo planner | [REPO-CONTRIBUTOR-GUIDE](references/REPO-CONTRIBUTOR-GUIDE.md) → live `scripts/migration_readiness_planner.py` output |
| Debug a runtime error | [ERROR-TAXONOMY](references/ERROR-TAXONOMY.md) → [TROUBLESHOOTING](references/TROUBLESHOOTING.md) |
| Tune runtime performance | [RUNTIME-CONTROLS](references/RUNTIME-CONTROLS.md) → [SCHEDULER-INTERNALS](references/SCHEDULER-INTERNALS.md) |
| See what to lead with vs use only when required | [STACK-SURFACES](references/STACK-SURFACES.md) → [TOKIO-REPLACEMENT-MATRIX](references/TOKIO-REPLACEMENT-MATRIX.md) |
| Work inside the Asupersync repo | [REPO-CONTRIBUTOR-GUIDE](references/REPO-CONTRIBUTOR-GUIDE.md) → [SOURCE-MAP](references/SOURCE-MAP.md) |
| Move bulk files / pull one object from many donors (ATP bonded transfer, `atp bond-pull` + `BondedTransfer` SDK) | [RAPTORQ-DISTRIBUTED](references/RAPTORQ-DISTRIBUTED.md) → [NETWORKING-PROTOCOL-STACK](references/NETWORKING-PROTOCOL-STACK.md) |

Other focused references live under `references/` for adoption lanes, compat
bridges, anti-patterns, budgets/outcomes/capabilities, lock ordering,
performance, supervision, networking, browser frameworks, distributed rigor,
observability, and troubleshooting. Use [SOURCE-MAP.md](references/SOURCE-MAP.md)
when you need the full codebase navigation map.

Specialized refs: [ADOPTION-LANES](references/ADOPTION-LANES.md),
[COMPAT-BOUNDARY](references/COMPAT-BOUNDARY.md),
[COMPAT-BRIDGE](references/COMPAT-BRIDGE.md),
[ANTI-PATTERNS](references/ANTI-PATTERNS.md),
[CHANNELS-SYNC-INTERNALS](references/CHANNELS-SYNC-INTERNALS.md),
[LOCK-ORDERING](references/LOCK-ORDERING.md),
[NETWORKING-PROTOCOL-STACK](references/NETWORKING-PROTOCOL-STACK.md),
[DB-MESSAGING-FS-PROCESS](references/DB-MESSAGING-FS-PROCESS.md),
[DISTRIBUTED-AND-RIGOR](references/DISTRIBUTED-AND-RIGOR.md),
[RAPTORQ-DISTRIBUTED](references/RAPTORQ-DISTRIBUTED.md),
[MATHEMATICAL-FOUNDATIONS](references/MATHEMATICAL-FOUNDATIONS.md),
[BROWSER-WASM](references/BROWSER-WASM.md), and
[BROWSER-FRAMEWORKS](references/BROWSER-FRAMEWORKS.md).

## Validation

When changing code:

- run the host project's normal formatter, compiler, lint, and test suite,
- add deterministic integration tests for the migrated path,
- verify cancellation, shutdown, and resource-release behavior,
- verify that no core domain code still depends on Tokio if the goal is full native adoption.

If working inside the Asupersync repo itself, read live `TESTING_FOR_AGENTS.md`
before choosing proof. Use `rch exec -- env CARGO_TARGET_DIR=...` for
remote-required lanes, preserve the RCH build id / target dir / artifact root /
dirty-tree state in handoff, and do not turn a local fallback into green proof
for a lane whose manifest says remote proof is required. See
[REPO-CONTRIBUTOR-GUIDE.md](references/REPO-CONTRIBUTOR-GUIDE.md) for mandatory
compiler checks and testing discipline.

## Operating Rules

- When forced to choose between "minimal code churn" and "native Asupersync semantics", choose the latter unless the task explicitly calls for a temporary boundary bridge.
- **Forbidden crates** in runtime/core `src/`: `tokio`, `hyper`, `reqwest`,
  `axum`, `tower` except scoped adapter feature paths, `async-std`, and `smol`.
  Satellite, test, fuzz, benchmark, and compat carve-outs must stay documented
  and proof-checked.
- Inside the Asupersync repo: follow live `AGENTS.md`. Never delete files
  without permission. Work only on `main`; do not introduce legacy-branch
  references except the exact required mirror command, if still present there.
- Inside the Asupersync repo, trust `AGENTS.md`, `README.md`,
  `CHANGELOG.md`, `artifacts/api_surface_map_v1.json`, proof-lane manifests,
  proof-status snapshots, and benchmark matrix artifacts over remembered API
  shapes.
- Classify every repo-internal proof through
  `artifacts/proof_lane_manifest_v1.json` and
  `artifacts/proof_status_snapshot_v1.json` before making any "green" claim.
  A broad `check`/`clippy` result is not enough when a Phase 6, benchmark,
  golden, flamegraph, or proof-note artifact gate applies.
- ATP benchmark claims require tuned-rsync, release-`atp`, crypto-symmetric,
  rate-capped, SHA/tamper-checked evidence. A single current cell can support a
  scoped regression claim; headline "beats rsync" claims need whole-matrix
  evidence. Compile success or `sha_ok` alone is not a win.

## Evidence-First Operator Cards

Use these compact operators for volatile repo-internal claims:

- **Live-doc refresh**: before any Asupersync-internal API, proof, or ATP claim,
  read live `AGENTS.md`, `README.md`, `TESTING_FOR_AGENTS.md`, `CHANGELOG.md`,
  the relevant source, and the relevant artifact/ledger rows. Do not rely on
  this skill's dated examples as authority.
- **Claim gate**: classify the evidence as `banked`, `scoped-cell-only`,
  `parity`, `correct-but-slower`, `candidate`, `stale`, `blocked`, or
  `failed`. Say the no-claim boundary in the same breath as the positive claim.
- **ATP gate**: require tuned rsync, release `atp`, crypto-symmetric setup,
  rate caps, SHA/tamper fail-closed checks, and current matrix/ledger evidence.
  `sha_ok`, `cargo check`, or one favorable stale cell is not a benchmark win.
- **Proof-lane classifier**: map each repo-internal proof to
  `artifacts/proof_lane_manifest_v1.json` and
  `artifacts/proof_status_snapshot_v1.json`; preserve RCH build id, target dir,
  artifact path, and dirty-tree state for cited proof.
- **Migration planner router**: for downstream migrations, run the read-only
  migration readiness planner when deciding whether/how to migrate; treat
  `scripts/audit-target.sh` as quick inventory only.

Current ATP evidence snapshot (refresh before citing): encrypted QUIC
`MATRIX-205/206/210` has a measured `50M/good/encrypted` win and
`5G/perfect/encrypted` correctness unblock, but no banked encrypted-large or
full-matrix win; `500M/perfect/encrypted`, `50M/bad/encrypted`, and 5G
receiver RSS remain open. RQ/nocrypto `MATRIX-207/208/209` banked exactly one
new positive cell: `500M/broken/nocrypto` atp median 564.77s, sha-ok 3/3 plus
a confirming fourth rep, versus tuned rsync median 574.46s. `MATRIX-210`
QUIC drain-cap tuning and `MATRIX-211` packed-member commit batching are
implementation landings, not banked benchmark wins without fresh matrix proof.
