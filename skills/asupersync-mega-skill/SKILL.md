---
name: asupersync-mega-skill
description: >-
  Replace Tokio Rust stacks with Asupersync. Use when migrating tokio/axum/hyper/tonic apps, designing native Cx/region-based services, or debugging Asupersync internals.
---

# Asupersync Mega Skill

Asupersync is a spec-first, cancel-correct, capability-secure async runtime for Rust. Not a Tokio wrapper -- a complete replacement with stronger guarantees around structured concurrency, obligation tracking, deterministic testing, and capability security.

This skill is primarily for agents integrating Asupersync into other projects or extracting maximum architectural leverage from it in greenfield systems. It also covers repo-internal work when that is the actual task.

For codebase orientation, types, module map, and workspace layout see [SOURCE-MAP.md](references/SOURCE-MAP.md).
For repo-internal testing choices, use the compact agent router at
[`../../TESTING_FOR_AGENTS.md`](../../TESTING_FOR_AGENTS.md) before drilling into
`TESTING.md`.

## Quick Orient

Minimal bootstrap:

```rust
use asupersync::runtime::RuntimeBuilder;

fn main() -> Result<(), asupersync::Error> {
    let rt = RuntimeBuilder::current_thread().build()?;
    rt.block_on(async {
        let cx = asupersync::Cx::for_request();
        asupersync::proc_macros::scope!(cx, {
            cx.trace("running");
            asupersync::Outcome::ok(())
        });
    });
    Ok(())
}
```

This is the smallest runnable seam, not the recommended production architecture. Do not build serious services around `Cx::for_request()` plus `block_on(...)` alone; prefer runtime-managed contexts, request/call regions at service boundaries, and graduate to `AppSpec` + supervision when the topology becomes long-lived.

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
- Add `cx.checkpoint()` in loops, retry bodies, long handlers, and shutdown-sensitive code.
- Prefer cancel-aware primitives and two-phase effects.
- Use deterministic tests as part of normal development, not as optional polish.
- Treat `Cx::for_testing()` as test-only. `Cx::for_request()` is a convenience seam, not your whole architecture.
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
- App code: `Cx`, `Scope`
- Tests: `test_utils::{run_test, run_test_with_cx}`, `LabRuntime`, `LabConfig`
- Service boundaries: `web::request_region::{RequestRegion, RequestContext}`, `grpc::CallContext::with_cx(...)`
- Higher-level apps: `app::AppSpec`, `actor`, `gen_server`, `supervision`, `spork`

Start with RuntimeBuilder + Cx + Scope. Graduate to AppSpec + supervision when you need restart policy, named workers, or explicit application topology.

Macro guidance: `scope!` is useful. Manual APIs are still the safest authoritative path. Do not assume proc-macro surfaces are automatically the best default path for every task.

Agent-native v2 entry points:

- Public API navigation: `artifacts/api_surface_map_v1.json` once br-asupersync-agent-native-dx-zxqaqs.1 lands
- Error remediation lookup: `docs/error_codes/registry.json` once br-asupersync-agent-native-dx-zxqaqs.2 lands
- Testing router: [`../../TESTING_FOR_AGENTS.md`](../../TESTING_FOR_AGENTS.md)
- Full testing contract: [`../../TESTING.md`](../../TESTING.md)
- Mandatory repo rules: [`../../AGENTS.md`](../../AGENTS.md)

## Standard Workflow

- For brownfield work, run the read-only planner first: `python3 scripts/migration_readiness_planner.py --project-root /path/to/rust/project --output-root target/migration-readiness`.
- Use `python3 scripts/migration_readiness_planner.py --list`, `--dry-run`, and `--execute --output-root "${TMPDIR:-/tmp}/asupersync_migration_planner_e2e"` to inspect deterministic fixture scenarios before touching a target project.
- Read `summary.final_verdict`, `proof_pack.proof_commands`, `semantic_map.recommendations`, and `operator_report.phase_plan` before choosing the first migration edit.
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
| Plan a brownfield migration before edits | Run `scripts/migration_readiness_planner.py` → [BROWNFIELD-MIGRATION](references/BROWNFIELD-MIGRATION.md) → [TOKIO-MAPPING](references/TOKIO-MAPPING.md) |
| Migrate a Tokio HTTP/gRPC service | [BROWNFIELD-MIGRATION](references/BROWNFIELD-MIGRATION.md) → [TOKIO-MAPPING](references/TOKIO-MAPPING.md) → [WEB-GRPC-HTTP](references/WEB-GRPC-HTTP.md) |
| Build a new service from scratch | [NATIVE-GREENFIELD](references/NATIVE-GREENFIELD.md) → [GREENFIELD-PATTERNS](references/GREENFIELD-PATTERNS.md) |
| Get more than parity and maximize Asupersync leverage | [LEVERAGE-PLAYBOOK](references/LEVERAGE-PLAYBOOK.md) → [BUDGET-OUTCOME-CAPABILITIES](references/BUDGET-OUTCOME-CAPABILITIES.md) → [SUPERVISION-OTP](references/SUPERVISION-OTP.md) → [TESTING-FORENSICS](references/TESTING-FORENSICS.md) |
| Design a supervised long-lived service | [SUPERVISION-OTP](references/SUPERVISION-OTP.md) → [LEVERAGE-PLAYBOOK](references/LEVERAGE-PLAYBOOK.md) |
| Choose the right channel/sync/combinator | [PRIMITIVES-AND-ORCHESTRATION-CHOOSER](references/PRIMITIVES-AND-ORCHESTRATION-CHOOSER.md) |
| Add deterministic tests inside this repo | [`../../TESTING_FOR_AGENTS.md`](../../TESTING_FOR_AGENTS.md) → [TESTING-FORENSICS](references/TESTING-FORENSICS.md) → [LAB-TRACE-DPOR](references/LAB-TRACE-DPOR.md) |
| Add deterministic tests in a consuming project | [TESTING-FORENSICS](references/TESTING-FORENSICS.md) → [LAB-TRACE-DPOR](references/LAB-TRACE-DPOR.md) |
| Debug a runtime error | [ERROR-TAXONOMY](references/ERROR-TAXONOMY.md) → [TROUBLESHOOTING](references/TROUBLESHOOTING.md) |
| Tune runtime performance | [RUNTIME-CONTROLS](references/RUNTIME-CONTROLS.md) → [SCHEDULER-INTERNALS](references/SCHEDULER-INTERNALS.md) |
| See what to lead with vs use only when required | [STACK-SURFACES](references/STACK-SURFACES.md) → [TOKIO-REPLACEMENT-MATRIX](references/TOKIO-REPLACEMENT-MATRIX.md) |
| Work inside the Asupersync repo | [REPO-CONTRIBUTOR-GUIDE](references/REPO-CONTRIBUTOR-GUIDE.md) → [SOURCE-MAP](references/SOURCE-MAP.md) |

### All References

**Integration and Migration**

- Leverage playbook: [LEVERAGE-PLAYBOOK.md](references/LEVERAGE-PLAYBOOK.md)
- Budgets, outcomes, capabilities: [BUDGET-OUTCOME-CAPABILITIES.md](references/BUDGET-OUTCOME-CAPABILITIES.md)
- Native greenfield: [NATIVE-GREENFIELD.md](references/NATIVE-GREENFIELD.md)
- Greenfield patterns: [GREENFIELD-PATTERNS.md](references/GREENFIELD-PATTERNS.md)
- Brownfield migration: [BROWNFIELD-MIGRATION.md](references/BROWNFIELD-MIGRATION.md)
- Tokio mapping: [TOKIO-MAPPING.md](references/TOKIO-MAPPING.md)
- Tokio replacement matrix: [TOKIO-REPLACEMENT-MATRIX.md](references/TOKIO-REPLACEMENT-MATRIX.md)
- Compat boundary rules: [COMPAT-BOUNDARY.md](references/COMPAT-BOUNDARY.md)
- Compat bridge recipes: [COMPAT-BRIDGE.md](references/COMPAT-BRIDGE.md)
- Adoption lanes: [ADOPTION-LANES.md](references/ADOPTION-LANES.md)
- Anti-patterns: [ANTI-PATTERNS.md](references/ANTI-PATTERNS.md)

**Architecture and Primitives**

- Primitive and orchestration chooser: [PRIMITIVES-AND-ORCHESTRATION-CHOOSER.md](references/PRIMITIVES-AND-ORCHESTRATION-CHOOSER.md)
- Channel and sync internals: [CHANNELS-SYNC-INTERNALS.md](references/CHANNELS-SYNC-INTERNALS.md)
- Performance and scheduling: [PERFORMANCE-AND-SCHEDULING.md](references/PERFORMANCE-AND-SCHEDULING.md)
- Scheduler internals: [SCHEDULER-INTERNALS.md](references/SCHEDULER-INTERNALS.md)
- Lock ordering: [LOCK-ORDERING.md](references/LOCK-ORDERING.md)
- Advanced features: [ADVANCED-FEATURES.md](references/ADVANCED-FEATURES.md)
- Runtime controls and diagnostics: [RUNTIME-CONTROLS.md](references/RUNTIME-CONTROLS.md)
- Supervision and OTP: [SUPERVISION-OTP.md](references/SUPERVISION-OTP.md)

**Networking and Services**

- Networking and protocol stack: [NETWORKING-PROTOCOL-STACK.md](references/NETWORKING-PROTOCOL-STACK.md)
- Web and gRPC: [WEB-GRPC-HTTP.md](references/WEB-GRPC-HTTP.md)
- Database, messaging, fs, process: [DB-MESSAGING-FS-PROCESS.md](references/DB-MESSAGING-FS-PROCESS.md)
- Distributed execution: [DISTRIBUTED-AND-RIGOR.md](references/DISTRIBUTED-AND-RIGOR.md)
- RaptorQ and distributed snapshots: [RAPTORQ-DISTRIBUTED.md](references/RAPTORQ-DISTRIBUTED.md)

**Testing and Diagnostics**

- Testing and forensics: [TESTING-FORENSICS.md](references/TESTING-FORENSICS.md)
- Lab runtime, DPOR, traces: [LAB-TRACE-DPOR.md](references/LAB-TRACE-DPOR.md)
- Mathematical foundations: [MATHEMATICAL-FOUNDATIONS.md](references/MATHEMATICAL-FOUNDATIONS.md)
- Observability and forensics: [OBSERVABILITY-FORENSICS.md](references/OBSERVABILITY-FORENSICS.md)
- Error taxonomy: [ERROR-TAXONOMY.md](references/ERROR-TAXONOMY.md)
- Troubleshooting: [TROUBLESHOOTING.md](references/TROUBLESHOOTING.md)

**Codebase Navigation**

- Source map, module map, types, workspace: [SOURCE-MAP.md](references/SOURCE-MAP.md)
- Stack surface guidance: [STACK-SURFACES.md](references/STACK-SURFACES.md)
- Browser / WASM: [BROWSER-WASM.md](references/BROWSER-WASM.md)
- Browser / React / Next: [BROWSER-FRAMEWORKS.md](references/BROWSER-FRAMEWORKS.md)
- Repo contributor guide: [REPO-CONTRIBUTOR-GUIDE.md](references/REPO-CONTRIBUTOR-GUIDE.md)

## Validation

When changing code:

- run the host project's normal formatter, compiler, lint, and test suite,
- add deterministic integration tests for the migrated path,
- verify cancellation, shutdown, and resource-release behavior,
- verify that no core domain code still depends on Tokio if the goal is full native adoption.

If working inside the Asupersync repo itself, see [REPO-CONTRIBUTOR-GUIDE.md](references/REPO-CONTRIBUTOR-GUIDE.md) for mandatory compiler checks and testing discipline.

## Operating Rules

- When forced to choose between "minimal code churn" and "native Asupersync semantics", choose the latter unless the task explicitly calls for a temporary boundary bridge.
- **Forbidden crates** in core: `tokio`, `hyper`, `reqwest`, `axum`, `async-std`, `smol`.
- Inside the Asupersync repo: follow AGENTS.md. Never delete files without permission. Branch is `main`, never `master`.
