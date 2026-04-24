# Reality Check - 2026-04-24

Bead: `asupersync-ao9m8l`

## Verdict

The README roadmap is mostly aligned with the current tree.

- Phases 0-5 are backed by real implementation files and executable evidence; they do not read as aspirational only.
- Phase 6 is correctly marked `Continuous`, not `Complete`.
- The main nuance is support-class fragmentation on browser and adapter surfaces: some lanes are fully supported, some are preview-public, some are guarded canary-only, and some are intentionally bridge-only or fail-closed.
- This run tightened the README FAQ wording so the broad "fully implemented" statement is not misread as blanket GA across every adapter or browser boundary.

## Roadmap Crosswalk

| Phase | README claim | Concrete implementation evidence | Executable evidence | Assessment |
|---|---|---|---|---|
| 0 | Single-thread deterministic kernel | `src/lab/runtime.rs`, `src/cx/`, `src/obligation/` | `tests/conformance_no_leak_invariant.rs`, `tests/refinement_conformance.rs` | Supported |
| 1 | Parallel scheduler + region heap | `src/runtime/scheduler/three_lane.rs`, `src/runtime/sharded_state.rs` | inline scheduler tests in `src/runtime/scheduler/three_lane.rs` | Supported |
| 2 | I/O integration (epoll, io_uring, TCP, HTTP, TLS) | `src/runtime/reactor/epoll.rs`, `src/runtime/reactor/uring.rs`, `src/http/`, `src/tls/` | `tests/io_e2e.rs`, `tests/net_tcp.rs`, `tests/http_verification.rs` | Supported |
| 3 | Actors + supervision | `src/actor.rs`, `src/gen_server.rs`, `src/supervision.rs` | `tests/supervision_regression.rs` | Supported |
| 4 | Distributed structured concurrency | `src/distributed/bridge.rs`, `src/distributed/snapshot.rs`, `src/trace/distributed/` | `tests/distributed_trace_remote_invariants.rs` | Supported |
| 5 | DPOR + TLA+ tooling | `src/trace/dpor.rs`, `formal/tla/Asupersync.tla`, `formal/lean/coverage/invariant_theorem_test_link_map.json` | `tests/dpor_exploration.rs`, `tests/semantic_gate_evaluation.rs`, `tests/lean_invariant_theorem_test_link_map.rs` | Supported |
| 6 | Hardening, policy gates, and adapter surface expansion | `.github/workflows/ci.yml`, `.github/workflows/publish.yml`, `scripts/check_wasm_optimization_policy.py`, `scripts/check_wasm_dependency_policy.py`, `scripts/check_security_release_gate.py`, `docs/integration.md`, `docs/WASM.md`, `docs/wasm_release_channel_strategy.md`, `src/runtime/builder.rs`, `packages/browser/src/index.ts`, `packages/next/src/index.ts` | `tests/wasm_browser_feasibility_matrix.rs`, `tests/wasm_js_exports_coverage_contract.rs`, `tests/wasm_supply_chain_controls.rs`, `tests/wasm_ga_readiness_review_board_checklist.rs`, `tests/wasm_rust_browser_example_contract.rs` | In progress, correctly labeled continuous |

## Phase 6 Reality

The repo does have real Phase 6 machinery. The gate and adapter story is not just prose:

- CI runs policy checks in `.github/workflows/ci.yml`.
- Publish flow runs gate and packaging steps in `.github/workflows/publish.yml`.
- Browser and adapter support classes are enforced in `docs/integration.md`, `docs/WASM.md`, `src/runtime/builder.rs`, `packages/browser/src/index.ts`, and `packages/next/src/index.ts`.
- Contract tests lock the support matrix and fail-closed behavior in `tests/wasm_browser_feasibility_matrix.rs`, `tests/wasm_js_exports_coverage_contract.rs`, `tests/wasm_supply_chain_controls.rs`, and `tests/wasm_ga_readiness_review_board_checklist.rs`.

What is not true is "all adapter surfaces are equally shipped." The current support classes are intentionally mixed:

| Surface | Current posture | Evidence |
|---|---|---|
| Browser main thread, dedicated worker, React client tree, Next client component | supported | `docs/integration.md`, `docs/WASM.md`, `tests/wasm_browser_feasibility_matrix.rs` |
| Rust-authored browser consumer via `RuntimeBuilder::browser()` | preview public lane | `docs/WASM.md`, `src/runtime/builder.rs`, `tests/wasm_rust_browser_example_contract.rs` |
| Service-worker broker helpers, shared-worker coordinator helpers, guarded browser extras | guarded / canary-only / fail-closed direct runtime | `docs/wasm_release_channel_strategy.md`, `packages/browser/src/index.ts`, `tests/wasm_browser_feasibility_matrix.rs`, `tests/wasm_service_worker_broker_contract.rs`, `tests/wasm_shared_worker_tenancy_lifecycle_contract.rs` |
| React SSR, Next server components, Next route handlers, Next edge runtime | bridge-only | `docs/integration.md`, `packages/next/src/index.ts`, `tests/wasm_js_exports_coverage_contract.rs` |

That means the roadmap table itself is honest, but readers can still overread the FAQ language if they do not also consult the support matrices.

## Gap Assessment

I did not find evidence that Phases 0-5 are materially overstated in the README.

I did find one wording gap worth fixing directly:

- The README FAQ previously said the project had a "fully implemented runtime surface" without immediately reminding readers that browser and adapter surfaces still carry mixed Phase 6 support classes.

That gap is fixed in this run by updating the README FAQ to point readers at the live support matrices in `docs/integration.md` and `docs/WASM.md`.

## Follow-up Beads

None created in this run.

- I did not find a larger unresolved README overstatement that justified a separate follow-up bead after the wording fix.
- If a future sweep wants to go beyond README scope, the next useful audit would be doc-to-workflow drift inside Phase 6 release automation, not a roadmap-table mismatch.
