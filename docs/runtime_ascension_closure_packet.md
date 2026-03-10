# Runtime Ascension Closure Packet and Launch Doctrine

Owner bead: `asupersync-1508v.10.6`  
Prep lineage: `asupersync-1508v.10.6.1`, `asupersync-1508v.10.6.2`  
Parent epic: `asupersync-1508v.10`

## Purpose

This packet is the truth-first closure scaffold for the runtime ascension
program. Its job is not to market the program. Its job is to say what is
actually evidenced, what is still experimental, what remains blocked, and
which downgrade path keeps operators on the conservative surface when a track
is not ready.

## Contract Artifacts

1. Canonical artifact: `artifacts/runtime_ascension_closure_packet_v1.json`
2. Smoke runner: `scripts/run_runtime_ascension_closure_smoke.sh`
3. Invariant suite: `tests/runtime_ascension_closure_packet_contract.rs`

Runner behavior is part of the contract: smoke scenarios execute from the
repository root even when the script is invoked from another caller CWD, and
the emitted manifests/report retain command provenance (`invoked_from`,
`command`, `command_workdir`, `log_file`, `summary_file`).

## Execution State

| Field | Value |
|-------|-------|
| Current phase | `active_closure_execution` |
| Packet mode | `preparatory` |
| Current verdict | `NO_GO` |
| Remaining blocker bead(s) | `none` |
| Completed milestones | closure packet contract scaffold, evidence registry command matrix, transport validation closure alignment |
| Immediate next actions | run smoke bundle in execute mode, refresh comparative demo evidence against the closed transport validation surface, re-evaluate launch verdict without promoting AA-08 beyond opt-in |

## Current Decision Snapshot

| Surface | Verdict | Reason |
|---------|---------|--------|
| AA core-stack launch packet | **NO_GO** | This packet is preparatory. It assembles the closure doctrine, but closure-grade comparative demos and final sign-off are not complete. |
| Default-ready core stack (`AA-01/02/03/04/05/06/07/09`) | **CONDITIONAL** | Core contract artifacts exist and `CX-FULL-STACK` is classified as supported, but this packet does not yet promote the stack to shipped-by-default status. |
| Transport experiments (`AA-08`) | **EXPERIMENTAL** | `asupersync-1508v.8.6` is closed and transport validation evidence is available, but the surface remains opt-in and excluded from default-ready launch doctrine. |

Upstream closure state captured by this packet:

- closed evidence fabric beads:
  - `asupersync-1508v.10.5`
  - `asupersync-1508v.10.7`
  - `asupersync-1508v.5.6`
  - `asupersync-1508v.6.6`
  - `asupersync-1508v.8.6`
- no remaining upstream blocker beads are open at packet refresh time.

Delivery checklist for `asupersync-1508v.10.6`:

1. [x] Establish closure packet contract scaffold and evidence registry linkage.
2. [x] Add command-id matrix that maps every promoted claim to deterministic rerun commands.
3. [x] Refresh comparative demo posture after `asupersync-1508v.8.6` closure.
4. [ ] Promote packet verdict from `NO_GO` to `GO` only after refreshed evidence and doctrine checks.

## Comparative Demo Matrix

| Demo ID | Conservative baseline | Advanced surface | Current status | Evidence / blocker |
|---------|------------------------|------------------|----------------|--------------------|
| `DEMO-CORE-STACK` | Conservative runtime path with explicit rollback doctrine and no experimental transport | `AA-01/02/03/04/05/06/07/09` composed as `CX-FULL-STACK` | staged | `artifacts/claim_evidence_graph_v1.json`, `artifacts/ci_proof_gates_v1.json`, `artifacts/cross_track_composition_v1.json` |
| `DEMO-STATIC-SAFETY` | Dynamic protocol path remains canonical | `AA-05` typed/static-safety surface | staged | `tests/cap_obligation_compile_fail.rs`, `tests/session_type_obligations.rs`, `docs/integration.md` |
| `DEMO-TRACE-INTELLIGENCE` | Existing replay path without minimization/canonicalization upgrades | `AA-06` replay minimization and inconsistency-debugging surface | staged | `artifacts/replay_minimization_validation_contract_v1.json` |
| `DEMO-TRANSPORT-OPTIN` | Conservative transport behavior only | `AA-08` network-aware transport experiments | staged | `artifacts/transport_frontier_benchmark_v1.json`, `artifacts/cross_track_composition_v1.json`; validation is closed but the surface remains experimental-only |

Interpretation rules:

1. A staged demo is a runnable recipe with evidence pointers, not a ship signal.
2. A blocked demo cannot be presented as launch-ready.
3. Comparative results must always cite their underlying evidence graph or
   validation artifact, not a free-form claim.

## Evidence Citation Registry

Every comparative demo and every promoted surface in this packet maps to a
machine-readable evidence registry entry in
`artifacts/runtime_ascension_closure_packet_v1.json`.

| Scope ID | Kind | Status | Evidence refs | Command IDs / blocker posture |
|---------|------|--------|---------------|-------------------------------|
| `DEMO-CORE-STACK` | demo | staged | `artifacts/claim_evidence_graph_v1.json`, `artifacts/ci_proof_gates_v1.json`, `artifacts/cross_track_composition_v1.json` | `RACP-REFRESH-CLAIM-GRAPH`, `RACP-REFRESH-CI-GATES`, `RACP-REFRESH-COMPOSITION`, `RACP-REFRESH-PACKET` |
| `DEMO-STATIC-SAFETY` | demo | staged | `tests/cap_obligation_compile_fail.rs`, `tests/session_type_obligations.rs`, `docs/integration.md` | `RACP-VERIFY-STATIC-SAFETY-COMPILE-FAIL`, `RACP-VERIFY-STATIC-SAFETY-SESSIONS` |
| `DEMO-TRACE-INTELLIGENCE` | demo | staged | `artifacts/replay_minimization_validation_contract_v1.json`, `artifacts/runtime_workload_corpus_v1.json` | `RACP-VERIFY-TRACE-INTELLIGENCE`, `RACP-VERIFY-WORKLOAD-CORPUS` |
| `DEMO-TRANSPORT-OPTIN` | demo | staged | `artifacts/transport_frontier_benchmark_v1.json`, `artifacts/cross_track_composition_v1.json` | `RACP-VERIFY-TRANSPORT-OPTIN` |
| `AA-CORE-STACK` | surface | default_ready candidate | `artifacts/claim_evidence_graph_v1.json`, `artifacts/ci_proof_gates_v1.json`, `artifacts/cross_track_composition_v1.json`, `artifacts/runtime_ascension_closure_packet_v1.json` | `RACP-REFRESH-CLAIM-GRAPH`, `RACP-REFRESH-CI-GATES`, `RACP-REFRESH-COMPOSITION`, `RACP-REFRESH-PACKET` |
| `AA-TRANSPORT-OPTIN` | surface | experimental | `artifacts/transport_frontier_benchmark_v1.json`, `artifacts/cross_track_composition_v1.json` | `RACP-VERIFY-TRANSPORT-OPTIN` |
| `AA-CLOSURE-PACKET` | surface | blocked | `artifacts/runtime_ascension_closure_packet_v1.json` | `RACP-REFRESH-PACKET`, `RACP-RUN-SMOKE-BUNDLE`; no external bead blocker remains, but final sign-off is still withheld |

Registry rules:

1. Every staged or promoted scope must have at least one concrete command ID.
2. Scopes with open upstream blockers may omit command IDs only when the
   missing command bundle is itself blocked by an open bead and that reason is
   stated explicitly.
3. Headline claims without a registry row are invalid by doctrine.

## Default-Ready vs Experimental Surfaces

### Default-Ready Candidate Set

The only candidate default-ready surface encoded here is the supported
core-stack combination from `artifacts/cross_track_composition_v1.json`:

- `AA-01` Scheduling substrate
- `AA-02` Decision plane
- `AA-03` Controller interference validation
- `AA-04` Bounded latency regression pack
- `AA-05` Static safety surfaces
- `AA-06` Trace intelligence and replay minimization
- `AA-07` Authority sandboxing
- `AA-09` Crash-only recovery

This candidate set is still held below launch approval until the closure-grade
demo packet is executed and refreshed.

### Experimental Set

- `AA-08` transport experiments remain explicitly experimental and opt-in.
- Any combination not named `supported` in
  `artifacts/cross_track_composition_v1.json` is not default-ready.

### Forbidden by Doctrine

- Any launch path that bypasses `artifacts/ci_proof_gates_v1.json`
- Any launch path that lacks a downgrade action
- Any launch path that claims transport graduation without a dedicated
  promotion packet and refreshed transport evidence

## Known Risks, Non-Goals, and Downgrade Paths

| Risk ID | Summary | Current posture | Downgrade path |
|---------|---------|-----------------|----------------|
| `RACP-RISK-01` | Closure packet exists before final comparative evidence refresh | accepted only as prep work | Hold launch at `NO_GO`; rerun packet demos and refresh evidence refs |
| `RACP-RISK-02` | `AA-08` transport validation is closed, but the surface still remains experimental and opt-in | experimental-only | Disable transport experiments and stay on conservative transport path |
| `RACP-RISK-03` | Core-stack artifacts could drift out of sync with claim graph or CI gates | blocking if detected | Treat mismatch as promotion denial and rerun the affected contract suite |

Non-goals of this preparatory packet:

- declaring the ascension program shipped
- collapsing experimental transport into the default stack
- replacing underlying evidence contracts with prose

## Launch Doctrine

### Default-Ready Promotion Rules

1. The closure packet verdict must be `GO`, not `NO_GO`.
2. `artifacts/ci_proof_gates_v1.json` must remain closure-consistent with the
   claim graph and composition matrix.
3. `CX-FULL-STACK` must remain `supported`.
4. Every promoted headline result must cite a concrete artifact or test path.
5. Every promoted surface must name an exact downgrade path.

### Experimental Opt-In Rules

1. `AA-08` transport work stays opt-in after `asupersync-1508v.8.6` closure unless a later packet explicitly graduates it.
2. Experimental surfaces must never be described as default-ready.
3. Experimental drills must publish exact rerun commands and fallback behavior.

### Incident and Rollback Rules

1. Any artifact mismatch or stale claim/evidence reference denies launch.
2. Any failed composition drill or CI proof gate denies launch.
3. Any unresolved transport fairness or tail regression forces downgrade to the
   conservative transport surface.

## Operator/Developer Continuation Pack

This continuation pack leaves behind the exact commands needed to refresh the
closure packet's cited evidence surfaces.

### Rerun Command Matrix

| Command ID | Purpose | Exact command |
|------------|---------|---------------|
| `RACP-REFRESH-CLAIM-GRAPH` | Refresh AA-10 claim/evidence graph contract | `rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa101 cargo test --test claim_evidence_graph_contract -- --nocapture` |
| `RACP-REFRESH-CI-GATES` | Refresh AA-10 CI proof gates contract | `rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa102 cargo test --test ci_proof_gates_contract -- --nocapture` |
| `RACP-REFRESH-COMPOSITION` | Refresh AA-10 cross-track composition contract | `rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa104 cargo test --test cross_track_composition_contract -- --nocapture` |
| `RACP-REFRESH-PACKET` | Refresh this closure packet contract | `rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa106 cargo test --test runtime_ascension_closure_packet_contract -- --nocapture` |
| `RACP-VERIFY-STATIC-SAFETY-COMPILE-FAIL` | Re-run the static-safety compile-fail surface | `rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa105a cargo test --test cap_obligation_compile_fail -- --nocapture` |
| `RACP-VERIFY-STATIC-SAFETY-SESSIONS` | Re-run the typed session-obligation surface | `rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa105b cargo test --test session_type_obligations -- --nocapture` |
| `RACP-VERIFY-TRACE-INTELLIGENCE` | Re-run replay minimization validation | `rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa063 cargo test --test replay_minimization_validation_contract -- --nocapture` |
| `RACP-VERIFY-WORKLOAD-CORPUS` | Re-run workload corpus validation | `rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa015 cargo test --test runtime_workload_corpus_contract -- --nocapture` |
| `RACP-VERIFY-TRANSPORT-OPTIN` | Re-run transport validation evidence for the opt-in surface | `rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa083 cargo test --test transport_frontier_benchmark_contract -- --nocapture` |
| `RACP-RUN-SMOKE-BUNDLE` | Run packet smoke bundle and emit report manifest | `./scripts/run_runtime_ascension_closure_smoke.sh --execute` |

Use these commands to refresh this packet's inputs:

```bash
# Claim/evidence graph
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa101 cargo test --test claim_evidence_graph_contract -- --nocapture

# CI proof gates
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa102 cargo test --test ci_proof_gates_contract -- --nocapture

# Cross-track composition
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa104 cargo test --test cross_track_composition_contract -- --nocapture

# This closure packet contract
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa106 cargo test --test runtime_ascension_closure_packet_contract -- --nocapture

# Transport opt-in evidence
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa083 cargo test --test transport_frontier_benchmark_contract -- --nocapture

# Smoke bundle runner (writes run_report.json + per-scenario manifests)
./scripts/run_runtime_ascension_closure_smoke.sh --execute
```

The smoke runner handles repo-root command execution internally, so the
invocation directory can differ from the execution directory without changing
the deterministic cargo/test surface.

Operator troubleshooting recipe:

1. If the packet says `NO_GO`, treat that as authoritative until the packet is
   refreshed and the verdict changes.
2. If a demo is blocked, route traffic to the conservative baseline named in
   the demo matrix.
3. If a contract artifact drifts, rerun its smoke suite before touching launch
   doctrine text.

## Validation

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa106 cargo test --test runtime_ascension_closure_packet_contract -- --nocapture
```

## Cross-References

- `artifacts/runtime_ascension_closure_packet_v1.json`
- `scripts/run_runtime_ascension_closure_smoke.sh`
- `tests/runtime_ascension_closure_packet_contract.rs`
- `artifacts/claim_evidence_graph_v1.json`
- `artifacts/ci_proof_gates_v1.json`
- `artifacts/cross_track_composition_v1.json`
- `artifacts/runtime_control_seam_inventory_v1.json`
- `artifacts/runtime_workload_corpus_v1.json`
- `artifacts/controller_interference_validation_v1.json`
- `artifacts/bounded_latency_regression_v1.json`
- `artifacts/replay_minimization_validation_contract_v1.json`
- `artifacts/capability_token_model_v1.json`
- `artifacts/crash_recovery_validation_v1.json`
- `artifacts/transport_frontier_benchmark_v1.json`
- `docs/transport_frontier_benchmark_contract.md`
- `tests/transport_frontier_benchmark_contract.rs`
