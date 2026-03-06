# Cross-Track Composition Contract

Bead: `asupersync-1508v.10.7`

## Purpose

This contract defines the cross-track composition gauntlet: a compatibility matrix classifying track combinations as supported/experimental/forbidden, incident drills exercising multi-track failure paths, and actionable structured logs for reproduction.

## Contract Artifacts

1. Canonical artifact: `artifacts/cross_track_composition_v1.json`
2. Smoke runner: `scripts/run_cross_track_composition_smoke.sh`
3. Invariant suite: `tests/cross_track_composition_contract.rs`

## Compatibility Matrix

| Combination | Tracks | Status |
|-------------|--------|--------|
| CX-DECIDE-SCHED | AA-01, AA-02 | supported |
| CX-DECIDE-INTERFERE | AA-02, AA-03 | supported |
| CX-DECIDE-LATENCY | AA-02, AA-04 | supported |
| CX-DECIDE-SAFETY | AA-02, AA-05 | supported |
| CX-DECIDE-AUTHORITY | AA-02, AA-07 | supported |
| CX-DECIDE-RECOVERY | AA-02, AA-09 | supported |
| CX-AUTHORITY-RECOVERY | AA-07, AA-09 | supported |
| CX-TRACE-RECOVERY | AA-06, AA-09 | supported |
| CX-TRANSPORT-LATENCY | AA-08, AA-04 | experimental |
| CX-TRANSPORT-RECOVERY | AA-08, AA-09 | experimental |
| CX-FULL-STACK | All core | supported |

## Incident Drills

| Drill | Tracks | Scenario |
|-------|--------|----------|
| ID-CONTROLLER-CRASH-RECOVERY | AA-02/07/09 | Controller causes crash, full recovery cycle |
| ID-TAIL-REGRESSION-ROLLBACK | AA-02/04 | Tail budget exceeded, automatic rollback |
| ID-OBLIGATION-LEAK-DETECTION | AA-05/09 | Crash before settlement, leak detection |
| ID-AUTHORITY-REVOCATION-CASCADE | AA-07 | Root revocation cascades to all descendants |
| ID-FULL-STACK-DOWNGRADE | AA-01/02/04/07/09 | Multi-failure graceful degradation |

## Validation

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch-codex-aa104 cargo test --test cross_track_composition_contract -- --nocapture
```

## Cross-References

- `artifacts/cross_track_composition_v1.json`
- `artifacts/ci_proof_gates_v1.json` -- CI gate definitions
- `artifacts/claim_evidence_graph_v1.json` -- Evidence graph
