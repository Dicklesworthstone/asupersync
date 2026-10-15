# Artifact Governance Final Signoff

`artifacts/artifact_governance_final_signoff_v1.json` is the A6 final signoff artifact for `asupersync-artifact-governance-awdiwy.6`.

It aggregates A1-A5, A7, and A8 into one checked closeout surface: ledger schema, scanner, citation policy, producer checklist, operator report, seed backfill, and validation harness. This is a scoped artifact-governance signoff, not a full-corpus certification or release-readiness proof.

## Remote Validation

Run the manifest lane exactly:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_artifact_governance_final_signoff CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test artifact_governance_final_signoff_contract --test artifact_governance_validation_harness_contract --test artifact_governance_ledger_contract --test proof_lane_manifest_contract --test proof_status_snapshot_contract -- --nocapture
```

If RCH admission is unavailable or a tool falls back locally, record a fail-closed blocker receipt and do not cite the lane as fresh proof.

## Closeout Checklist

| Step | Required Action | Fail-Closed Condition |
| --- | --- | --- |
| `verify_remote_lane` | Run the exact remote-required command above. | RCH is unavailable, local fallback appears, or no terminal test output is produced. |
| `verify_manifest_status` | Confirm `artifacts/proof_lane_manifest_v1.json` and `artifacts/proof_status_snapshot_v1.json` name the same command, lane, guarantee, and claim. | Any command, marker, or guarantee drift. |
| `verify_ledger_registration` | Confirm `artifacts/artifact_governance_ledger_v1.json` registers this signoff and its contract. | Missing row, missing test, or broad proof claim. |
| `close_tracker_when_safe` | close A4, A7, A8, and A6 only when `.beads/issues.jsonl` is safe for a bounded tracker write. | Unrelated tracker dirt or active peer tracker edits. |

## Boundaries

- This signoff does not prove full-corpus artifact coverage.
- This signoff does not authorize deletion, cleanup, branches, or worktrees.
- This signoff does not authorize local Cargo fallback.
- This signoff does not prove release readiness, workspace health, runtime correctness, performance improvement, or live RCH fleet availability.

Machine-readable boundaries:

- `does_not_prove_full_corpus_coverage`
- `does_not_authorize_deletion`
- `does_not_authorize_local_cargo_fallback`
- `does_not_prove_release_readiness`
- `does_not_prove_workspace_health`
- `does_not_prove_runtime_correctness`
- `does_not_prove_performance_improvement`
- `does_not_prove_live_rch_fleet_availability`
