# Artifact Governance Validation Harness

`artifacts/artifact_governance_validation_harness_v1.json` is the A8 deterministic validation harness for `asupersync-artifact-governance-awdiwy.8`.

The harness checks fixture-sized schema/parser cases, citation overclaim cases, supersession-chain cases, and one e2e-style ledger -> scanner -> report -> signoff flow log. It is a checked fixture harness, not a full-corpus artifact scan.

## Summary

`schema=4 citation=3 supersession=3 e2e=1 pass=5 fail=6 first_blocker=validation-frontier-inventory`

## Fixture Buckets

| Bucket | Cases | Expected Outcome |
| --- | --- | --- |
| `schema_parser_edges` | `valid_proof_bearing_row_passes`, `missing_owner_fails_closed`, `duplicate_path_fails_closed`, `malformed_no_claim_boundary_fails` | Valid proof-bearing rows pass; missing owners, duplicate paths, and malformed no-claim tokens fail closed. |
| `citation_policy_edges` | `narrow_proof_bearing_citation_passes`, `proof_manifest_workspace_health_overclaim_fails`, `advisory_raptorq_closure_claim_fails` | Narrow citation passes; workspace-health and closure overclaims fail. |
| `supersession_edges` | `current_successor_context_passes`, `superseded_lineage_with_successor_passes`, `superseded_without_successor_fails_closed` | Current and lineage cases pass; missing successor metadata fails closed. |
| `e2e_flow_log` | `ledger_scanner_report_signoff_fixture` | The flow log pins class counts, first blocker, no-claim violations, and next action. |

## Remote Validation

Use the remote-required lane:

```bash
RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_artifact_governance_validation_harness cargo test -p asupersync --test artifact_governance_validation_harness_contract --test artifact_governance_ledger_contract -- --nocapture
```

If RCH admission is unavailable, record a blocker receipt and do not run local Cargo fallback.

## Boundaries

- This harness does not prove full-corpus artifact coverage.
- This harness does not prove a fresh RCH pass unless the remote-required command passes on current main.
- This harness does not authorize deletion, cleanup, branches, or worktrees.
- This harness does not authorize local Cargo fallback.
- This harness does not close artifact-producing beads.
- This harness does not prove release readiness or workspace health.

Machine-readable harness boundaries:

- `does_not_prove_full_corpus_coverage`
- `does_not_authorize_deletion`
- `does_not_prove_fresh_rch_pass`
- `does_not_authorize_local_cargo_fallback`
- `does_not_prove_release_readiness`
- `does_not_close_artifact_beads`
- `does_not_prove_workspace_health`
