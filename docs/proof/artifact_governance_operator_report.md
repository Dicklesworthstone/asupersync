# Artifact Governance Operator Report

`artifacts/artifact_governance_operator_report_v1.json` is the A4 deterministic operator report for `asupersync-artifact-governance-awdiwy.4`.

The report summarizes representative ledger, scanner, and seed-backfill rows by next action. It is an operator routing aid: it does not prove full-corpus coverage, fresh RCH success, release readiness, or broad workspace health.

## Summary

`citeable=2 blocked=3 ambiguous=1 owner_missing=1 reference_topology=1 stale_superseded=1 excluded=1 missing_tests=1 operator_context=1`

## Action Buckets

| Action | Representative Rows | Operator Meaning |
| --- | --- | --- |
| `citeable` | `artifact-governance-seed-backfill`, `browser-wasm-artifact-integrity-manifest` | Cite narrowly only when the focused contract passes on current main, and carry no-claim boundaries. |
| `blocked` | `proof-lane-manifest-canonical`, `runtime-pressure-control-evidence-contract`, `validation-frontier-inventory` | Route proof work and reruns; do not treat blocker rows as green proof. |
| `ambiguous_ownership` | `rch-stale-progress-receipt-contract` | Keep both owner signals visible and select no winner. |
| `owner_missing` | `artifacts/raptorq_track_e_gf256_p95p99_v1.json` | Add governance metadata or an explicit non-citeable exclusion before citation. |
| `reference_topology` | `dependency-capability-baseline-versioned-reference-topology` | Preserve the three historical baseline back-references without repinning; the seven-node content-addressed graph is acyclic, and separate immutable provenance is still required for each historical target. |
| `stale_superseded` | `raptorq-gf256-multiscenario-refresh-v3` | Retain lineage and cite the successor for current evidence. |
| `excluded` | `remote-build-target-cache-roots` | Explain why the cache pattern is outside durable artifact governance. |
| `missing_tests` | `remote-build-target-cache-roots` | Empty tests are allowed only because this is an excluded generated/cache pattern. |
| `operator_context` | `fifth-wave-live-swarm-telemetry-heatmap` | Use for routing context only, not as proof of observability or performance. |

## Boundaries

- This report does not prove full-corpus artifact coverage.
- This report does not prove a fresh RCH pass.
- This report does not authorize deletion, cleanup, branches, or worktrees.
- This report does not close artifact-producing beads.
- This report does not prove release readiness.
- The reference-topology row does not make historical pins current, authorize blind hash refresh, prove Git history is available in every checkout, or prove that the executable Rust contract passed.

Machine-readable report boundaries:

- `does_not_prove_full_corpus_coverage`
- `does_not_authorize_deletion`
- `does_not_prove_fresh_rch_pass`
- `does_not_close_artifact_beads`
- `does_not_prove_release_readiness`
- `does_not_make_historical_pins_current`
- `does_not_authorize_blind_hash_refresh`
- `does_not_prove_git_history_is_available_in_every_checkout`
- `does_not_prove_executable_contract_pass`
