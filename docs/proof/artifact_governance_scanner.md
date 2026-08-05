# Artifact Governance Scanner

`artifacts/artifact_governance_scanner_v1.json` is the A2 representative scan result for `asupersync-artifact-governance-awdiwy.2`.

The scanner is intentionally bounded: it validates a representative corpus and does not claim full-corpus coverage. It never rewrites, moves, or deletes artifacts.

## Categories

- `exact_ownership`: direct owner signals agree.
- `inferred_ownership`: owner is inferred from domain fields, tests, docs, or proof metadata.
- `orphan`: artifact exists and is referenced, but lacks a sufficient governance/proof owner row.
- `ambiguous`: owner signals conflict and require follow-up.
- `stale`: artifact is retained for lineage and points at a successor.
- `excluded`: generated or ephemeral path family outside durable artifact governance.

## Representative Findings

| Category | Path | Routing |
| --- | --- | --- |
| `exact_ownership` | `artifacts/artifact_governance_scanner_v1.json` | Owned by `asupersync-artifact-governance-awdiwy.2`; checked by `tests/artifact_governance_scanner_contract.rs`. |
| `exact_ownership` | `artifacts/proof_lane_manifest_v1.json` | Cited by README/AGENTS and proof-status source-of-truth rows; not proof that any lane passed. |
| `inferred_ownership` | `artifacts/raptorq_track_e_gf256_bench_v1.json` | Inferred from RaptorQ domain metadata and tests; not closure-grade evidence. |
| `orphan` | `artifacts/raptorq_track_e_gf256_p95p99_v1.json` | Referenced by RaptorQ docs/tests but missing a governance ledger row in this scan. |
| `ambiguous` | `artifacts/rch_stale_progress_receipt_contract_v1.json` | Top-level `bead_id` and governance ledger ownership disagree; cite only as an explicit ambiguity. |
| `stale` | `artifacts/raptorq_track_e_gf256_multiscenario_refresh_v3.json` | Superseded by `artifacts/raptorq_track_e_gf256_multiscenario_refresh_v4.json`; retain for lineage only. |
| `excluded` | `${TMPDIR:-/tmp}/rch_target_*` | Ephemeral RCH target/cache output; exclusion does not authorize deletion. |

## Full-File Hash Cycle Witness

The scanner also carries a static, read-only `BLOCKED_REFERENCE_CYCLE` witness captured at commit `15391290dce5d259bf491e676d35f3d46564935a`. This audit is orthogonal to the representative ownership rows above. Its discovery scope was the 354 Git-tracked JSON documents under `artifacts/`, recursively recognizing objects that pair a repository-relative `path` with a full-file `sha256`; it is not a full-artifact-corpus claim.

The only cyclic component found in that captured scope has four members and six directed edges:

- `artifacts/dependency_capability_baseline_v1.json` pins the Base64 inventory, Hex inventory, and Phase-1 signoff at their current captured bytes.
- Each of those three artifacts pins an older full-file hash of the dependency capability baseline.
- The result is three reciprocal two-edge cycles sharing the baseline. Refreshing any stale reverse pin changes its source artifact and invalidates the baseline's corresponding inbound pin.

Blind sequential hash refresh therefore has no guaranteed terminating order. Before repinning, an owner must break at least one full-file edge in each of the three named cycles by using immutable commit/blob provenance or a canonical semantic projection. Historical hashes must remain labeled as historical provenance.

## Boundaries

- This report is an operator routing aid, not a fresh RCH pass.
- Orphan does not mean unused, ownerless, or safe to delete.
- Excluded means outside this durable artifact scanner, not safe to remove.
- Stale means cite the successor for current evidence and retain the stale path for lineage.
- The cycle witness does not make cyclic pins current and does not authorize blind hash refresh.
