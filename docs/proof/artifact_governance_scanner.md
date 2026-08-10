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

## Versioned Full-File Reference Topology

The scanner also carries a static, read-only `PASS_NO_CONTENT_ADDRESSED_CYCLE_WITH_PATH_ALIAS_WARNING` receipt captured from commit `15391290dce5d259bf491e676d35f3d46564935a`. This audit is orthogonal to the representative ownership rows above. Its discovery scope was the 354 Git-tracked JSON documents under `artifacts/`, recursively recognizing objects that pair a repository-relative `path` with a full-file `sha256`; it is not a full-artifact-corpus claim.

Collapsing every version of an artifact to its path produces one strongly connected component with four paths and six directed edges:

- `artifacts/dependency_capability_baseline_v1.json` retains historical pins for Base64 `28171082ff529b93cbe951b9de84db9423b8922fde531c82aa21051b933c83eb`, Phase-1 `f99bb9e88291d122b1f075c43480436ed1a94c0389174a472c9684d9b2ebf3c4`, and Hex `971385dfaf02570e6a02d52b494bc231e089ab8281bbcde812ff529727c10478`.
- The current Base64, Phase-1, and Hex artifacts each pin the live baseline identity `2cc72453659c2209713d6779c6d12aa6a114201893cbbd6e840d9f73786d38a3`.
- The standalone historical-target receipt retains SHA-256 `88575b016105828ce8c1792492355fd34e8a3687ef6be2509e0412dee949cda8`, the 1,357-line baseline at commit `7390d33f4ac297cd28138c8e1ece38f60b278660` and blob `4e56ad4bc05dbd1614583f8cdf8586a0d1f88cc7`. That legacy receipt no longer corresponds to one of the six live-member edges and does not independently authenticate the three stored historical targets above.

The content-addressed graph has seven nodes, six edges, and no directed cycle. No full-file edge replacement is required. Operators must preserve the three historical back-references as recorded historical pins and must not refresh or relabel them as current; claiming immutable byte provenance for those three targets requires separate receipts. A future path-only strongly connected component is a warning to recompute the versioned topology, not sufficient evidence of a blocking content cycle.

## Boundaries

- This report is an operator routing aid, not a fresh RCH pass.
- Orphan does not mean unused, ownerless, or safe to delete.
- Excluded means outside this durable artifact scanner, not safe to remove.
- Stale means cite the successor for current evidence and retain the stale path for lineage.
- The versioned receipt does not make historical pins current and does not authorize blind hash refresh. It also does not prove that Git history is available in every checkout or that the executable Rust contract passed.
