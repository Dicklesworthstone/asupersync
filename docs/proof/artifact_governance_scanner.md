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

The scanner retains the original static discovery receipt from commit `15391290dce5d259bf491e676d35f3d46564935a`. Its scope was the 354 Git-tracked JSON documents under `artifacts/`, recursively recognizing objects that pair a repository-relative `path` with a full-file `sha256`. A separate September 9 observation at `6770004e82979cfa156eaaa1bbc7bc81f1b276f5` refreshes only the four members below. It does not refresh the original whole-discovery counts or make a full-artifact-corpus claim.

Collapsing every version of an artifact to its path produces one strongly connected component with four paths and six directed edges:

- `artifacts/dependency_capability_baseline_v1.json` retains historical pins for Base64 `02f58ff42dd48914ab91c5fc50ad6f44d85f8e3594495fc3ec10958b85a01b74`, Phase-1 `f99bb9e88291d122b1f075c43480436ed1a94c0389174a472c9684d9b2ebf3c4`, and Hex `70b50e423a89452fc2f47d16a775019c0bc5d7ca6bcdd60971a9c5a159aaedc9`.
- Base64 and Hex now pin reviewed live baseline `49e85f8defbccb4e9cce3c37d302e965b36de518f8929999928d9464e83ee791`; Phase-1 retains historical baseline `168e9a0b5f836c1d30b56c1fb6478092d8759b0d1fe144edbdb526cca5a488ad`. The prior baseline `df830fc2663de19f857ade1e07feed0ee29f41f9cf6eba84f9c85b1d9c1040bc` receipt remains as observation history.
- The standalone legacy receipt retains SHA-256 `88575b016105828ce8c1792492355fd34e8a3687ef6be2509e0412dee949cda8`, the 1,357-line baseline at commit `7390d33f4ac297cd28138c8e1ece38f60b278660` and blob `4e56ad4bc05dbd1614583f8cdf8586a0d1f88cc7`. It corresponds to none of the six current edges and does not independently authenticate their targets.

The content-addressed graph has eight nodes, six edges, and no directed cycle: two edges are current and four retain historical targets. The `PASS_NO_CONTENT_ADDRESSED_CYCLE_WITH_PATH_ALIAS_WARNING` finding covers that topology only. No full-file edge replacement is required; the remaining historical approval pins retain their bytes.

Three distinct target identities have separately recorded static Git-object receipts:

| Target SHA-256 prefix | Commit | Blob | Lines |
| --- | --- | --- | --- |
| Baseline `168e9a0b5f83` | `3cb2dc6d0540` | `c3a07d91aeb6` | 3210 |
| Baseline `df830fc2663d` | `caca35cc3a54` | `01d8c8407411` | 3213 |
| Phase-1 `f99bb9e88291` | `a8ab5a9bc8dd` | `e6614af99c3f` | 327 |

The artifact contains their full identities. The first receipt supplies the historical line count absent from the Phase-1 approval, without changing that approval. The second is retained from the prior observation and no longer identifies a current edge. The executable contract checks all three receipts and joins the two still referenced historical identities; it does not read Git objects or independently reauthenticate their bytes.

Base64 `02f58ff42dd4` and Hex `70b50e423a89` remain unresolved after a bounded main-history search. Their stored counts are 1,018 and 977 lines, respectively. Claiming their immutable byte provenance requires separate receipts. Preserve the four remaining historical back-references; do not replace them with live hashes to make other evidence current. A future path-only strongly connected component is a warning to recompute the versioned topology, not sufficient evidence of a blocking content cycle.

## Boundaries

- This report is an operator routing aid, not a fresh RCH pass.
- Orphan does not mean unused, ownerless, or safe to delete.
- Excluded means outside this durable artifact scanner, not safe to remove.
- Stale means cite the successor for current evidence and retain the stale path for lineage.
- The versioned receipt does not make historical pins current and does not authorize blind hash refresh. It also does not prove that Git history is available in every checkout or that the executable Rust contract passed.
