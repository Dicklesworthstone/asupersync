# Semantic Evidence Bundles

<!-- SEMANTIC-EVIDENCE-BUNDLES:SOURCE -->

`artifacts/semantic_evidence_bundles_v1.json` is the checked source of truth for
`asupersync-idea-wizard-fifth-wave-3gaiun.14`.

Semantic evidence bundles are citation packets for public guarantees. Each row
connects a user-facing claim to proof-lane IDs, source anchors, stale/missing
evidence fixtures, and explicit no-claim boundaries. The bundle does not execute
the proof lanes. It tells agents which evidence must be fresh before a claim can
be repeated in docs, closeout notes, or operator reports.

<!-- SEMANTIC-EVIDENCE-BUNDLES:SCHEMA -->

## Bundle Schema

Every bundle carries these fields:

| field | purpose |
|---|---|
| `bundle_id` | stable bundle identifier |
| `public_guarantee_id` | public guarantee covered by the row |
| `claim_text` | citation-safe claim wording |
| `semantic_scope` | surfaces the bundle is allowed to discuss |
| `primary_lanes` | proof manifest lanes carrying the strongest evidence |
| `supporting_lanes` | lanes used for freshness, routing, or no-claim support |
| `freshness_policy` | when cached or stale evidence becomes unciteable |
| `failure_mode_examples` | examples that should fail closed |
| `stale_missing_fixtures` | fixture IDs for stale, missing, or local-fallback evidence |
| `source_paths` | repo anchors that must stay present |
| `docs_links` | user or operator docs for the guarantee |
| `no_claims` | boundaries for what the bundle does not prove |

<!-- SEMANTIC-EVIDENCE-BUNDLES:GUARANTEES -->

## Covered Guarantees

The initial bundle set covers the guarantees users most often ask agents to
cite:

| guarantee | primary evidence |
|---|---|
| no orphan tasks | `formal-lean-build` |
| loser drain | `formal-lean-build`, `semantic-lint-proof-lane-contract` |
| no obligation leaks | `formal-lean-build`, `semantic-lint-proof-lane-contract` |
| cancel-safe send | `channel-mpsc-select-e2e-public-run` |
| deterministic replay | `validation-frontier-final-signoff` |
| no default tokio | `default-production-tokio-tree` |

Supporting lanes such as `proof-lane-manifest-contract` and
`validation-frontier-final-signoff` keep the citation rules, proof-status rows,
and no-claim boundaries aligned. They are not substitutes for rerunning an
affected primary lane after source or dependency overlap.

<!-- SEMANTIC-EVIDENCE-BUNDLES:FIXTURES -->

## Fail-Closed Fixtures

The bundle contract includes fixture classes for:

1. missing primary proof lanes
2. stale RCH receipts
3. local Cargo fallback receipts
4. dirty source overlap without a rerun
5. missing no-claim boundaries

Any of these cases should block citation of the affected public guarantee until
the correct remote proof lane has been rerun and the stale or missing evidence is
replaced.

## Validation

Use the focused remote-only contract:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_semantic_evidence_bundles_contract" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test semantic_evidence_bundles_contract --no-default-features -- --nocapture
```

Local Cargo fallback is not evidence for this bundle.

<!-- SEMANTIC-EVIDENCE-BUNDLES:NO-CLAIMS -->

## No-Claim Boundaries

This bundle does not prove broad workspace health, release readiness, runtime
correctness outside the cited scopes, performance improvement, live RCH fleet
availability, or freshness of any proof lane it names. It also does not permit
branch creation, worktree creation, file deletion, or source-bug closure from
cached evidence alone.
