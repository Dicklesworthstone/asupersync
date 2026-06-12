# Artifact Governance Seed Backfill

`artifacts/artifact_governance_seed_backfill_v1.json` is the A7 representative seed backfill for `asupersync-artifact-governance-awdiwy.7`.

The backfill maps real artifact-governance ledger rows across ten high-value families to citeability class, ownership confidence, next action, and no-claim boundaries. It is deliberately representative: it does not prove full-corpus coverage or release readiness.

## Covered Families

- `proof_manifest`
- `validation_frontier`
- `rch_stale_receipt`
- `runtime_pressure`
- `swarm_agent`
- `browser_wasm`
- `raptorq`
- `generated_fixture`
- `excluded`
- `artifact_governance`

## Ambiguous Ownership

`rch-stale-progress-receipt-contract` is represented with `ambiguous_owner_signals`. The scanner sees both `asupersync-validation-frontier-v2-b5cjsv.4` and `asupersync-artifact-governance-awdiwy.1`; the backfill records both and selects no winner. A future ledger override may resolve that, but this artifact does not.

## Operator Use

Use this report to choose the next action for seed rows: cite narrowly, route blocked-frontier rows, preserve superseded or advisory context, keep generated fixtures bounded, and explain exclusions. Do not use it to delete files, clean caches, create branches, create worktrees, bypass RCH, or claim the whole artifact corpus is governed.

## Boundaries

- This backfill does not prove full-corpus coverage.
- This backfill does not select ambiguous owners.
- This backfill does not authorize deletion.
- This backfill does not prove a fresh RCH pass.
