# Artifact Governance Producer Checklist

`artifacts/artifact_governance_producer_checklist_v1.json` is the A5 producer checklist for `asupersync-artifact-governance-awdiwy.5`.

When a bead adds a durable artifact, the producer must classify it in the governance taxonomy, add a ledger row or explicit exclusion, attach `does_not_*` no-claim boundaries, and run the focused remote-required proof that applies to the touched surface. A durable artifact is not citeable just because it appears in `artifacts/`, README, AGENTS, the proof-lane manifest, or the proof-status snapshot.

The checked guard scans the current high-trust reference surfaces for `artifacts/*.json` references. Each guarded reference must resolve to `artifacts/artifact_governance_ledger_v1.json` or to the checklist's explicit non-citeable exclusion list. Existing references that still need A7 backfill are excluded only as metadata: they do not become proof, they do not prove artifact absence, and they do not authorize deletion.

The verifier is `tests/artifact_governance_producer_checklist_contract.rs`.

## Producer Steps

1. Classify the artifact as proof-bearing, advisory, blocked-frontier, superseded, generated-fixture, operator-report, or excluded.
2. Add a ledger row for citeable or routeable artifacts; use an explicit exclusion only for non-citeable generated, ephemeral, or pre-backfill references.
3. Attach no-claim boundaries that travel with every citation.
4. Add or update a focused contract test for the artifact shape and citation limits.
5. Validate proof-supporting claims through `RCH_REQUIRE_REMOTE=1 rch exec -- ...`; do not cite local Cargo fallback as proof.

## Boundaries

- This checklist does not claim full-corpus artifact coverage.
- This checklist does not prove full-corpus coverage.
- This checklist does not make excluded references citeable.
- This checklist does not prove a fresh RCH pass.
- This checklist does not authorize deletion.
- This checklist does not close future artifact gaps.
- This checklist does not delete, move, rewrite, or clean artifacts.
