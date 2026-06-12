# Artifact Governance Citation Policy

`artifacts/artifact_governance_citation_policy_v1.json` is the A3 citation policy for `asupersync-artifact-governance-awdiwy.3`.

The policy uses the artifact-governance ledger as the source of truth for citeability class, evidence scope, freshness policy, and no-claim boundaries. It complements validation-frontier and proof-evidence-debt artifacts; it does not replace either one or create fresh proof receipts.

## Checked Contexts

- `readme_agents_discoverability`: docs may help agents find artifacts only when no-claim text travels with the citation.
- `proof_status_claim`: proof-status rows may cite proof-bearing, blocked-frontier, or operator-report artifacts without turning blocked rows green.
- `bead_closeout`: close reasons may cite narrow task evidence only with the ledger row boundaries.
- `release_signoff`: broad release claims require proof-bearing artifacts and still cannot bypass release-specific proof lanes.
- `operator_runbook`: runbooks may use advisory, stale, excluded, and blocked rows for routing without upgrading them to production truth.
- `internal_fixture`: tests may exercise policy behavior without creating user-facing claims.

## Negative Fixtures

The contract rejects these representative overclaims:

- A generated-fixture artifact cited as release proof.
- A blocked-frontier stale RCH receipt cited as green proof.
- A runtime pressure row cited as production runtime enforcement.

## Boundaries

- This policy does not prove full-corpus coverage.
- This policy does not authorize overclaims beyond a row's citeability class.
- This policy does not prove a fresh RCH pass.
- This policy does not authorize deletion, mutation, branch creation, worktree creation, or local Cargo fallback.
