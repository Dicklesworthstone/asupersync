# Lab-Live Differential Scenario Contract

**Bead**: `asupersync-idea-wizard-fifth-wave-3gaiun.5.1`
**Contract artifact**: `artifacts/lab_live_differential_scenario_contract_v1.json`
**Contract test**: `tests/lab_live_differential_contract.rs`

This contract is the fifth-wave scenario map for lab/live differential evidence.
It does not replace the existing `asupersync-2a6k9` lab/live program. It
inherits that program's scope matrix, normalized observable schema, divergence
taxonomy, verification taxonomy, scenario adapter contract, and v2 pilot
scenario artifact.

## Claim Classes

`supported_now` scenarios are admitted Phase 1 semantic-core surfaces. They may
claim a bounded lab/live semantic comparison only when they name the exact lab
fixture, live adapter, normalized record, expected logs, failure bundle, and
no-claim boundary.

`supported_later` scenarios are legitimate future targets. They remain blocked
until their virtualization, capture, timing normalization, and observability
requirements are present.

`unsupported` scenarios are red-line cases for this program. They must emit a
negative-control fixture rather than a skipped pass.

`stale_evidence` scenarios identify support rows or README-facing claims whose
evidence is missing or old. A stale row is not a failed runtime behavior, but it
cannot support a promotion claim until fresh fixture evidence exists.

## Required Fields

Every scenario fixture must carry:

- `scenario_id`, `claim_id`, `claim_class`, `surface_id`, and `phase`
- `lab_fixture` and `live_adapter`
- `admitted_differences`
- `timing_normalization`
- `platform_prerequisites`
- `expected_logs`
- `failure_bundle`
- `readme_or_support_matrix_row`
- `verification_floor`
- `expected_verdict`
- `no_claims`

The `no_claims` field is mandatory. A fixture without explicit no-claim
boundaries is invalid even if every other field is present.

## Fixture Verdicts

The checked fixture set covers four evidence outcomes:

- `pass`: a supported Phase 1 channel reserve/send claim.
- `fail`: a Phase 1 region-close divergence with a first mismatched field.
- `unsupported`: a raw-socket surface rejected for missing virtualization and
  capture boundaries.
- `stale`: a browser support row that cannot promote without fresh fixture
  evidence.

These fixtures are deliberately small. They freeze the contract language that a
later runner must emit; they do not run adapter scenarios by themselves.

## No-Claim Boundary

Green contract tests for this artifact mean only that the scenario map is
well-formed, inherits the existing lab/live contracts, and rejects missing
no-claim boundaries. They do not prove broad workspace health, raw OS fidelity,
browser host parity, real-network behavior, or runtime-wide adapter parity.

## Validation

Use the focused RCH lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_lab_live_differential_contract" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-D warnings -C debuginfo=0" cargo test -p asupersync --test lab_live_differential_contract -- --nocapture
```
