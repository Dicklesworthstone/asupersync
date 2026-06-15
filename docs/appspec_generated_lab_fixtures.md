# AppSpec generated lab fixtures

Bead: `asupersync-idea-wizard-fifth-wave-3gaiun.2.3`

This packet defines the contract for generated AppSpec lab fixtures and now
carries an executed deterministic lab replay for the minimal single-group
topology. `asupersync-idea-wizard-fifth-wave-3gaiun.2.2` (the A2 compiler) is
proven and closed in commit `39e1a9b74` (single-group lowering, region-close
quiescence), so the minimal fixture is cited as executable evidence. It remains
fail-closed for everything beyond that: the richer multi-group region tree stays
a contracted snapshot pending A2 multi-group sub-supervisor lowering, and this
packet makes no broad workspace-health or production-readiness claim.

<!-- APPSPEC-GENERATED-LAB-FIXTURES:SOURCE -->

## Source

The source of truth is
`artifacts/appspec_generated_lab_fixtures_v1.json`. It binds the packet to:

- `artifacts/appspec_v1_schema.json`
- `docs/appspec_v1.md`
- `src/app.rs`
- `tests/appspec_generated_lab_fixtures_contract.rs`

Manual status tables are not proof. A fixture row is citeable only when the
artifact, this runbook, and the focused contract test agree on source paths,
failure modes, RCH command shape, and no-claim boundaries.

<!-- APPSPEC-GENERATED-LAB-FIXTURES:FIXTURES -->

## Fixtures

The accepted fixture catalog currently contains
`minimal-http-worker-topology`. It describes a small AppSpec manifest with an
HTTP service, a background worker, route and budget bindings, declared
capabilities, supervision groups, and a trace-ledger observability sink.

The expected topology snapshot records the region tree, child tasks, route
bindings, budget bindings, capability declarations, and observability bindings.
The lab replay is executed for the single-group lowering: `tests/appspec_v1_lab_replay.rs`
builds the minimal topology, runs it to region-close quiescence with no orphan
tasks for the deterministic seeds 1/2/3, and asserts a deterministic
trace fingerprint on replay (`execution_status: executed-single-group`). The
multi-group region tree in the snapshot is contracted-only until A2 grows
multi-group sub-supervisor lowering.

<!-- APPSPEC-GENERATED-LAB-FIXTURES:NEGATIVE -->

## Negative Fixtures

The contract requires one negative fixture for each validation class below:

- `missing-capability`
- `invalid-budget-composition`
- `unsupported-db-protocol-feature`
- `supervision-cycle`
- `supervision-assignment`

Each negative row owns its validation phase, expected error kind, and local
no-claim boundary. Missing any required row blocks proof-manifest projection.
The `supervision-assignment` row is tied to the A2 validation surface that rejects
missing, duplicate, or mismatched service-to-supervision-group assignment.

<!-- APPSPEC-GENERATED-LAB-FIXTURES:MANIFEST -->

## Manifest Projection

The projected lane is `appspec-generated-lab-fixtures-contract`. It is a focused
artifact contract lane, not a broad workspace health lane. The remote-required
command is:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_appspec_generated_lab_fixtures_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test appspec_generated_lab_fixtures_contract --no-default-features -- --nocapture
```

The executed lab-replay lane is `appspec-v1-lab-replay`. Its remote-required
command is:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_appspec_v1_lab_replay CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test appspec_v1_lab_replay -- --nocapture
```

The A2 source/proof evidence is commits `739780907`, `5707618c1`, and the proof
commit `39e1a9b74`, which proved the A2 single-group compiler/lowering via
`tests/appspec_v1_compiler.rs` (region-close quiescence + fail-closed cases) on a
remote RCH pass. The A2 proof blocker is therefore cleared for the single-group
topology.

<!-- APPSPEC-GENERATED-LAB-FIXTURES:VALIDATION -->

## Validation

Use local non-Cargo checks for syntax and formatting only:

```bash
jq empty artifacts/appspec_generated_lab_fixtures_v1.json
rustfmt --edition 2024 --check tests/appspec_generated_lab_fixtures_contract.rs
git diff --check -- artifacts/appspec_generated_lab_fixtures_v1.json docs/appspec_generated_lab_fixtures.md tests/appspec_generated_lab_fixtures_contract.rs
```

Cargo validation for this packet must run through RCH with
`RCH_REQUIRE_REMOTE=1`. Local Cargo fallback is not accepted evidence.

<!-- APPSPEC-GENERATED-LAB-FIXTURES:NO-CLAIMS -->

## No Claims

This packet does not prove broad workspace health, release readiness, AppSpec
production readiness, runtime correctness, local Cargo fallback, or closure of
`asupersync-idea-wizard-fifth-wave-3gaiun.2`,
`asupersync-idea-wizard-fifth-wave-3gaiun.2.3`, or
`asupersync-idea-wizard-fifth-wave-3gaiun.16`.
