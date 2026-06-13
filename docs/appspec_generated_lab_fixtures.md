# AppSpec generated lab fixtures

Bead: `asupersync-idea-wizard-fifth-wave-3gaiun.2.3`

This packet defines the contract for generated AppSpec lab fixtures without
claiming that the AppSpec source is fully proven. It is intentionally
fail-closed because `asupersync-idea-wizard-fifth-wave-3gaiun.2.2` still needs a
fresh focused RCH proof before these fixtures can be cited as executable
evidence.

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
The lab replay metadata is deterministic, but its execution status remains
`blocked-by-a2-proof` until the A2 AppSpec validation proof is fresh.

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

The projection is not a canonical manifest row until the focused contract test
passes remotely and the A2 proof blocker is cleared.

The current A2 source evidence is commits `739780907` and `5707618c1`. Those
commits added the compiler bridge and supervision-assignment validation, but the
focused test-profile proof still needs a fresh remote pass before this packet can
be cited as executable generated-fixture evidence.

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
