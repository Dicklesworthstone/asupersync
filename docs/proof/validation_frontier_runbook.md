# Validation Frontier Runbook

<!-- validation-frontier-signoff-v1 -->

Contract ID: `validation-frontier-signoff-v1`
Bead: `asupersync-validation-frontier-v2-b5cjsv.7`

Canonical machine artifact:
`artifacts/validation_frontier_signoff_v1.json`.

Focused manifest lane: `validation-frontier-final-signoff`.

The validation frontier exists so agents can tell the difference between a
focused proof lane, a broad Cargo frontier, and an infrastructure blocker. A
focused lane that reaches an unrelated compile graph tail is not source-failure
evidence for the touched code. It is a validation-frontier record until a
smaller focused lane or a broad release gate proves otherwise.

## Decision Tree

Start with the smallest manifest lane that matches the claim:

1. If the claim is dependency shape, use the matching dependency-graph lane.
2. If the claim is a source behavior, prefer a focused lib, integration, or
   downstream-consumer lane that exercises that public surface.
3. If the claim is a proof artifact, use the artifact-contract lane for that
   artifact and keep the claim limited to schema, docs, manifest/status wiring,
   deterministic report fields, and no-claim boundaries.
4. If the claim is release readiness, run the broad release gates. A focused
   artifact lane is not a substitute for check, clippy, test, rustdoc, or
   package-specific publish gates.

When two lanes appear to overlap, choose the narrower lane for local change
evidence and record the broader lane as a follow-up. Do not cite a stale cached
receipt as `fresh-rch-pass`.

## Evidence Classes

`compile_only` or focused compile evidence proves that the requested surface
compiled under the declared feature graph. It does not prove runtime behavior.

`test_execution` evidence proves only the tests that actually ran. Exact
filters that report zero tests fail closed.

`artifact_contract` evidence proves the checked JSON, docs, manifest/status
rows, deterministic report rendering, and no-claim boundaries. It does not run
the child proof lanes unless the command explicitly includes them.

`RCH stale-progress` evidence is not a Rust diagnostic. Record build id, worker
id, command, last compiler line, progress age, heartbeat state, and cancellation
outcome. If the last compiler line is an unrelated graph tail, route it as a
validation-frontier blocker instead of blaming the touched source file.

## Channel MPSC/Select Fixture

The current regression fixture is recorded in
`artifacts/validation_frontier_inventory_v1.json`:

- `channel-mpsc-select-e2e-public-run` is the public execution lane and was
  observed green.
- `channel-mpsc-select-e2e-lib-check` is compile-only support evidence and was
  observed green.
- `channel-mpsc-select-e2e-lib-tests-check`,
  `channel-mpsc-select-e2e-filtered-run`, and
  `mpsc-recv-many-wake-cascade-exact-run` reached stale-progress or preflight
  boundaries before they became clean focused test evidence.

Use that split when deciding whether a channel change has focused public
evidence, blocked cfg(test) frontier evidence, or both.

## No-Claim Rules

The validation-frontier final signoff does not prove broad workspace health,
release readiness, source correctness outside the cited surfaces, performance
improvement, no regression, live RCH fleet availability, or permission to close
the parent epic. It is a scoped operator packet that ties together inventory,
stale-progress receipts, downstream-consumer proof, graph budgets, manifest
semantics, proof-status rows, and this runbook.

Before closing a proof-lane bead:

1. Cite the exact manifest lane id and command.
2. Attach or reference the exact RCH receipt state.
3. State whether evidence is `fresh-rch-pass`, `rerun-required`, `blocked`,
   `stale-evidence`, `no-win`, `unsupported`, or `approved-cache-hit`.
4. Preserve non-claims in the bead comment, commit message, and operator
   report.
5. Escalate to broad release gates only when making broad release, workspace,
   package, or performance claims.

## Focused Proof

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_validation_frontier_signoff CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test validation_frontier_signoff_contract -- --nocapture
```

The full deterministic operator runner is:

```bash
scripts/run_validation_frontier_signoff_e2e.sh
```

That runner invokes remote-required RCH lanes for the lightweight validation
frontier contracts. It must not be replaced with local Cargo fallback.
