# Dependency Verification Matrix

Bead `asupersync-dep-p1-foundations-upksjk.6.1` owns the checked VER A1
evidence plan in
`artifacts/dependency_verification_matrix_v1.json`. The artifact is canonical;
this page explains how implementation owners consume it and how reviewers
interpret its guarantees.

The matrix is deliberately broader than source implementation alone. It covers
every non-epic `dep-plan` work node, including implementation, architecture,
verification, and decision leaves. The only excluded work node is a closed
tracker duplicate whose close reason explicitly identifies its canonical
successor. That scope prevents an executable planning bead from bypassing the
evidence contract by presenting itself as documentation, review, benchmarking,
or signoff.

## Current inventory

The checked artifact currently contains:

| Surface | Count |
| --- | ---: |
| Stable capabilities | 50 |
| Capability invariants | 473 |
| Covered work beads | 335 |
| Evidence-plan rows | 1,595 |
| Implementation leaves | 106 |
| Architecture leaves | 14 |
| Verification leaves | 199 |
| Decision leaves | 16 |

The specialized plan counts are:

| Evidence class | Count |
| --- | ---: |
| Local unit plans | 106 |
| Local structural contract plans | 229 |
| Deterministic property plans | 296 |
| Lab lifecycle plans | 263 |
| Bounded fuzz plans | 303 |
| Public downstream plans | 201 |
| No-mock E2E plans | 197 |

Counts are regenerated from `.beads/issues.jsonl` and
`artifacts/dependency_capability_registry_v1.json`; they are not handwritten
success claims.

## Row contract

Each matrix row records:

- the exact bead ID, title, leaf role, capability IDs, and invariant IDs;
- the risk tags derived from the live bead contract and capability boundary;
- all affected feature and target requirements;
- mandatory case classes;
- exact test or scenario files and stable test filters;
- deterministic seeds or fixtures;
- an exact replay command and artifact root;
- the evidence owner and expected outcome;
- a fail-closed cutover state and explicit no-claim boundary.

An implementation row names the current capability source owner as its focused
unit-test file. Architecture, verification, and decision rows name
`tests/dependency_verification_matrix_contract.rs` as their local structural
gate. This does not claim that future behavior tests already exist. The owning
bead must replace its planned row with retained evidence at implementation
closeout.

Every evidence plan has state `PLANNED_BLOCKING`. That value is intentional:
the plan is a checked obligation, not executed proof. It may never be
translated to `PASS`, `SAME`, `BETTER`, or cutover approval merely because VER
A1 is green.

## Required cases

Every work bead requires focused coverage for:

- happy path;
- empty and boundary values;
- maximum values and overflow;
- malformed input and error mapping;
- resource bounds;
- a stable regression fixture.

Risk tags add obligations:

| Risk | Additional mandatory cases and evidence |
| --- | --- |
| `parser_codec` | truncation, invalid state, round trip, independent vector, deterministic property plan |
| `concurrency` | cancellation, race/shutdown, task leak, obligation leak, loser drain, quiescence, deterministic lab plan |
| `security` | misuse, authentication failure, secret redaction, adversarial fuzz plan |
| `public_generic` | public-only downstream compile and runtime fixtures without `test-internals` |
| `fuzz` | bounded input/time, owned corpus, crash artifacts, minimization, oracle-retirement independence |
| `user_journey` | stable no-mock scenario in the `dependency-sovereignty` E2E suite |

Local unit or structural-contract plans cover the row's complete required case
set. Specialized property, lab, fuzz, downstream, and E2E plans add the
execution shape and retained evidence needed for higher-risk claims.

## Concurrency and deterministic evidence

Concurrent rows use fixed lab seeds, virtual time, and these registered
oracles:

- `task_leak`
- `obligation_leak`
- `loser_drain`
- `cancellation_protocol`
- `quiescence`

The minimum plan cannot be weakened to a wall-clock stress test or log-string
assertion. If a failure depends on schedule or seed, the owner retains the
minimized seed, trace fingerprint, artifact root, and exact RCH replay command.

## Property and fuzz evidence

Property rows reserve deterministic seed range `0..64`. Lab lifecycle rows
reserve `0..16`. Owners may widen those ranges, but may not replace them with
ambient entropy or omit the first minimized failure.

Fuzz rows specify:

- a stable target and corpus path;
- the bead that owns corpus maintenance;
- a maximum input of 1 MiB;
- a bounded 60-second focused run;
- a stable crash-artifact path;
- an exact `cargo fuzz tmin` command;
- `oracle_retirement_independent = true`;
- `oracle_evidence_may_authorize_cutover = false`.

An incumbent or external implementation may remain a differential oracle, but
its green output is never sufficient cutover authority. Oracle quarantine,
expiry, renewal, and retirement remain owned by the separate oracle-policy
campaign.

## Public and generic surfaces

Any row tagged `public_generic` includes both compile and runtime downstream
fixtures. The fixture is public-only and must not enable `test-internals`.
Finite internal schemas, selected repository call sites, or a root-export scan
cannot stand in for generic downstream usability.

The affected feature and platform coordinates remain listed on every row even
when the focused unit command uses only the contributor profile. Sparse
feature, target, platform, and service-version execution is owned by VER A5;
VER A1 makes those coordinates mechanically visible so they cannot be silently
lost.

## Real-service and user-journey evidence

User-visible, service, wire, persisted-format, protocol, CLI, daemon, and
operational rows name a stable scenario in:

```text
scripts/run_all_e2e.sh --suite dependency-sovereignty
```

VER A2 owns the runner and schema. Each terminal run must retain:

```text
target/e2e-results/dependency-sovereignty/<run_id>/summary.json
target/e2e-results/dependency-sovereignty/<run_id>/events.ndjson
target/e2e-results/dependency-sovereignty/<run_id>/scenarios.ndjson
target/e2e-results/dependency-sovereignty/<run_id>/validation_stages.ndjson
target/e2e-results/dependency-sovereignty/<run_id>/artifact_manifest.ndjson
target/e2e-results/dependency-sovereignty/<run_id>/environment.json
target/e2e-results/dependency-sovereignty/<run_id>/repro_manifest.json
target/e2e-results/dependency-sovereignty/<run_id>/<scenario_id>/<step_id>.stdout.log
target/e2e-results/dependency-sovereignty/<run_id>/<scenario_id>/<step_id>.stderr.log
```

A plan row is not a silent substitute for that no-mock run. `BLOCKED`,
`UNSUPPORTED`, missing hardware, missing service, redaction failure, replay
failure, or cleanup residue remains non-green.

### VER A2 runner operation

The maintained runner is
`scripts/run_dependency_sovereignty_e2e.sh`. The primary orchestrator registers
it as `dependency-sovereignty` with canonical suite ID
`E2E-SUITE-DEPENDENCY-SOVEREIGNTY`.

The default smoke profile runs two local, non-Cargo contract scenarios:

- `catalog` checks the live 335-bead, 50-capability, 1,595-plan VER A1 matrix
  and its 197 planned E2E rows;
- `runner-contract` exercises the happy path and eleven fail-closed outcome
  classes: assertion failure, command failure, timeout, signal, unsupported
  platform, blocked RCH, local fallback, corrupt summary, missing artifact,
  replay failure, and cleanup failure. It separately injects a deterministic
  canary through the redaction filter.

The runner also exposes four opt-in Cargo-backed contract scenarios:
`registry-contract`, `baseline-contract`, `cutover-policy-contract`, and
`verification-matrix-contract`, plus the VER A4
`failure-injection-contract`. They refuse execution unless
`RCH_REQUIRE_REMOTE=1` and `rch` are both present; a local fallback marker is a
terminal non-green result.

Useful commands:

```bash
# Discover the stable scenario IDs without creating a run directory.
bash scripts/run_dependency_sovereignty_e2e.sh --list

# Emit a complete contract-only bundle through the primary orchestrator.
bash scripts/run_all_e2e.sh --suite dependency-sovereignty

# Preview selected scenario commands and artifacts without executing them.
bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario registry-contract \
  --scenario verification-matrix-contract \
  --run-id review-001 \
  --dry-run

# Execute one Cargo-backed scenario with remote-only admission.
RCH_REQUIRE_REMOTE=1 \
  bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario verification-matrix-contract \
  --run-id ver-a2-matrix-001

# Execute the deterministic VER A4 failure-injection matrix contract.
RCH_REQUIRE_REMOTE=1 \
  bash scripts/run_dependency_sovereignty_e2e.sh \
  --scenario failure-injection-contract \
  --run-id ver-a4-failure-matrix-001
```

`--scenario` may be repeated. `--timeout` bounds each scenario; the direct
runner default is 900 seconds so an uncached remote Cargo scenario can finish.
An explicit `E2E_TIMEOUT` or `DEPENDENCY_SOVEREIGNTY_TIMEOUT` overrides it.
`--fail-fast` records later scenarios as `NOT_RUN_FAIL_FAST`;
`--continue-for-diagnostics` is the default. An explicit run ID is validated
against ASCII letters, digits, dot, underscore, and hyphen, and the runner
refuses to overwrite an existing evidence directory.

Every scenario and validation-stage row records the bead, track, capabilities,
scenario and step IDs, validation surface, feature/profile coordinates, seed
or fixture, configuration snapshot, exact command, expected and observed
outcome, exit and signal, monotonic elapsed time, artifact links, RCH routing,
worker and target directory, evidence owner, redaction policy, first failing
invariant, cleanup result, and replay pointer. The safe environment snapshot is
allowlisted; arbitrary process environment values are not retained.

### VER A4 failure-injection mapping

`artifacts/dependency_failure_injection_matrix_v1.json` maps the live VER A1
replacement inventory to deterministic cancellation, error, recovery, panic,
leak, loser-drain, finalizer, region-tree, and quiescence obligations. Its
focused contract is
`tests/dependency_failure_injection_matrix_contract.rs`; its stable E2E step is
`ver-a4-failure-injection-contract`.

The contract requires bounded steps and virtual time, deterministic drivers or
real process control, structured receipts, exact replay commands, and cleanup
on success, error, cancellation, and panic. Sleeps used to create races,
ambient randomness, mocks, unbounded waits, and log-substring pass criteria are
fail-closed. See `docs/dependency_failure_injection_matrix.md` for the
applicability rules, receipt fields, negative fixtures, and no-claim boundary.

The suite root maintains machine-readable `latest.json` and
`latest_success.json` pointers. A failed or blocked attempt advances only
`latest.json`; it cannot replace the last passing pointer.

## Regeneration

Build the generator through RCH:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env \
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_verification_matrix" \
  cargo build -p asupersync --bin dependency_verification_matrix
```

RCH retrieves the built binary into the requested local target directory. Use
that reviewed binary to rewrite only the reserved canonical artifact:

```bash
"${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_verification_matrix/debug/dependency_verification_matrix" \
  --write artifacts/dependency_verification_matrix_v1.json
```

The generator fingerprints only plan-semantic tracker fields, dependencies,
explicit capability-authority comments, and superseded-duplicate disposition.
Routine claim/status churn does not make the artifact stale. New work nodes,
changed contracts, changed edges, changed mappings, or changed duplicate
disposition do.

## Validation

Run the focused fail-closed contract through RCH:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env \
  CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_verification_matrix" \
  cargo test -p asupersync --test dependency_verification_matrix_contract -- --nocapture
```

The contract compares the canonical artifact byte-for-byte with fresh
generator output, joins it to the live tracker and capability registry, checks
all counts and references, and exercises negative mutations for missing happy,
edge, malformed, resource, cancellation, security, regression, downstream,
fuzz-bound, corpus, minimization, invariant, uniqueness, and cutover-blocking
requirements.

## No-claim boundary

This matrix and its contract prove deterministic plan coverage and fail-closed
schema behavior only. They do not execute the planned behavior tests, prove
runtime correctness, service interoperability, performance, broad workspace
health, release readiness, RCH fleet availability, or authorize dependency,
feature, API, format, protocol, platform, diagnostic, user-journey, or file
removal.
