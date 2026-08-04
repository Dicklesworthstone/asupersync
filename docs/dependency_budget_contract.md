# Dependency Budget Contract

Bead: `asupersync-mnotoo.1`

## Purpose

The checked artifact at `artifacts/dependency_budget_contract_v1.json` freezes
two dependency-sovereignty budgets:

1. the exact set of direct Cargo dependency edges, including normal, build,
   dev, and target-qualified kinds; and
2. package-version and unique-package-name ceilings for every canonical
   synthesized out-of-workspace consumer graph.

`tests/dependency_budget_contract.rs` fails closed when either surface grows.
It also contains safe in-memory negative fixtures that inject a trivial direct
edge and a one-package graph increase without changing `Cargo.toml` or any
other repository file.

This contract does not authorize dependency removal, replacement, or cutover.
It enforces the budget surface owned by `CAP-DEPENDENCY-LEDGER`.

## Measurement source

The budget consumes `artifacts/dependency_marginal_ledger_v1.json`. The
Cargo-built generator at `src/bin/dependency_marginal_ledger.rs` exposes
`--budget-from-ledger` so the budget and marginal measurements cannot silently
diverge onto different resolver methodologies.

The source ledger resolves neutral consumer crates outside the workspace.
Package IDs, rather than package-name text, define reachability. Every budget
cell retains:

- feature profile;
- target triple;
- host triple;
- Cargo dependency edge kind for the active direct-edge partition;
- package-version ceiling; and
- unique-package-name ceiling.

The `workspace-dev-build-audit` profile is recorded as an excluded graph
scope. Its feature-unified workspace graph remains useful audit evidence, but
it is not substituted for a neutral consumer ceiling. The fuzz-quarantine
profile is a synthesized consumer and remains explicitly quarantined rather
than becoming a production claim.

## Ratchet behavior

Regeneration compares the fresh ledger projection with the existing budget:

- a removed direct edge disappears from the allowset;
- a smaller graph writes the smaller count, so ceilings ratchet down;
- a new direct edge fails before output;
- a larger package-version or unique-name count fails before output.

The generator also verifies that the frozen ledger's direct-edge inventory
still equals the current root `Cargo.toml`. A manifest change therefore cannot
be admitted by updating only one artifact.

The ordinary reviewed state has an empty `reviewed_exceptions` array.

## Rare reviewed exception

An increase is exceptional. Before regeneration, a reviewer must add one
narrow row to the existing artifact's `reviewed_exceptions` array. Every row
requires:

- `exception_id`;
- `exception_kind`;
- `reviewed_by`;
- `approved_on`;
- `expires_on`;
- `review_reference`; and
- `rationale`.

For `direct-dependency-addition`, also provide the exact `direct_root_edge`.
For `graph-ceiling-increase`, also provide the exact feature profile, target
triple, host triple, and the approved package-version and unique-name ceilings.
The generator accepts only an exact matching row whose approved counts cover
the fresh graph. The review must explain why the capability cannot be
preserved within the prior ceiling, link the owning bead or review record, and
set a finite expiry for follow-up.

The focused contract checks the exception schema. Expiry and approval remain
operator-review obligations; an exception is not evidence that the larger
graph is desirable.

## Reproducible regeneration

Regenerate the source marginal ledger first if `Cargo.toml`, feature profiles,
targets, or the lockfile changed. Then, from a clean `main`, project the budget
through remote-required RCH:

```bash
set -o pipefail
SOURCE_COMMIT="$(git rev-parse HEAD)"
RCH_REQUIRE_REMOTE=1 rch exec -q \
  --base "$SOURCE_COMMIT" --clean-overlay --no-overlay -- \
  env CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_budget_generate" \
      CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
      RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo run --quiet -p asupersync \
    --bin dependency_marginal_ledger \
    --no-default-features --features dependency-ledger -- \
    --source-commit "$SOURCE_COMMIT" \
    --budget-from-ledger artifacts/dependency_marginal_ledger_v1.json \
    --output - \
  2>&1 | sed '/^\[RCH\] remote /d' \
  > artifacts/dependency_budget_contract_v1.json
```

When the canonical budget already exists, the generator reads it before
rendering stdout and applies the ratchet checks. RCH quiet mode relays remote
stdout on stderr, so `pipefail` and the narrow status-line filter are required
to avoid converting a remote failure into an apparently valid artifact.

Validate the artifact with:

```bash
jq empty artifacts/dependency_budget_contract_v1.json
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_dependency_budget_contract" \
      CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
      RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync --features dependency-ledger \
    --test dependency_budget_contract -- --nocapture
```

The canonical focused proof lane is `dependency-budget-contract`.

## No-claim boundaries

Passing the lane proves the checked allowset, synthesized-consumer cell keys,
ledger fingerprint, graph ceilings, safe negative fixtures, generator markers,
documentation markers, and proof-manifest/status mapping remain aligned.

It does not prove compilation, runtime correctness, security, performance,
interoperability, release readiness, broad workspace health, workspace
dev/build graph health, excluded fuzz health, live RCH fleet availability, or
permission to change a dependency.
