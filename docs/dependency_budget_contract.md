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

## AGENTS key-dependency projection readiness

Bead `asupersync-mnotoo.3.6` owns a future Cargo-built projection of the
`AGENTS.md` **Key Dependencies** table. That projection is not implemented or
admitted yet. The current sources expose a concrete metadata gap that must be
closed before a generator can be truthful:

| Surface | Current checked state | Required projection state |
| --- | --- | --- |
| `allowed_direct_dependencies` | 105 exact edge rows with dependency/package name, edge kind, manifest table, target condition, and optionality | Retain these rows as the manifest-membership authority |
| Documentation metadata | No purpose, feature/profile, documentation tier, display grouping, or display order fields | Add an explicit checked projection object; do not infer prose from crate names or Cargo kinds |
| `AGENTS.md` table | 14 manually curated rows covering 15 crate names because `serde` and `serde_json` share one row; two columns only | Render the exact checked row set with Crate, Purpose, Feature/Profile, and Tier columns |
| Cargo generator | `dependency_marginal_ledger` can emit the ledger and budget only | Add one explicit AGENTS render/check mode that reuses the checked budget input |
| Contract | Pins broad README/AGENTS markers, direct edges, and graph ceilings | Reject missing, extra, duplicate, stale, reordered, or differently rendered projection rows |

The budget artifact must gain one canonical `agents_key_dependencies`
projection object before AGENTS generation is enabled. Its row schema must
contain:

- a stable `row_id` and integer `display_order`;
- one or more exact `dependency_names`, allowing a grouped display row only
  when the grouping is explicit in metadata;
- nonempty `purpose` text;
- one or more checked `feature_profiles` or an explicit dev/build scope; and
- a `tier` from a closed documented enum such as core runtime, optional
  production, development/test, or development/benchmark.

Every dependency name in that projection must join to at least one
`allowed_direct_dependencies` row. A dependency name may occur in only one
display row, every feature/profile value must join to the budget's canonical
profile vocabulary, and the rendered row order must equal `display_order`.
The key-dependency table is intentionally a curated projection, not a
replacement for the complete 105-edge allowset.

### Reviewed projection seed

The following seed preserves the current reviewed purpose meaning and order
while separating activation details from purpose text and pinning the exact
direct-edge joins needed by the future machine object. It is design input only:
until the object, renderer, and contract land, this table is not a second
metadata authority and does not make the AGENTS table generated.

For readability, **all consumer profiles** below means the exact current
profile vocabulary: `cli`, `compression`, `default`, `fuzz-quarantine`,
`io-uring`, `kafka`, `loom-tests`, `metrics`, `minimal`, `sqlite`, `tls`, and
`trace-compression`. That phrase is documentation shorthand, not an admissible
JSON feature value; the future object must store the expanded values. Dev rows
instead use an explicit `development_scope`, which is mutually exclusive with
`feature_profiles`. The closed tier enum for this projection is
`core-runtime`, `optional-production`, `development-test`, and
`development-benchmark`.

| Order | Stable row ID | Exact dependency and edge join | Activation or development scope | Purpose | Tier |
| ---: | --- | --- | --- | --- | --- |
| 10 | `key-thiserror` | `thiserror` -> `normal:thiserror` | all consumer profiles | Ergonomic error type derivation | `core-runtime` |
| 20 | `key-crossbeam-queue` | `crossbeam-queue` -> `normal:crossbeam-queue` | all consumer profiles | Lock-free concurrent queues | `core-runtime` |
| 30 | `key-parking-lot` | `parking_lot` -> `normal:parking_lot` | all consumer profiles | Fast synchronization primitives | `core-runtime` |
| 40 | `key-polling` | `polling` -> `target-normal:cfg(not(target_arch = "wasm32")):polling` | all consumer profiles; `cfg(not(target_arch = "wasm32"))` | Portable epoll/kqueue/IOCP polling | `core-runtime` |
| 50 | `key-slab` | `slab` -> `normal:slab` | all consumer profiles | Pre-allocated storage for fixed-size records | `core-runtime` |
| 60 | `key-smallvec` | `smallvec` -> `normal:smallvec` | all consumer profiles | Stack-allocated small vectors | `core-runtime` |
| 70 | `key-pin-project` | `pin-project` -> `normal:pin-project` | all consumer profiles | Safe pin projections | `core-runtime` |
| 80 | `key-serde-json` | `serde` -> `normal:serde`; `serde_json` -> `normal:serde_json` | all consumer profiles | Serialization | `core-runtime` |
| 90 | `key-socket2` | `socket2` -> `target-normal:cfg(not(target_arch = "wasm32")):socket2` | all consumer profiles; `cfg(not(target_arch = "wasm32"))` | Low-level socket configuration | `core-runtime` |
| 100 | `key-rustls` | `rustls` -> `normal:rustls` | `tls`; optional | TLS support | `optional-production` |
| 110 | `key-rusqlite` | `rusqlite` -> `normal:rusqlite` | `sqlite`; optional | SQLite async wrapper | `optional-production` |
| 120 | `key-proptest` | `proptest` -> `dev:proptest` | `development_scope = "test"` | Property-based testing | `development-test` |
| 130 | `key-criterion` | `criterion` -> `target-dev:cfg(not(windows)):criterion` | `development_scope = "benchmark"`; `cfg(not(windows))` | Benchmarking | `development-benchmark` |
| 140 | `key-rayon` | `rayon` -> `dev:rayon` | `development_scope = "benchmark"` | Data parallelism for CPU-bound work | `development-benchmark` |

### Pinned projection object and table bytes

The future top-level `agents_key_dependencies` value is an object, not a
second free-form document. It has exactly these object-level fields:

- `schema_version`, fixed at `1`;
- `bead_id`, fixed at `asupersync-mnotoo.3.6`;
- `heading`, `begin_marker`, and `end_marker` strings fixed to the values in
  the renderer interface below;
- `columns`, fixed in order to `Crate`, `Purpose`, `Feature/Profile`, and
  `Tier`;
- `consumer_profile_vocabulary`, equal as a set to the synthesized-consumer
  profile names in `graph_ceilings` and stored in ascending lexical order;
- `tier_vocabulary`, fixed in order to `core-runtime`,
  `optional-production`, `development-test`, and
  `development-benchmark`; and
- `rows`, containing the 14 reviewed rows above in ascending
  `display_order`.

Each row has exactly `row_id`, `display_order`, `dependency_names`,
`direct_edge_ids`, `purpose`, `optional`, `target_conditions`, `crate_cell`,
`feature_profile_cell`, and `tier`, plus exactly one of `feature_profiles` or
`development_scope`. `dependency_names`, `direct_edge_ids`,
`target_conditions`, and `feature_profiles` are arrays of unique strings.
Empty `target_conditions` is valid; the other array fields must be nonempty.
`development_scope` is either `test` or `benchmark`. Unknown fields, nulls,
duplicate values, and an empty string fail closed rather than being ignored.
Row IDs and positive display orders must also be unique. Feature profiles are
stored in ascending lexical order; dependency names retain display order.

The semantic and display fields are deliberately both checked. For example,
the first row is represented by metadata equivalent to:

```json
{
  "row_id": "key-thiserror",
  "display_order": 10,
  "dependency_names": ["thiserror"],
  "direct_edge_ids": ["normal:thiserror"],
  "purpose": "Ergonomic error type derivation",
  "optional": false,
  "target_conditions": [],
  "feature_profiles": [
    "cli", "compression", "default", "fuzz-quarantine", "io-uring",
    "kafka", "loom-tests", "metrics", "minimal", "sqlite", "tls",
    "trace-compression"
  ],
  "crate_cell": "`thiserror`",
  "feature_profile_cell": "all consumer profiles",
  "tier": "core-runtime"
}
```

The contract must cross-check `crate_cell` against `dependency_names`: one
dependency is one code span, while an explicitly grouped row joins code spans
with the literal ` + ` separator in array order. It must cross-check every
`direct_edge_id` against the named dependency and every target condition
against those exact allowset rows. The row's `optional` value must equal the
value on every joined allowset row. `feature_profile_cell` is reviewed
display metadata, not text inferred from an edge kind; the semantic profile,
development-scope, optionality, and target-condition fields prove what that
display text means.

The renderer emits UTF-8 with LF line endings, no leading blank line, and
exactly one LF after the final row. It emits this fixed header and separator,
then one row per ascending `display_order`:

```text
| Crate | Purpose | Feature/Profile | Tier |
| --- | --- | --- | --- |
| {crate_cell} | {purpose} | {feature_profile_cell} | `{tier}` |
```

The braces above describe substitution; they are not emitted. Stored cell
text must be trimmed and must not contain CR, LF, or a Markdown table
delimiter (`|`). Render mode emits neither marker line. Check mode compares
the bytes immediately after the begin marker's LF through the LF immediately
before the end marker, so whitespace-only drift is still drift.

The future contract must validate each edge string above against
`allowed_direct_dependencies`, expand each consumer-profile set against the
graph-ceiling vocabulary, and verify the two target conditions verbatim. The
rendered Feature/Profile cells may use concise display text, but that text must
come from checked projection metadata rather than being reconstructed from
Cargo edge kinds.

The future renderer must use unique begin/end marker lines, fail on missing,
duplicate, nested, or reversed markers, and replace only the bytes between
those markers. Check mode must render in memory and reject drift without
writing; the reviewed update path must use the same rendered bytes and preserve
every byte outside the marked region. Until the metadata object, renderer,
markers, and focused contract land together, the table remains manually
maintained and this lane makes no generated-document or drift-prevention claim.

### Pinned renderer interface and remote boundary

The future implementation must use these exact, trimmed marker lines:

```text
<!-- BEGIN GENERATED AGENTS KEY DEPENDENCIES -->
<!-- END GENERATED AGENTS KEY DEPENDENCIES -->
```

The `### Key Dependencies` heading stays outside the generated region. The
begin marker must be the next nonblank line after that heading, the end marker
must precede the next heading, and only the four-column Markdown table belongs
between them. The markers must not be added to `AGENTS.md` until the metadata
object, renderer, and focused contract land in the same reviewed change.

The Cargo-built tool must extend the existing argument style with one input
selector, `--agents-key-dependencies-from-budget PATH`, and exactly one of two
mutually exclusive modes:

- `--render-agents-key-dependencies` validates the budget artifact and writes
  only the canonical bytes that belong between the markers to stdout;
- `--check-agents-key-dependencies` renders in memory, compares the marked
  region in `AGENTS.md`, exits nonzero on any marker or content drift, and
  performs no writes.

These modes may accept the existing `--repo-root` selector. They must reject
ledger-generation options such as `--work-dir`, `--output`, `--source-commit`,
`--budget-from-ledger`, `--jobs`, `--offline`, `--profiles`, and `--targets`
rather than silently combining two output contracts. Render stdout contains
the table only; diagnostics belong on stderr so a caller never mistakes a
status line for documentation.

Cargo execution remains remote-only. A process running on an RCH worker must
not be assumed to mutate the local checkout, and the render command must never
be redirected directly onto `AGENTS.md`: the local shell can truncate the file
before the remote exit status is known. The reviewed update workflow is:

1. reserve `AGENTS.md`, the budget artifact, generator, contract, and this
   runbook;
2. render the canonical table from the exact clean-overlay source snapshot;
3. review the captured stdout and use `apply_patch` to replace only the bytes
   between the two marker lines;
4. rerun read-only check mode and the focused contract against that exact
   snapshot; and
5. verify the staged path set and outside-marker bytes before committing.

An automatic local update mode may be added only after its RCH-to-local
round-trip and failure atomicity are separately demonstrated. Until then,
render plus reviewed marker-scoped `apply_patch` is the only documented update
path and makes no automatic-update claim.

## Ratchet behavior

Regeneration compares the fresh ledger projection with the existing budget:

- a removed direct edge disappears from the allowset;
- a smaller graph writes the smaller count, so ceilings ratchet down;
- a new direct edge fails before output;
- a larger package-version or unique-name count fails before output.

The generator also verifies that the frozen ledger's direct-edge inventory
still equals the current root `Cargo.toml`. A manifest change therefore cannot
be admitted by updating only one artifact.

The ordinary reviewed state has an empty `reviewed_exceptions` array. The
v0.4.0 release carries two finite, exact exceptions for `dev:tracing-log` and
`normal:tracing-log`: the former is dev-only, while the latter is optional and
confined to `test-internals`. Both support an explicit log-to-tracing bridge,
never install it implicitly, and expire on 2026-11-08 for follow-up review.

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
