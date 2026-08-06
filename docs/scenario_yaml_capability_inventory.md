# YAML scenario capability inventory

<!-- BEGIN SCENARIO YAML CAPABILITY INVENTORY -->

This is the operator-readable companion to
`artifacts/scenario_yaml_capability_inventory_v1.json`. It freezes the live
scenario-format baseline for `asupersync-5z2scg.5.1` and
`CAP-SCENARIO-YAML-JSON`, with its cross-cutting
`CAP-LAB-DETERMINISM` obligation, at revision
`295136459f9e3e38e7373394e713866ec0693a8d`.

The governing `DEP-ADR-004` decision is additive coexistence:
`KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`. YAML remains accepted. JSON may be
added, but no child before terminal A5 may authorize removing `serde_yaml` or
narrowing the accepted YAML corpus.

## What actually parses YAML

The public `Scenario` model in `src/lab/scenario.rs` is format-neutral. It
derives serde traits and already exposes `Scenario::from_json` and
`Scenario::to_json`; it does not call `serde_yaml`.

There are two production/developer loader implementations:

| Stable ID | Build profile | Loader | Read and parse behavior |
| --- | --- | --- | --- |
| `SCN-LOADER-ASUPERSYNC-CLI` | root `cli` feature | `bin/asupersync.rs::load_scenario` | whole-file `read_to_string`, then `serde_yaml::from_str::<Scenario>` |
| `SCN-LOADER-FRANKENLAB` | `frankenlab` member | `main.rs::load_scenario` | whole-file `read_to_string`, then `serde_yaml::from_str::<Scenario>` |

Two additional test-local loaders live in `tests/frankenlab_integration.rs` and
`frankenlab/tests/adoption_funnel.rs`. The root crate carries `serde_yaml` as
an optional normal dependency enabled by `cli` and as a dev dependency.
`frankenlab` carries it directly. The resolved version is
`serde_yaml 0.9.34+deprecated`, backed by `unsafe-libyaml 0.2.11`.

The default library profile has no normal `serde_yaml` edge. The
`messaging-fabric` feature adds four reportable oracle names, not another YAML
loader.

## Typed schema and defaults

`Scenario` has 16 root fields. Only `id: String` lacks a serde default.
Consequently an empty YAML document is rejected during typed deserialization;
an `id`-only document receives all remaining Rust defaults and validates if
the ID is nonempty.

The root fields are `schema_version`, `id`, `description`, `lab`, `chaos`,
`network`, `faults`, `participants`, `oracles`, `cancellation`,
`resource_caps`, `expected_invariants`, `minimization`, `golden_projection`,
`include`, and `metadata`.

The machine artifact enumerates every nested typed field:

- nine lab fields;
- seven custom-chaos fields;
- the network preset and link map, six link-condition fields, and three
  latency variants;
- three fault-event fields and eleven action variants;
- three participant fields;
- three cancellation fields and seven strategies;
- three resource-cap fields;
- three minimization fields;
- three golden-projection fields;
- include paths, string metadata, nine validated dynamic fault-argument keys,
  five supported expected-invariant names, and the oracle selection domain.

Unknown fields are currently accepted and ignored because the typed structs do
not use `deny_unknown_fields`. Comments and input layout are accepted but
discarded.

### Canonical JSON contract

`Scenario::to_json` is the additive canonical machine form for schema v1. It
emits compact UTF-8 with no trailing newline, sorts every object key
lexicographically and recursively, and preserves array order. Integer fields
remain exact base-10 JSON integers; duration fields ending in `_ms` are unsigned
integer milliseconds; finite decimals use serde_json's stable shortest form.
The encoder materializes `schema_version`, all typed defaults, and every typed
field.

An input without `schema_version` follows the existing typed default to v1;
encoding that value produces the same bytes as an explicit v1 document with the
same fields. Unsupported versions remain parseable for located diagnostics and
are rejected by `Scenario::validate`. The preserved free-form extension
channels are `metadata`, `participants[].properties`, and `faults[].args`.
Unknown typed-struct fields retain the frozen accept-and-discard behavior; A3
owns parser parity and bounds rather than A2 silently tightening that policy.

The fixed byte golden, recursive dynamic-map ordering, full typed equality,
missing-version migration, and YAML-to-JSON replay-identity checks are
executable tests. The library encoder does not add a CLI conversion command or
make `golden_projection.format` select an output form; those authoring and
projection surfaces remain routed to A4.

## Observed YAML grammar

The executable contract freezes observed typed behavior instead of assuming
the whole YAML specification.

Accepted constructs include block and flow mappings/sequences, quoted and
block strings, Unicode, comments, anchors and aliases, tagged string scalars,
null for `Option`, `u64::MAX`, and hexadecimal, octal, and binary integers.
Aliases resolve before typed deserialization. For a typed `String` target,
serde_yaml 0.9 also coerces an unquoted null scalar to the literal string
`"null"`; this surprising behavior is part of the frozen baseline.

The important boundaries are:

- duplicate mapping keys are rejected with parser location;
- multiple YAML documents are rejected;
- null maps to `None` for `Option`, but to literal `"null"` for `String`;
  integers above `u64::MAX` are rejected;
- YAML 1.2 boolean resolution applies: `true` and `false` are booleans, while
  legacy `yes`/`no` forms remain strings and fail for a bool target;
- `.nan` and infinities parse as floats, then scenario probability validation
  rejects non-finite values;
- a merge key is not applied by the typed loaders. `serde_yaml::Value` has an
  explicit `apply_merge` operation, but no production loader calls it, so
  `<<` is merely an ignored unknown field in a typed section;
- arbitrary scalar tags do not invoke code and are transparent for the tested
  string target;
- serde_yaml has an internal recursion counter starting at 128 and an alias
  repetition guard, but the application loaders define no document-byte,
  scalar-length, collection-count, or overall parsing-work policy.

## Exact checked-in corpus

The typed Scenario corpus contains 13 files:

- ten files under `examples/scenarios/`;
- three files under `frankenlab/examples/scenarios/`.

Every file path, SHA-256 digest, line count, and byte count is frozen in the
machine artifact. The focused contract reparses and semantically validates all
13.

`tools/demos/time_travel.yaml` is adjacent, not part of the typed corpus. Its
six root keys are `schema_version`, `name`, `description`, `seed`, `scenario`,
and `expected`, not the `Scenario` schema. Both CLIs have generic user-selected
path loaders, but no current source literal or discovery route automatically
selects this file. `make demo-benchmark` runs `examples/demo_benchmark.rs`,
which uses compiled constants and consumes JSON golden checksums rather than
that YAML file. The scenario inventory contract is a test-only governance
reader. CI workflow YAML and `pnpm` metadata are likewise explicitly adjacent.

The ADR and machine registry now state the exact two-root, 13-file typed corpus
and classify this demo reference separately. The focused contracts were not
executed in the static A4 lane, so `SCN-GAP-12` remains fail-closed.

## Author workflows

The root CLI exposes:

- `asupersync lab run <scenario>`;
- `asupersync lab validate <scenario>`;
- `asupersync lab replay <scenario>`;
- `asupersync lab explore <scenario>`.

The `frankenlab` member exposes corresponding run, validate, replay, and
explore commands, plus minimize and demo workflows. Run and explore can emit
JSON result objects. Replay emits a JSON-shaped report and the root CLI may
write an optional replay artifact.

Neither CLI accepts a JSON `Scenario` input. Neither CLI has a Scenario dump
command or emits canonical Scenario JSON. Existing JSON is result/artifact
output. `Scenario::to_json` is the shipped library-only canonical encoder for
the typed Scenario schema; it is not a CLI conversion path or a shared config
encoder.

The author guide at `docs/adoption/getting_started.md` now states the current
YAML grammar, diagnostics, field-consumption, include, and JSON boundaries. At
typed struct boundaries, unknown fields are accepted and discarded; a typo can
therefore silently leave a default in effect. YAML anchors and aliases resolve,
but `<<` merge keys are not applied by either application loader.

## Parsing is not execution

The frozen runner-consumption inventory prevents parsed fields from being
mistaken for active runtime capability.

Actively consumed fields include scenario identity/metadata, lab
configuration, chaos policy, oracle selection, and the fault list. Resource
caps, minimization, and golden projection are only partially consumed.

Several declared capabilities are currently validation-only:

- `include` paths are checked, but no loader resolves, reads, or merges them;
- network presets and link conditions never reach `ScenarioRunner`;
- cancellation strategies never reach `ScenarioRunner`;
- participant names validate fault references, while participant roles and
  properties are unused;
- expected invariants are validated but do not select or enforce checks;
- golden format is unused, and `canonicalized` is validation-only.

`golden_projection.redacted` is also validation-only; it does not scrub output.
Every `faults[].args` key and value is copied into user-trace text, and JSON run
results include the fault log. Scenario authors must not put credentials,
tokens, personal data, or other private values in those maps or elsewhere in a
scenario document.

Fault injection is also partial. Every fault becomes a timed user-trace entry.
Disk pressure/recovery, delayed cleanup, and process stall/resume affect a
synthetic summary. Partition/heal, host crash/restart, and clock skew/reset do
not simulate those behaviors.

Most importantly, the YAML schema does not schedule an application workload.
Descriptions such as send-permit, lease, saga, and 10K-task stress are
narrative metadata, not executable task definitions. A valid file can run an
otherwise empty lab runtime and report success. This inventory does not call
that runtime-feature parity.

## Diagnostics and resource boundaries

The root CLI distinguishes read, parse, validation, unknown-oracle, assertion,
and replay errors. Parser failures use `scenario_parse_error`, the user-error
exit class, path context, parser text and location when serde_yaml provides it,
plus a generic indentation/field-name hint. Frankenlab returns equivalent
plain strings.

`Scenario::validate` returns all semantic problems with field-like paths, but
those paths are not YAML source spans. `ScenarioRunnerError` includes
`[ASUP-E401]` in replay-divergence `Display`; both CLI adapters reconstruct
their own replay text and lose that stable token.

Both loaders publish a fully deserialized temporary value or an error, so a
parse failure cannot expose a partial `Scenario`. They nevertheless read the
entire file without application-level size or work limits. The root replay
artifact writer now has an authored same-directory staged-write, staged-file
sync, and no-clobber publication path; that source has not been compiled or
executed in this static lane.

## A3.1 current-surface and acceptance-satisfiability audit

`asupersync-5z2scg.5.3.1` refreshed the live source at revision
`207a435d59bad452239caa773f3a7c64c8b5edbc`. This is a static source and
artifact audit. A3.1 did not rerun the A1/A2 executable evidence and does not
promote the parent A3 decision to a terminal cutover receipt.

The refresh found six stale A1 source pins (`Cargo.toml`, `Cargo.lock`,
`src/lab/mod.rs`, `src/bin/asupersync.rs`, `examples/metadata.json`, and
`TESTING_FOR_AGENTS.md`) and refreshed them. It also pins the semantic adjacent
consumer, its workflow input, all currently known YAML writer classes, the
selected adjacent-classification anchors, and the registry/baseline/API-map
authorities. The source-pin inventory now contains 32 unique tracked current
paths. Untracked local lockfiles are outside this pin inventory. All 13 Scenario
corpus files still match their A1 hashes, line counts, and byte counts.

A 2026-08-05 static provenance pass refreshed three stale pins against
`6b5d0638aabc84dfafa078936e3892ed77bfa196`. The shared ADR gained only the
independent config A3 KEEP receipt and its related evidence/no-claim wording;
the methodology workflow changed only ten action source references, with all
non-action content byte-identical; and the capability baseline gained 1,853
append-only audit lines while both mapped capability rows stayed byte-identical.
The pass also updates the contract's own pin after adding a fail-closed check
for this maintenance receipt, for four refreshed rows in the unchanged 32-path
set. Scenario acceptance semantics, historical A3.1/A3.2 revisions, and the
`KEEP_INCUMBENT` result did not change. This pass did not rerun executable
evidence.

### Current dependency edges

| Edge | Profile | Current declaration | Consequence |
| --- | --- | --- | --- |
| root optional normal | `asupersync --features cli` | `serde_yaml = { version = "0.9", optional = true }`, activated by `cli -> dep:serde_yaml` | retains the root production loader; absent from the default library profile |
| root dev | root tests | `serde_yaml = "0.9"` | retains Scenario grammar/corpus tests and the adjacent workflow parser |
| frankenlab normal | `frankenlab` binary and tests | `serde_yaml = "0.9"` | retains the second production loader and adoption tests |

The lock still resolves `serde_yaml 0.9.34+deprecated` (checksum
`6a8b1a…b47`) through `unsafe-libyaml 0.2.11` (checksum `673aac…861`).
This is inventory, not a dependency-safety or vulnerability claim.

### Consumer and writer matrix

| Stable surface | Class | Read/write path | Application input bound |
| --- | --- | --- | --- |
| `SCN-A3-CONSUMER-ROOT-CLI` | production Scenario loader | whole-file `read_to_string`, then `serde_yaml::from_str::<Scenario>` for run/validate/replay/explore | none |
| `SCN-A3-CONSUMER-FRANKENLAB` | production Scenario loader | the same whole-file parse path for run/validate/replay/explore, minimize YAML fallback, and demo discovery | none |
| `SCN-A3-CONSUMER-ROOT-INTEGRATION` | test Scenario loader and writer | fixture parse plus test-only `serde_yaml::to_string` round trip | fixture-only; no application policy |
| `SCN-A3-CONSUMER-ADOPTION-FUNNEL` | test Scenario loader | whole-file fixture parse | fixture-only; no application policy |
| `SCN-A3-CONSUMER-A1-CONTRACT` | grammar/corpus contract | typed positive and negative parses over the frozen 23-row grammar and 13 files | fixture-only; no application policy |
| `SCN-A3-CONSUMER-METHODOLOGY-WORKFLOW` | adjacent semantic YAML parser | `.github/workflows/methodology-gates.yml` to `serde_yaml::Value` | fixture-only; no application policy |
| `SCN-A3-CONSUMER-RUNNER-DOC-EXAMPLE` | ignored documentation example | demonstrates a typed parse but is not a live loader | not applicable |

The exact direct `serde_yaml::` source allowset is the root CLI, the
frankenlab binary, the root integration test, the frankenlab adoption test,
the A1 contract, the methodology workflow contract, and the ignored runner
documentation example. The documentation example names `serde_yaml`, but does
not activate or retain a dependency edge. Raw text and path assertions over
examples metadata, `pnpm-workspace.yaml`, and workflow names do not interpret
YAML or retain `serde_yaml`; the time-travel YAML is an orphan document. Those
surfaces remain classified by A1's adjacent-file inventory and selected source
pins, but are outside this direct parser-acceptance consumer matrix.

No production Scenario YAML writer or dump command exists. The only typed
Scenario writer is the test round trip. Separate
adjacent writers are a raw Docker Compose fixture generator, a deterministic
test-only conformance-manifest renderer, and two test-only Insta YAML snapshot
surfaces; none is a Scenario writer.

### Frozen acceptance and diagnostics

The A3.1 audit carries forward all 23 A1 grammar rows without widening their
claim. Fourteen are accepted (some with a documented projection such as
comment discard, alias resolution, or unknown-field discard), five are typed
parse rejections, `.nan`/infinity parse and are then rejected by probability
validation, and recursion plus alias repetition are incumbent parser-internal
boundaries. The remaining arbitrary-tag row records only the frozen
no-implicit-code-execution behavior of typed deserialization; it does not add
another acceptance witness or make a broad security claim. The partition is
disjoint and complete.

Unknown root and nested typed-struct fields remain accepted and ignored because
the structs do not use `deny_unknown_fields`. This is different from the three
preserved extension maps: `metadata`, `participants[].properties`, and
`faults[].args`. Tightening unknown-field behavior would narrow the accepted
language and therefore requires an explicit owner policy; A3.1 records no such
approval.

The root CLI still returns structured `scenario_parse_error` user errors with
path context, parser text and available parser location plus a generic hint.
Frankenlab still returns plain strings with equivalent path/parser context.
Semantic validation reports field-like paths without YAML source spans.
Unknown-oracle rejection remains separate. The runner owns `[ASUP-E401]` for
replay divergence, while both CLI adapters still reconstruct text without that
token. A3.1 freezes these facts; it does not prove a replacement diagnostic.

### Application-limit matrix

| Dimension | Current application policy | Why another control does not satisfy it |
| --- | --- | --- |
| document bytes | none | both production loaders allocate/read the whole file before parsing |
| scalar length | none | `id`, `description`, metadata values, and other strings have no general application maximum |
| mapping count | none | `metadata` and other maps have no universal application entry limit |
| sequence count | none | participants and other sequences have no universal application item limit |
| total parse work | none | no application work budget surrounds either parse |
| nesting depth | none | serde_yaml's recursion counter starts at 128, but that is an incumbent-internal guard rather than an application policy |
| alias repetition | none | serde_yaml's repetition guard is likewise parser-internal |
| include path | per-entry semantic validation | the 255-byte path check occurs after parsing and does not cap document or include count; includes are not resolved |
| fault count | optional author-selected post-parse cap | `max_fault_events` constrains only faults and only when present |
| runtime steps | optional execution control | `lab.max_steps` defaults to 100,000 and may be `null`; it is not a parse bound |

### Formal satisfiability result

Let `L_current` be the documents for which either current application loader
returns a typed `Scenario`. The replacement requirement simultaneously says:

1. every document in `L_current` must remain accepted; and
2. the owned replacement must apply finite application byte, depth, count, and
   work bounds.

Those requirements are `UNSATISFIABLE_UNDER_CURRENT_ACCEPTANCE` without a
policy change. For any proposed finite byte or scalar bound `N`, an otherwise
valid flat Scenario can use a `description` longer than `N`. For any finite
mapping bound, an otherwise valid `metadata` map can contain more than `N`
unique entries. For any finite sequence bound, an otherwise valid Scenario can
contain more than `N` uniquely named participants. The current loaders define
no application rule rejecting those witness families, and each family can stay
flat, so the incumbent recursion guard does not resolve the contradiction.

The policy result is therefore `OWNER_POLICY_REQUIRED`; no owner policy receipt
exists. The required A3.1 disposition is `KEEP_INCUMBENT`, with
`dependency_exit_allowed=false`, `owned_parser_present=false`, and
`owned_writer_present=false`. This is not an assertion that finite bounds are
undesirable. It means adopting them changes the current accepted language and
needs a separately approved product decision before replacement work can claim
parity.

### A3 handoff

A3.2 (`asupersync-5z2scg.5.3.2`) records the durable fail-closed receipt as
`SCN-A3-KEEP-INCUMBENT-V1`. Its basis is the landed A3.1
commit `d7bd450dc53647723a5e9aaa360d0e044794a4b2`; the receipt pins that commit's
artifact, documentation, and contract SHA-256 values. This makes the KEEP
decision traceable to the exact static audit rather than to mutable prose.

The receipt groups five blocking gates whose union is all seven unresolved A3.1
rows:

| Required row | Class | Current state | State required before adoption/cutover |
| --- | --- | --- | --- |
| `SCN-A3-UNRESOLVED-OWNER-INPUT-POLICY` | finite application bounds | missing | owner-approved input policy plus all finite byte, scalar, mapping, sequence, work, nesting, and alias bounds |
| `SCN-A3-UNRESOLVED-OWNED-PARSER` | owned parser | absent | present and source-pinned owned candidate |
| `SCN-A3-UNRESOLVED-OWNED-WRITER` | owned writer | absent | present and source-pinned owned writer |
| `SCN-A3-UNRESOLVED-GRAMMAR-DIFFERENTIAL` | grammar parity | not run | SAME-or-BETTER |
| `SCN-A3-UNRESOLVED-DIAGNOSTIC-PARITY` | diagnostic parity | not proven | SAME-or-BETTER |
| `SCN-A3-UNRESOLVED-WRITER-PARITY` | writer parity | not proven | SAME-or-BETTER |
| `SCN-A3-UNRESOLVED-CONSUMER-CUTOVER` | consumer cutover | not authorized | every consumer proven and A5 authorized |

All seven rows are blocking and none is satisfied. The durable result is
therefore `KEEP_INCUMBENT`, `dependency_exit_allowed=false`,
`input_narrowing_allowed=false`, and `terminal_cutover_authorized=false`.
Any missing or regressed row keeps the A3 receipt at `KEEP_INCUMBENT`.

The authority handoff is deliberately asymmetric:

| Child | Authority now | Explicit prohibitions |
| --- | --- | --- |
| A4 (`asupersync-5z2scg.5.4`) | may continue additive YAML/JSON conversion, validation, diagnostics, documentation, examples, include-truth, and atomic-output work | may not approve input narrowing, promote scoped evidence to a terminal verdict, narrow YAML acceptance, remove the dependency/capability/files, or issue a terminal decision |
| A5 (`asupersync-5z2scg.5.5`) | remains the sole terminal KEEP, DEFER, or CUTOVER authority and may issue KEEP/DEFER while blockers remain | CUTOVER and dependency exit are not authorized now; they first need every declared prerequisite, including an owner-approved finite input policy and every required row at its declared state |

A4 conversion work must remain semantic, reversible, and non-destructive. It
must preserve current YAML inputs, files, accepted language, schema versions,
defaults, seeds, oracle sets, and replay fingerprints. A5 CUTOVER additionally
requires a claim-time source/dependency/writer/consumer refresh, complete
cross-format corpus and downstream evidence, dependency-graph/oracle/replay
disposition, and migration/rollback evidence. Any missing, absent, unknown,
planned, blocked, blocked-gap, unrun, unproven, unauthorized, or regressed row
forces KEEP or DEFER.

This is a static governance receipt. A3.2 did not rerun A1/A2 evidence, approve
bounds, implement a parser/writer, prove parity or runtime behavior, remove a
dependency/YAML capability/file, close the tracker, or exercise A5 authority.

### A4 source progress: exact example registry

A4 (`asupersync-5z2scg.5.4`) records one bounded source-alignment row,
`SCN-A4-GAP-13-REGISTRY-SOURCE-V1`. `examples/metadata.json` now declares both
typed scenario roots and registers the same 13 files frozen by the corpus: ten
under `examples/scenarios/` and three under
`frankenlab/examples/scenarios/`. `examples/README.md` links the three
FrankenLab fixtures and explicitly labels their names and descriptions as
authoring narratives rather than evidence of simulated runtime effects.

The existing `tests/examples_metadata_contract.rs` source now inventories both
roots, requires exactly 13 typed scenario rows, fixes the three FrankenLab
paths, and retains live-path and exact-line-span checks. The governed A4 row is
`SOURCE_ALIGNED_STATIC`: source alignment is complete, but
`dynamic_contract_executed=false` and the execution state is
`NOT_RUN_BY_STATIC_LANE`. No Rust contract was executed in this lane, so
`SCN-GAP-13 remains blocked` and fail-closed.

This source slice changes no parser, model, loader, runner, scenario corpus
file, accepted YAML construct, dependency, capability, or runtime behavior. It
does not prove that any scenario parses, validates, executes, explores, or
replays; it does not establish the named race, leak, or partition effects; and
it does not prove conversion, semantic or fingerprint equivalence, diagnostics,
security, performance, release readiness, broad health, or terminal authority.

### A4 source progress: GAP-12 and author claim truth

A4 separately records `SCN-A4-GAP-12-CLAIM-TRUTH-V1`. The ADR, its machine
registry, the adjacent demo comments, the source-level `Scenario` documentation,
the examples index, and the author guide now agree on these facts:

- the typed corpus is ten files under `examples/scenarios/` and three under
  `frankenlab/examples/scenarios/`;
- `tools/demos/time_travel.yaml` is an adjacent parameter reference, not the
  typed Scenario schema and not an operational benchmark input;
- generic CLI path loaders exist, while no source literal or discovery route
  automatically selects that adjacent file;
- `Scenario::to_json` is a library-only canonical encoder for the typed schema,
  while CLI JSON is command-result/report output and shared config canonical
  encoding remains absent;
- include paths are validated but never read or merged, unknown typed fields
  are discarded, merge keys are not applied, and parsed fields must not be
  confused with runner effects; and
- fault argument keys and values enter trace/result text, while the `redacted`
  flag does not scrub them.

Only comments changed in the adjacent YAML; its six data fields are unchanged.
No parser, loader, runner, typed fixture, dependency, accepted input, or runtime
behavior changed. The Rust contracts were not executed in this static lane, so
`SCN-GAP-01`, `SCN-GAP-12`, and `SCN-GAP-13` remain blocked. The receipt does
not prove parsing, validation, execution, replay, conversion, fingerprints,
benchmark behavior, checksums, cross-platform determinism, redaction, security,
broad health, release readiness, tracker closure, dependency or file removal,
cutover, or terminal authority.

### A4 source progress: atomic replay artifact persistence

A4 additionally records `SCN-A4-GAP-16-ATOMIC-REPLAY-SOURCE-V1`. The root
`write_replay_artifact` source now serializes the complete JSON report before
opening output, creates a `tempfile::NamedTempFile` in the destination
directory, writes the full payload, flushes and synchronizes the staged file,
and publishes it with `persist_noclobber`. The final commit therefore refuses
to replace an existing replay artifact. The existing success-path source test
is retained, and
`write_replay_artifact_preserves_existing_destination` checks that a failed
commit leaves earlier evidence byte-for-byte unchanged.

This changes replay-artifact persistence behavior only: an occupied output
path now fails closed rather than being silently overwritten. It changes no
report schema, scenario format, accepted YAML input, dependency, capability,
or scenario runtime semantics. The commit primitive is supplied by
`tempfile`; on supported platforms it uses a no-replace rename and may fall
back to link/unlink publication, so this packet makes no stronger
cross-platform or post-publication crash-durability claim.

The focused Rust tests and this inventory contract were not executed in this
static lane. Accordingly, `SCN-GAP-16 remains blocked`: the artifact records
`SOURCE_IMPLEMENTED_STATIC`, not executable proof. This slice does not prove
compilation, runtime filesystem behavior, conversion, semantic or fingerprint
equivalence, performance, security, broad health, release readiness, tracker
closure, cutover, or terminal authority.

## Child routing

| Child | Frozen responsibility | Current evidence |
| --- | --- | --- |
| A1 | loaders, schema, grammar, corpus, workflows, diagnostics, consumption, gaps | executed contract |
| A2 | one versioned typed model and additive canonical JSON | executed contract |
| A3 | incumbent KEEP or complete bounded owned parser/writer parity | A3.1 static audit and A3.2 durable receipt recorded; tracker state is separate |
| A4 | located diagnostics, migration, examples, include truth, atomic output, docs | static source progress for exact example registry, GAP-12/author claim truth, and GAP-16 no-clobber replay persistence; behavioral evidence remains unrun |
| A5 | real validate/run/explore/replay journeys and terminal KEEP, DEFER, or CUTOVER decision | planned |

Only A5 is terminal. Any missing, planned, blocked, regressed, or not-at-required
state row forces KEEP or DEFER with the incumbent retained.

## Known gaps

The artifact routes sixteen fail-closed gaps:

| Gap | Finding | Owner |
| --- | --- | --- |
| `SCN-GAP-01` | include is validated but never resolved or merged | A4 |
| `SCN-GAP-02` | network configuration is validation-only | A5 |
| `SCN-GAP-03` | cancellation configuration is validation-only | A5 |
| `SCN-GAP-04` | participant roles/properties are unused | A5 |
| `SCN-GAP-05` | expected invariants do not select checks | A5 |
| `SCN-GAP-06` | library canonical JSON exists, but golden format selection/redaction remain unwired | A4 |
| `SCN-GAP-07` | six fault actions have no simulated effect | A5 |
| `SCN-GAP-08` | YAML schedules no workload | A5 |
| `SCN-GAP-09` | library canonical JSON exists, but neither CLI exposes dump/conversion | A4 |
| `SCN-GAP-10` | no application document/work bounds | A3 |
| `SCN-GAP-11` | unknown fields are ignored | A3 |
| `SCN-GAP-12` | source truth now separates the adjacent demo YAML from the typed corpus, but focused contracts remain unexecuted | A4 |
| `SCN-GAP-13` | all 13 typed fixtures are source-registered, but the focused Rust contracts were not executed in this static lane | A4 |
| `SCN-GAP-14` | no full-corpus typed YAML/JSON equivalence proof | A3 |
| `SCN-GAP-15` | semantic spans and stable CLI replay code are incomplete | A4 |
| `SCN-GAP-16` | staged, synced, no-clobber replay persistence is authored, but its focused Rust tests and inventory contract remain unexecuted | A4 |

There are zero `UNKNOWN` loader, schema, grammar, corpus, workflow,
diagnostic, resource, consumer, child, or gap rows.

## Validation

Run the focused source-pin, typed-schema, parser-behavior, corpus, routing,
durable-receipt gate derivation, A4/A5 authority, GAP-16 replay-persistence
source, documentation, and negative-mutation contract:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path src/bin/asupersync.rs \
  --overlay-path src/lab/scenario.rs \
  --overlay-path tools/demos/time_travel.yaml \
  --overlay-path docs/adoption/getting_started.md \
  --overlay-path examples/README.md \
  --overlay-path docs/adr/dep_plan_adr_004_config_scenario_formats.md \
  --overlay-path artifacts/dependency_api_adr_registry_v1.json \
  --overlay-path docs/dependency_api_adr_registry.md \
  --overlay-path tests/dependency_api_adr_registry_contract.rs \
  --overlay-path artifacts/config_toml_capability_inventory_v1.json \
  --overlay-path artifacts/scenario_yaml_capability_inventory_v1.json \
  --overlay-path docs/scenario_yaml_capability_inventory.md \
  --overlay-path tests/scenario_yaml_capability_inventory_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_scenario_yaml_capability_inventory" \
  cargo test -p asupersync --test scenario_yaml_capability_inventory_contract \
  -- --nocapture
```

The artifact also records exact RCH commands for the existing root integration
and frankenlab adoption suites. Those suites are evidence only for their
checked scenarios and workflows; they do not close the routed execution gaps.

## No-claim boundary

This A1/A2/A3.1/A3.2 packet combines the earlier executable
inventory/canonical-JSON evidence with a current static
acceptance-satisfiability audit and fail-closed KEEP receipt. The A4 additions
are source-level example-registry, GAP-12/author claim-truth alignment, and an
authored GAP-16 replay-persistence change. No Rust contract was executed for
them, and `SCN-GAP-01`, `SCN-GAP-12`, `SCN-GAP-13`, and `SCN-GAP-16` remain
blocked. A3.1, A3.2, and these A4 static slices did not rerun executable lanes
or implement an owned YAML parser or production Scenario YAML writer. The
GAP-16 source was not compiled or executed and therefore does not establish
cross-platform filesystem behavior or crash durability after destination
publication. The packet proves no complete parity, runtime behavior outside
the authored replay-persistence source, performance, resource, security,
broad-health, release, or terminal decision, and authorizes no input narrowing,
dependency or file removal, tracker closure, or cutover. It also does not
implement include merging, network or cancellation simulation, participant
workloads, full fault effects, resource-policy bounds, or stable located
semantic diagnostics.
`KEEP_INCUMBENT` and `dependency_exit_allowed=false` remain mandatory. Only A5
may issue a terminal KEEP, DEFER, or CUTOVER decision; CUTOVER and dependency
exit remain unauthorized until every declared prerequisite is satisfied.

<!-- END SCENARIO YAML CAPABILITY INVENTORY -->
