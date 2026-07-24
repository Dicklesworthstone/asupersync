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
root keys are `name`, `seed`, `scenario`, and `expected`, not the `Scenario`
schema, and no live source reads it. `make demo-benchmark` runs
`examples/demo_benchmark.rs`, which consumes JSON golden checksums rather than
that YAML file. CI workflow YAML and `pnpm` metadata are likewise explicitly
adjacent.

This matters because the ADR says every `tools/demos` document must validate,
run, and replay. That sentence overstates the live implementation; it is
routed as `SCN-GAP-12`.

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
output, not yet the additive format journey required by A2.

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
artifact path uses direct `fs::write`, not atomic temp-write, sync, and rename.

## Child routing

| Child | Frozen responsibility | Current evidence |
| --- | --- | --- |
| A1 | loaders, schema, grammar, corpus, workflows, diagnostics, consumption, gaps | executed contract |
| A2 | one versioned typed model and additive canonical JSON | planned |
| A3 | incumbent KEEP or complete bounded owned parser/writer parity | planned |
| A4 | located diagnostics, migration, examples, include truth, atomic output, docs | planned |
| A5 | real validate/run/explore/replay journeys and terminal KEEP-or-cutover decision | planned |

Only A5 is terminal. Any missing, planned, blocked, regressed, or
non-SAME-or-BETTER row forces KEEP.

## Known gaps

The artifact routes sixteen fail-closed gaps:

| Gap | Finding | Owner |
| --- | --- | --- |
| `SCN-GAP-01` | include is validated but never resolved or merged | A4 |
| `SCN-GAP-02` | network configuration is validation-only | A5 |
| `SCN-GAP-03` | cancellation configuration is validation-only | A5 |
| `SCN-GAP-04` | participant roles/properties are unused | A5 |
| `SCN-GAP-05` | expected invariants do not select checks | A5 |
| `SCN-GAP-06` | golden format/canonicalization are not implemented | A2 |
| `SCN-GAP-07` | six fault actions have no simulated effect | A5 |
| `SCN-GAP-08` | YAML schedules no workload | A5 |
| `SCN-GAP-09` | no Scenario dump/canonical JSON workflow | A2 |
| `SCN-GAP-10` | no application document/work bounds | A3 |
| `SCN-GAP-11` | unknown fields are ignored | A3 |
| `SCN-GAP-12` | time-travel demo YAML is orphaned and not the schema | A4 |
| `SCN-GAP-13` | root metadata omits the three frankenlab examples | A4 |
| `SCN-GAP-14` | no typed YAML/JSON equivalence proof | A3 |
| `SCN-GAP-15` | semantic spans and stable CLI replay code are incomplete | A4 |
| `SCN-GAP-16` | replay artifact output is non-atomic | A4 |

There are zero `UNKNOWN` loader, schema, grammar, corpus, workflow,
diagnostic, resource, consumer, child, or gap rows.

## Validation

Run the focused source-pin, typed-schema, parser-behavior, corpus, routing,
documentation, and negative-mutation contract:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
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

This A1 packet proves a source-pinned, zero-`UNKNOWN` inventory and executable
parser/typed-corpus baseline only. It does not implement JSON input, canonical
output, an owned YAML parser, include merging, network or cancellation
simulation, participant workloads, full fault effects, atomic artifact output,
resource-policy bounds, stable located diagnostics, broad workspace health,
performance, or permission to remove `serde_yaml`, `serde`, any field, error,
document, workflow, or dependency.

<!-- END SCENARIO YAML CAPABILITY INVENTORY -->
