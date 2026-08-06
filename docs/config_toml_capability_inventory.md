# TOML/config capability inventory

<!-- BEGIN CONFIG TOML CAPABILITY INVENTORY -->

This is the operator-readable companion to
`artifacts/config_toml_capability_inventory_v1.json`. It preserves the live
configuration baseline frozen by `asupersync-5z2scg.4.1` at revision
`3468d4474e981fd2b19a8020175e6bb8bd4a5dc3`, records the A2 additive JSON
source implementation, and retains the A3 incumbent decision for
`CAP-CONFIG-TOML-JSON`.

The governing `DEP-ADR-004` decision is additive coexistence:
`KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`. Versioned JSON source APIs now exist
for the four typed application-config families, but their focused tests have
not been executed in the A2 receipt. TOML remains accepted, and no child before
terminal A5 may authorize removing the incumbent `toml` dependency.

## What actually parses TOML

The repository does not have one TOML configuration schema. It has five
production or internal-tool surfaces with different defaults, required fields,
errors, path policies, and write behavior.

| Stable ID | Build profile | Live owner | Typed fields | Empty document | Additive JSON source state | Write behavior |
| --- | --- | --- | ---: | --- | --- | --- |
| `CFG-TOML-RUNTIME` | `config-file` | `runtime/env_config.rs`, `runtime/builder.rs` | 14 | accepted as defaults | model, string/file entry points, canonical projection | none |
| `CFG-TOML-ATP-COMMAND` | `cli` | `cli/atp_config.rs`, `cli/atp_command_tree.rs` | 11 | accepted as an all-`None` layer | model parse/projection API | pretty direct TOML write |
| `CFG-TOML-ATP-INSTALL` | `cli` | `cli/atp_config.rs`, `cli/first_run.rs`, `cli/upgrade.rs` | 14 | rejected: required fields missing | model parse/projection API | pretty direct TOML write |
| `CFG-TOML-ATPD` | `atpd-daemon` | `bin/atpd.rs` | 45 | loader rejects; start falls back to defaults | `.json` loader plus redacted projection | none |
| `CFG-TOML-DEPENDENCY-LEDGER` | `dependency-ledger` | `bin/dependency_marginal_ledger.rs` | generic `toml::Value` | parser accepts, Cargo consumer may not | explicitly not an application-config model | pretty generated shadow TOML manifest |

Three adjacent surfaces are deliberately separated:

- `CFG-TOML-FRANKEN-DECISION-TEST` contains test-only round-trips for
  `LossMatrix` and `FallbackPolicy`.
- `CFG-TOML-MOCK-METAMORPHIC` is a legacy-harness mock and is not evidence for
  any live configuration type.
- `CFG-NON-TOML-RAPTORQ` is the public `src/config.rs` `ConfigLoader`. It is an
  INI-style line parser with six sections and 33 exact keys. It is not TOML.

That last distinction is material. The capability registry and API surface map
currently route TOML ownership to `src/config.rs`; the live code route above is
the source-pinned truth.

## Exact typed fields

`CFG-TOML-RUNTIME` has two optional tables. `scheduler` has
`worker_threads`, `task_queue_depth`, `thread_stack_size`,
`thread_name_prefix`, `steal_batch_size`, `enable_parking`, `poll_budget`,
`cancel_lane_max_streak`, `enable_governor`, `governor_interval`,
`enable_adaptive_cancel_streak`, and
`adaptive_cancel_streak_epoch_steps`. `blocking` has `min_threads` and
`max_threads`. Every field is `Option`; an omitted table or field leaves the
fresh `RuntimeConfig` default unchanged.

`CFG-TOML-ATP-COMMAND` has eleven optional root fields: `profile`,
`chunk_size`, `max_concurrent`, `timeout`, `compression`, `encryption`,
`repair_overhead`, `interface`, `relay_server`, `daemon_socket`, and `verbose`.
Deserializing an empty layer produces eleven `None` values; this is distinct
from `AtpConfig::default()`, which populates selected defaults before layers
are merged.

`CFG-TOML-ATP-INSTALL` persists `schema_version`, optional `version`, four
paths, two policies, two network/privacy booleans, logging level, platform, and
two service booleans. Only `version` is optional. This is why the broad ADR
wording that all config fields are optional cannot be applied to every live
surface.

`CFG-TOML-ATPD` requires six top-level tables: `identity`, `network`,
`storage`, `transfers`, `service`, and `diagnostics`. The 45 leaf fields cover
identity and team arrays, bind and discovery, optional QUIC credentials,
storage and journal policy, transfer limits, health/restart policy, and
logging/rotation. Only `network.quic` has a table default. The credential
paths, auth key, bandwidth limit, metrics bind, log path, and log rotation are
optional; the remaining typed fields are required.

The machine artifact enumerates every field with its Rust target type and
checks that the group totals remain exactly 14, 11, 14, 45, and zero generic
fields.

## Observed grammar

The executable corpus freezes parser behavior rather than claiming the entire
TOML specification by assumption. It covers:

- basic, literal, and multiline strings;
- decimal and radix integers, target-type bounds, floats, and booleans;
- offset and local datetime values;
- arrays, tables, inline tables, arrays of tables, dotted keys, and quoted
  keys;
- comments and formatting;
- duplicate keys, table/key conflicts, malformed syntax, wrong types, bad
  enums, and semantic apply errors;
- empty, partial, full, unknown-field, missing-file, path-attack, and
  write/read cases.

The generic parser accepts every listed valid TOML construct and rejects
duplicates and table conflicts. Typed behavior is narrower:

- there is no typed datetime field; a datetime is accepted only when attached
  to an unknown ignored key;
- arrays are typed only on the atpd string-vector fields;
- generic `toml::Value` integers are bounded by signed 64-bit representation,
  while direct deserialization into ATP's `u64` fields accepts values through
  `u64::MAX`;
- known fields with the wrong type fail;
- duplicate and conflicting definitions fail before serde deserialization.

All current typed models accept and ignore unknown fields because none uses
`deny_unknown_fields`. That includes unknown keys beside QUIC/auth and other
security-adjacent settings. The inventory records this observed compatibility
behavior and separately records its conflict with the registry's fail-closed
unknown-security-field invariant.

Comments and input ordering are accepted but discarded. `to_string_pretty`
emits a semantic representation; it does not preserve an operator's comments
or original layout.

## Defaults and precedence

Runtime configuration is operational call-order precedence:

1. `RuntimeConfig::default()`;
2. `RuntimeBuilder::from_toml[_str]`;
3. `with_env_overrides()` when called after TOML construction;
4. later programmatic builder setters.

The existing tests prove the documented file → environment → programmatic
sequence, but the implementation is a builder, not a global layer engine. A
later method call mutates the builder at that point.

ATP command configuration merges:

1. `AtpConfig::default()`;
2. daemon policy;
3. local `.atp.toml`;
4. CLI flags.

`ConfigPaths` also exposes a user config path and `save_config(User, ...)`, but
`load_all()` never reads it. Daemon and local read/parse failures are swallowed
as absent layers. A separate programmatic overlay trap is now executable:
constructing a nominally partial layer with `..AtpConfig::default()` injects
`Some` defaults for unrelated keys. The existing precedence test currently
gets `Auto` where it expects the lower-priority `SyncTree` profile.

Atpd starts from a successfully parsed file and then applies selected start
arguments. Its boolean flags can enable settings but cannot disable a
file-enabled value. A missing file yields defaults. More seriously, the start
path also catches an existing unreadable or malformed file and starts on
defaults, while reload, diagnostics, and identity paths propagate loader
errors.

ATP install configuration is persisted state, not a layered config. First-run
writes it; upgrade reads, backs up, rewrites, and restores it. The dependency
ledger's “precedence” is only input manifest followed by selected deterministic
shadow mutations.

## I/O, paths, errors, and security

Runtime reads an entire caller-supplied path through `EnvReader`, parses an
intermediate model, and applies it to a fresh builder. It has no writer or base
directory restriction.

ATP exposes explicit secure install-config read/write variants using
`SecurePath` and an explicit base. Compatibility variants accept an
unconfined path and log a warning. First-run and upgrade currently call those
compatibility variants. Config-manager standard directories sanitize
environment-derived paths for traversal, excessive length, controls, and
relative Unix values; `.atp.toml` remains relative to the ambient current
directory.

ATP and dependency-ledger writes use direct `fs::write`. They do not use a
temporary file plus fsync and rename, do not set restrictive permissions, and
do not preserve comments or ordering. Read paths deserialize into a temporary
value before publishing it, but there is no application-level file-size,
nesting, string, array, table-count, or work limit.

Runtime maps file and parse failures into `BuildError`/`ErrorKind::ConfigError`.
ATP has distinct `FileRead`, `FileWrite`, `Parse`, `Serialize`,
`InvalidScope`, `Validation`, and `PathSecurity` variants, although manager
loads swallow file and parse variants. Atpd and the dependency ledger use
located text/context errors. None of the operator-facing TOML failures has a
stable `ASUP-Exxx` token, and secret-redacted parse diagnostics are not proven.

## Downstream files and journeys

The frozen consumer set is:

- public `RuntimeBuilder::from_toml` and `from_toml_str`;
- ATP first-run `<config_dir>/config.toml`;
- ATP upgrade and `<backup_dir>/<backup_id>/config.toml`;
- daemon-policy, user-path, and local `.atp.toml` command configuration;
- `atpd --config <PATH>`;
- root/member/shadow Cargo manifests in the dependency marginal ledger;
- the dependency capability portfolio fixture.

The last fixture enables `config-file` but exercises only
`CFG-NON-TOML-RAPTORQ`; it does not call either runtime TOML constructor. A5
owns replacing that inert feature check with a real external-user journey.

## A2 additive JSON source implementation

A2 is source-implemented at commits `cbe4a452a`, `0fb5fadc6`, and
`c05c8cb6d`. Its receipt state is
`SOURCE_IMPLEMENTED_NOT_EXECUTED`: all twenty-one focused source tests are
present, but none was executed while authoring this receipt.

The shared `VersionedConfigDocument<T>` keeps the format envelope separate
from each application's existing typed payload. It has two fields, `config`
and `schema_version`; version 1 is current, an omitted version migrates to 1,
and any other explicit version is rejected on read or write. Canonical output
is compact. Object keys are recursively lexicographic, arrays retain typed
order, and finite numbers use the stable shortest `serde_json`
representation. Model conversion rejects non-finite values rather than
silently converting them to `null`.

Path values are exact lexical UTF-8 strings. Conversion does not normalize,
resolve, canonicalize, or access a path. Unknown input fields retain Serde's
incumbent ignore-on-input behavior, while required fields remain exactly those
required by each existing typed model.

The five inventoried TOML families route as follows:

| Family | Single typed payload | JSON surface | Precedence or write effect |
| --- | --- | --- | --- |
| runtime | `RuntimeConfigLayer` for TOML, JSON, and environment values | parse/project APIs plus `RuntimeBuilder::from_json[_str]` | same call-order layer application; no writer |
| ATP command | `AtpConfig` for manager TOML, JSON conversion, and CLI merging | `parse_atp_command_json` and `atp_command_to_canonical_json` | manager inputs and direct TOML writer unchanged |
| ATP install | `AtpInstallConfig` for persisted TOML and JSON conversion | `from_json` and `to_canonical_json` | existing TOML read/write paths unchanged |
| atpd | `AtpdConfig` for both file formats | `.json` selects JSON; every other extension selects TOML | missing-file defaults and later start overrides unchanged |
| dependency ledger | generic `toml::Value` Cargo-manifest transformation | none | explicitly not treated as a typed application-config model |

Runtime parses and validates the complete layer before applying it to a fresh
builder, so a rejected layer is not partially published. Canonical projection
does no file I/O. This model-publication rule is not a claim that existing
physical writes are atomic: ATP install and command writes remain direct TOML
writes, and A4 retains physical write safety, diagnostics, migration UX, and
operator examples.

The runtime and ATP command layers contain no credential-bearing fields. The
install model stores an identity path, not identity key material. Atpd's
`network.quic.rq_auth_key_hex` is redacted at both the Serde and `Debug`
boundaries. Its canonical output is intentionally a diagnostic projection when
a key is present: the JSON loader rejects the `[REDACTED]` sentinel so that a
projection cannot be mistaken for a credential-bearing round trip.

The source tests cover exact recursive byte goldens, TOML/JSON typed
equivalence, empty/default behavior, missing and unsupported schema versions,
unknown and required fields, wrong types, finite-number enforcement, lexical
UTF-8 paths, runtime file capability mediation, runtime precedence, atpd
extension routing, and secret redaction. They remain unexecuted; A2 therefore
does not yet claim its acceptance criteria are green.

### A2 source-pin reconciliation

The current sixteen-path inventory pin set was reconciled against the
post-A3 comparison revision `424134f7338f610e36d5047d3d334128ae4275e4`.
Seven pins moved:

| Path | Classification | Accepted TOML input effect |
| --- | --- | --- |
| `src/config.rs` | shared versioned document and source tests | none |
| `src/runtime/env_config.rs` | runtime single typed layer and JSON conversion | none |
| `src/runtime/builder.rs` | runtime JSON entry points and shared application helper | none |
| `src/cli/atp_config.rs` | ATP command/install JSON model APIs | none |
| `src/cli/atp_command_tree.rs` | typed equality for cross-format receipts | none |
| `src/bin/atpd.rs` | additive atpd JSON loader and redacted projection | none |
| `tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs` | unrelated downstream stream/ATP contract growth | none |

The seventh path grew by 81 lines in another campaign. Its diff adds stream
and ATP downstream contract coverage; it does not change configuration parsing
or representation. The receipt records it separately from the six A2-owned
paths. The historical A1/A3 revisions and the A3 TOML-token projection remain
unchanged.

## Child routing

| Child | Frozen responsibility | Current evidence |
| --- | --- | --- |
| A1 | inventory, fields, grammar, corpus, precedence, I/O, errors, consumers, gaps | executed contract |
| A2 | one versioned typed model and additive canonical JSON | source implemented, tests not executed |
| A3 | incumbent KEEP or complete bounded owned TOML parser/writer parity | evidence-backed `KEEP_INCUMBENT` receipt |
| A4 | diagnostics, precedence, secure/atomic I/O, redaction, migration, docs | planned |
| A5 | real binary journeys and terminal KEEP-or-cutover decision | planned |

Only A5 is a terminal cutover node. Any missing, planned, blocked, regressed,
or non-SAME row forces KEEP.

## A3 incumbent decision

At claim revision `98aee7f58d463a3950a3412c061d0875ea64b003`, A3 chose the
acceptance contract's evidence-backed `KEEP_INCUMBENT` branch. No owned TOML
parser or writer exists in the inventoried production surfaces, and none of the
seven required replacement-evidence rows is present. The incumbent therefore
continues to preserve all five live surfaces, all sixteen observed grammar
constructs, all twelve error distinctions, and all twenty-seven corpus cases.
The machine decision state is `EVIDENCE_BACKED_KEEP`.

This is a positive preservation decision, not a deferred replacement claim:

- `replacement_selected`, `owned_parser_present`, and `owned_writer_present`
  are all `false`;
- dependency exit and terminal cutover are both forbidden;
- A5 (`asupersync-5z2scg.4.5`) remains the sole terminal cutover owner;
- A3 gaps `CFG-GAP-02`, `CFG-GAP-06`, `CFG-GAP-10`, and `CFG-GAP-12`
  remain explicitly open rather than being reclassified as green.

### Claim-time source reconciliation

Four of the sixteen A1 source pins had changed by the A3 claim revision. Each
diff was read and classified before refreshing its hash:

| Path | Drift classification | Accepted TOML contract effect |
| --- | --- | --- |
| `Cargo.toml` | manifest and package growth | none detected |
| `src/runtime/builder.rs` | runtime scheduling and test growth | `from_toml` entry points unchanged |
| `src/bin/dependency_marginal_ledger.rs` | dependency-budget generation growth | existing generic parse/write surface retained |
| `tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs` | unrelated consumer-fixture growth | none detected |

A 2026-08-05 static provenance pass refreshed the sole later source-pin drift
against `424134f7338f610e36d5047d3d334128ae4275e4`. Commit
`24eb7ec6c62e9ba037d70fed4a69c4e733785926` added six lines and removed one
line in `src/runtime/builder.rs`: it documented the production request-context
entry point and changed `request_cx_with_budget` from `pub(crate)` to `pub`.
The ordered `from_toml`, `from_toml_str`, and direct `toml::` token projection
remained byte-identical. The 16-path pin set, historical A1/A3 revisions,
`KEEP_INCUMBENT` decision, and all blocked gaps are unchanged.
This is static source-pin maintenance only; it does not add JSON, rerun either
receipt, or authorize dependency exit.

The receipt fails closed on seven absent replacement rows: parser parity,
writer parity, explicit resource bounds, independent comparison, generated
input coverage, diagnostic precision, and all downstream consumer journeys.
A replacement may be reconsidered only at a fresh claim revision after every
row is terminal SAME-or-BETTER; A5 must still record the real user journeys and
the terminal decision.

## Known gaps

The artifact routes fifteen fail-closed gaps:

| Gap | Finding | Owner |
| --- | --- | --- |
| `CFG-GAP-01` | registry/API source-owner mismatch | registry owner |
| `CFG-GAP-02` | no real-file `RuntimeBuilder::from_toml` integration test | A3 |
| `CFG-GAP-05` | no checked-in/doctested runtime TOML example | A5 |
| `CFG-GAP-06` | metamorphic TOML suite tests a mock | A3 |
| `CFG-GAP-07` | user config is writable but never loaded | A4 |
| `CFG-GAP-08` | ATP manager swallows read/parse failures | A4 |
| `CFG-GAP-09` | atpd start falls back after malformed/unreadable config | A4 |
| `CFG-GAP-10` | unknown security-adjacent fields are ignored | A3 |
| `CFG-GAP-11` | direct non-atomic, non-comment-preserving writes | A4 |
| `CFG-GAP-12` | no application resource bounds | A3 |
| `CFG-GAP-13` | external portfolio fixture never calls TOML APIs | A5 |
| `CFG-GAP-14` | ADR optionality wording conflicts with install/atpd reality | A4 |
| `CFG-GAP-15` | no stable error codes or proven secret redaction | A4 |
| `CFG-GAP-16` | JSON source and equivalence tests exist, but focused execution is still absent and persisted ATP writers remain TOML | A2 |
| `CFG-GAP-17` | programmatic default-filled ATP overlays override unrelated lower-priority values | A4 |

There are zero `UNKNOWN` surface, grammar, precedence, I/O, error, corpus,
consumer, child, or gap rows. A row is executed, existing-test,
source-baselined, planned, explicitly test-only/non-TOML/unsupported, or a
routed blocked gap.

## Validation

Run the focused source-pin, authority, field, grammar, typed corpus, routing,
documentation, and negative-mutation contract:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path artifacts/config_toml_capability_inventory_v1.json \
  --overlay-path docs/config_toml_capability_inventory.md \
  --overlay-path tests/config_toml_capability_inventory_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_config_toml_capability_inventory" \
  cargo test -p asupersync --test config_toml_capability_inventory_contract \
  --features cli -- --nocapture
```

The inventory also records exact RCH replay commands for the existing runtime
and ATP config unit-test groups. The A2 receipt adds twenty-one source tests but
records `NOT_RUN_STATIC_ONLY`; their presence is not a passing result. The real `config_formats`,
`config_toml_json_roundtrip`, `config_precedence`, and `atpd_config_user`
journeys remain A5 obligations.

The historical A1-only focused inventory lane completed on remote worker
`ovh-a` at 2026-07-24T21:46:01Z: 7 passed, 0 failed. That receipt predates the
A3 contract extension and is not presented as execution evidence for the new
KEEP receipt. The A3 extension was authored and reviewed statically; its
machine state is `STATIC_DECISION_AUTHORED_NOT_EXECUTED`.

The existing ATP config unit group completed on remote worker `hz2` at
2026-07-24T22:04:14Z: 3 passed and 1 failed. The failure is the preserved
`CFG-GAP-17` precedence defect, not a hidden green result.

## No-claim boundary

This packet preserves the A1 source-pinned, zero-`UNKNOWN` inventory, records
the A2 additive JSON source implementation without executable confirmation,
and retains the A3 evidence-backed KEEP branch. It does not add or execute a
replacement TOML parser or writer, change precedence or incumbent TOML
acceptance, repair physical write atomicity or diagnostics, prove the current
contract or source-test execution, prove real binary journeys, prove arbitrary
TOML or JSON, prove broad workspace health or performance, or authorize
removing `toml`, `serde`, any feature, field, error, path, input, output, or
user journey.

<!-- END CONFIG TOML CAPABILITY INVENTORY -->
