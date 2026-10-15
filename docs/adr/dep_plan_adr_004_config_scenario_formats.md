# DEP-ADR-004: Additive canonical JSON while preserving accepted TOML config and YAML scenarios

- Status: accepted
- Date: 2026-07-24
- Owner: SapphireHill
- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Bead: `asupersync-dep-p3-api-adrs-h3jspm.4`
- Capabilities: `CAP-CONFIG-TOML-JSON`, `CAP-SCENARIO-YAML-JSON`
- Decision: `ADDITIVE_COEXISTENCE` / `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`
- Config A3 disposition: evidence-backed `KEEP_INCUMBENT` at `98aee7f58d463a3950a3412c061d0875ea64b003`
- Machine row: `artifacts/dependency_api_adr_registry_v1.json`
- Supersedes: `COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md` §7 item 3.4

## Context

TOML configuration and YAML scenarios are the two operator- and author-facing
file formats in the crate. The Rev-3 plan framed Phase 3 item 3.4 as a
*migration* decision — TOML to versioned JSON, plus YAML scenario migration
rules. Reading the live source changes what that decision can reasonably be.

**The parsing surfaces are much thinner than the dependency list suggests.**
The `Scenario` type contains no YAML code whatsoever — only serde derives.
Every YAML parse happens at a call site: the `asupersync` CLI binary, the
frankenlab binary, and two test files. Consequently `serde_yaml` never appears
in a library public signature. The same is true on the config side: the typed
target `RuntimeConfig` contains no format code, and all `toml`-crate parsing is
concentrated in `runtime/env_config.rs` plus the CLI and daemon config surfaces.

**JSON is already here.** `serde_json` is a non-optional dependency, and
`Scenario::from_json` / `to_json` round-trip the typed schema. A2 has since made
`Scenario::to_json` compact and recursively key-ordered, so canonical Scenario
JSON is a shipped library surface rather than a new capability.

**What genuinely does not exist** is JSON *configuration* loading — there is no
`RuntimeBuilder::from_json`, no JSON path in `env_config`, and none in the ATP or
`atpd` config surfaces — or a shared/config-agnostic canonical-JSON encoder.
Neither application CLI accepts a JSON Scenario or emits canonical Scenario
JSON; their `--json` flags serialize command results and reports.

**A trap worth naming.** `src/config.rs` looks like a TOML surface and the
capability registry names it as a source owner, but it makes zero `toml::` calls.
It hand-splits lines on `=`, treats `[section]` lines as headers, lowercases
section names, and strips `#` and `//` comments. It is an INI-style parser
accepting a narrower and different grammar with different error semantics. It is
not evidence that an owned TOML parser exists. See CFG-GAP-01.

## Decision

TOML configuration and YAML scenarios **MUST** remain accepted inputs. Canonical
JSON is **additive**. `toml` and `serde_yaml` remain `KEEP_UNTIL_PARITY`.

1. Every TOML or YAML document that loads today **MUST** keep loading. No field
   may become mandatory, and the tolerance for empty and partial documents
   **MUST** be preserved — both config tables and all their fields are optional.
2. Configuration precedence **MUST** remain file (lowest) → environment →
   programmatic (highest), and **MUST NOT** become format-dependent.
3. JSON **MAY** be added as an additional accepted configuration input and as
   canonical machine-generated output. It **MUST NOT** become the only accepted
   form for either capability.
4. Diagnostics **MAY** improve; they **MUST NOT** get coarser. Syntax, type,
   unknown-field, precedence, path, and semantic validation failures stay
   distinguishable and located.
5. Configuration written back **MUST** stay loadable and semantically identical.
   Comment or ordering loss on write-back is operator-visible and belongs in the
   migration evidence, not in a silent behavior change.
6. Scenario replay determinism **MUST** be preserved bit-for-bit. A format change
   that perturbs field ordering, numeric parsing, or defaulting can break replay
   fingerprints, so that risk is explicitly in scope for this ADR's evidence.
7. Security bounds **MUST** hold: scenario include paths keep their extension,
   length, and character-set validation; the explicit secure read/write config
   variants keep their stricter path handling; untrusted documents stay bounded
   in size, nesting, and collection count; no format introduces implicit code
   execution.
8. Replacing either parser **MUST NOT** be attempted until the accepted subset is
   pinned from the live corpus — `asupersync-5z2scg.5.1` for YAML,
   `asupersync-5z2scg.4.1` for config — and matched exactly.

## Allowed tradeoffs

- Canonical JSON may be documented as the preferred machine-generated form.
- Scenario JSON output need not be byte-identical to any pretty-printed form
  once a canonical encoder exists, provided round-trips stay lossless.
- The runtime TOML schema has no version field today; adding one is permitted
  provided older documents keep loading.

## Forbidden compromises

- Ending acceptance of either currently accepted format.
- Making any currently optional field mandatory, or rejecting empty or partial
  documents that are valid today.
- Reordering the precedence chain, or making precedence depend on the format.
- Routing real TOML through the INI-style parser in `src/config.rs`.
- Tightening unknown-field policy, include-path bounds, or size bounds in a way
  that invalidates the existing corpus, without its own evidence.
- Citing `src/fs_config_metamorphic_tests.rs` as evidence for the real config
  types — it tests a local mock behind a legacy harness feature (CFG-GAP-06).

## Config A3 preservation disposition

`asupersync-5z2scg.4.3` selects this ADR's incumbent KEEP branch. The complete
A1 inventory names five live TOML surfaces, sixteen accepted grammar
constructs, twelve error distinctions, and twenty-seven corpus cases. Claim-time
review found no owned parser or writer spanning that contract and no terminal
replacement evidence. Replacing `toml` would therefore narrow an accepted
capability or substitute an unproven implementation.

The machine receipt is
`artifacts/config_toml_capability_inventory_v1.json#a3_keep_receipt`. It records
all replacement rows as `NOT_PRESENT`, retains A3 gaps `CFG-GAP-02`,
`CFG-GAP-06`, `CFG-GAP-10`, and `CFG-GAP-12`, forbids dependency exit, and
leaves `asupersync-5z2scg.4.5` as the sole terminal cutover owner. This decision
does not block additive typed-model, diagnostic, I/O, or documentation work in
A2 and A4; it prevents those changes from being misrepresented as parser
replacement evidence.

Four A1 source pins drifted before this disposition. Static diff review
classified them as manifest/package growth, runtime scheduling/test growth,
dependency-budget generation growth, and unrelated consumer-fixture growth.
The `from_toml` entry points and the generic manifest parse/write surface were
retained. Refreshed hashes are stored in the A1 artifact, while the A3 receipt
keeps the exact claim revision and the per-path classification.

## Known gaps

Recorded as truthful baseline. Each names an owning bead and may only improve.

| ID | Gap | Owner |
|---|---|---|
| CFG-GAP-01 | The capability registry's `source_owners` for `CAP-CONFIG-TOML-JSON` (`src/config.rs`, `src/bin/asupersync.rs`) name files that make **zero** `toml::` calls. The real owners are `src/runtime/env_config.rs`, `src/runtime/builder.rs`, `src/cli/atp_config.rs`, `src/bin/atpd.rs`, `src/bin/dependency_marginal_ledger.rs`. The `api_surface_map` selector `config-reexports` has the same mismatch. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| CFG-GAP-02 | No integration test exercises `RuntimeBuilder::from_toml` (the file-path variant); only `from_toml_str` is covered. | `asupersync-5z2scg.4.3` |
| CFG-GAP-03 | One focused typed YAML-to-canonical-JSON equality and replay-identity test exists, but no exact 13-file cross-format corpus proof or real CLI conversion journey exists. | `asupersync-5z2scg.5.3` |
| CFG-GAP-04 | A1 source-baselines the observed YAML subset, including anchors, aliases, merge-key behavior, tags, numerics, Unicode, and duplicate keys; the accepted application language still has no owner-approved finite input policy. | `asupersync-5z2scg.5.1` |
| CFG-GAP-05 | No checked-in example TOML config and no doctested TOML journey; both rustdoc examples are in `ignore` fences and the documented `config/runtime.toml` does not exist. | `asupersync-5z2scg.4.5` |
| CFG-GAP-06 | `src/fs_config_metamorphic_tests.rs` covers TOML round-trip and canonical form, but against a mock struct and behind `legacy-internal-test-harnesses`. | `asupersync-5z2scg.4.3` |

CFG-GAP-01 belongs to the capability-registry owner, not to this ADR. It is
recorded here because any baseline work that trusts those rows will inventory
the wrong files and miss the entire runtime and CLI TOML surface.

## Invariant impact checklist

- [x] No accepted input format loses acceptance.
- [x] No optional field becomes mandatory; empty and partial documents stay valid.
- [x] Precedence order is unchanged and format-independent.
- [x] Diagnostics are preserved or improved, never coarsened.
- [x] Config write-back round-trip fidelity is a stated contract.
- [x] Scenario validation still returns a located list rather than first-error.
- [x] Scenario replay determinism is preserved.
- [x] Include-path, size, nesting, and collection bounds are preserved.
- [x] Secure config read/write variants are preserved.
- [x] No compatibility shim or deprecated alias is introduced.
- [x] No root export changes, so `artifacts/api_surface_map_v1.json` is untouched.

## Evidence

Evidence state is mixed and deliberately scoped. The A1 inventory contract has
a historical executed receipt. The A3 preservation disposition is
`STATIC_DECISION_AUTHORED_NOT_EXECUTED`: it is based on source-pin
reconciliation and explicit absence of replacement evidence, not a new parser
run. A2, A4, A5, and the Scenario cross-format work remain planned unless their
own artifacts say otherwise.

- Baseline: `asupersync-5z2scg.4.1` (config), `asupersync-5z2scg.5.1` (YAML subset)
- Unit: `asupersync-5z2scg.4.3`
- No-mock E2E: `asupersync-5z2scg.4.5`
- Scenario IDs: `config_toml_json_roundtrip`, `config_precedence`,
  `atpd_config_user`, `lab_scenario_yaml`, `scenario_cross_format`,
  `scenario_replay`

The typed corpus obligation is concrete: the ten Scenario files in
`examples/scenarios/` and the three in `frankenlab/examples/scenarios/` must
still validate, run, and replay with unchanged fingerprints. The differential
class must close CFG-GAP-03 by proving YAML and JSON deserialize to the same
`Scenario` across all 13 files. `tools/demos/time_travel.yaml` is an adjacent
parameter reference, not the Scenario schema and not a benchmark input; it must
remain classified separately rather than being forced through Scenario flows.

## Rollback

Triggered by any previously accepted document that stops loading, any coarsened
diagnostic, any precedence reordering, any lost comment or value on config
write-back, any change in scenario replay fingerprints, or any narrowing of
include-path or size bounds. Because the decision is additive coexistence,
rollback removes the additive JSON path rather than restoring a deleted format.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

## No-claim boundary

This ADR is a frozen decision and public-surface inventory, plus the static A3
incumbent-preservation disposition. It does not prove that the current A3
contract extension or other planned evidence has run, that JSON is lossless
with respect to the full accepted TOML and YAML corpora, that config write-back
preserves comments, that any owned parser could reach parity, that performance
is unchanged, or that either parser dependency may be removed. The
Scenario-specific canonical encoder is not a shared config encoder or a CLI
conversion path. This ADR also does not certify the capability registry's
source-owner rows, which CFG-GAP-01 records as incorrect for this capability.
