# Dependency public-API ADR registry

Bead: `asupersync-dep-p3-api-adrs-h3jspm.3`

Canonical artifact: `artifacts/dependency_api_adr_registry_v1.json`
Focused contract: `tests/dependency_api_adr_registry_contract.rs`
ADR narratives: `docs/adr/`

This document is the checked human view of the Phase-3 owner-ADR registry. The
artifact is canonical; the table below is deterministic and the contract test
rejects drift.

## What Phase 3 is for

Several proposed dependency swaps in the dependency-sovereignty program
(`asupersync-ir2uf0`) change public contracts rather than internal
implementation. Those are product decisions, not mechanical imports, so Phase 3
freezes each one in an ADR before any implementation, migration, or dependency
exit may begin. Phase 1 gates Phase 3; Phase 3 gates everything downstream.

An ADR here is a **decision record, not an implementation licence**. Resolving
an ADR authorizes no source change, no cutover, and no dependency removal.

## The no-loss rule

No ADR may authorize removal or narrowing of an accepted public API, generic
extension point, Cargo feature, binary, accepted format, wire protocol, platform
cell, diagnostic, third-party integration, or documented user journey. Additive
redesign is permitted; erasure is not.

When a complete owned replacement is disproportionate or its parity is unproven,
the required terminal decision is `KEEP_UNTIL_PARITY` with cutover state
`KEEP_INCUMBENT`. That is a real, allowed outcome — not a failure to decide.

Because asupersync is pre-1.0 with no external users to protect, preserved
surfaces stay because the capability is real, never because a deprecated alias
is kept alive. ADRs may not introduce compatibility shims or wrapper facades.

## Truthful baselines

An ADR records the capability **as it actually is** at claim time, including
gaps, quarantined surfaces, and dead code paths. Freezing an aspirational
surface is a defect. Each resolved ADR therefore carries a `known_gaps` list
whose entries name an owning bead and are marked as not permitted to widen. A
gap is not an authorized loss; it is a fact that may only ever get better.

## What one ADR row owns

Every resolved row names:

- the capability IDs it has authority over, which must equal the set the
  capability registry maps to its bead;
- the decision, its summary, and every alternative with the reason it was
  rejected;
- the exact preserved public symbols, per module path and feature gate, with
  the source file each lives in;
- the preserved Cargo feature definitions, verbatim from the manifest;
- the preserved surfaces, wire contract, and configuration semantics;
- known gaps with owning beads;
- security, cancellation, and platform invariants;
- external ecosystem integration points and their removal preconditions;
- downstream consumers and documented user journeys;
- the API surface delta and any superseded prior guidance;
- migration and rollback policy;
- evidence owners, scenario IDs, and required evidence classes;
- the cutover state, gates, and the explicit no-claim boundary.

Capability authority is derived, not restated: the contract test reads
`bead_mapping_rules` from `artifacts/dependency_capability_registry_v1.json` and
fails closed when an ADR claims a different set, when the roster stops matching
the live ADR children, or when an ADR's disposition or cutover state disagrees
with its capability row.

## Why the symbol freeze is the real gate

The most important check in this lane is mechanical: **every frozen public
symbol must still exist in the source file the ADR declares it in.** Deleting a
preserved capability therefore breaks the contract test rather than passing
review unnoticed. The same applies to the frozen Cargo feature definitions,
which are compared verbatim against `Cargo.toml`, and to the feature gating of
the observability re-exports.

## Generated summary

<!-- BEGIN GENERATED ADR SUMMARY -->
- Artifact: `dependency-api-adr-registry-v1` (schema 1)
- Phase: `asupersync-dep-p3-api-adrs-h3jspm`; aggregate terminal `asupersync-dep-p3-api-adrs-h3jspm.13`.
- Roster: 12 ADRs; RESOLVED=7; PENDING=5.
- Negative fixtures: 15.

| ADR | Bead | Capabilities | State | Decision | Cutover |
|---|---|---|---|---|---|
| `DEP-ADR-001` | `asupersync-dep-p3-api-adrs-h3jspm.1` | `CAP-SERDE-GENERIC`, `CAP-PERSISTED-TRACE-SNAPSHOT` | RESOLVED | ADDITIVE_COEXISTENCE | BLOCKED_PENDING_EVIDENCE / KEEP_INCUMBENT |
| `DEP-ADR-002` | `asupersync-dep-p3-api-adrs-h3jspm.2` | `CAP-PROTOBUF-GENERIC` | RESOLVED | KEEP_UNTIL_PARITY | KEEP_INCUMBENT |
| `DEP-ADR-003` | `asupersync-dep-p3-api-adrs-h3jspm.3` | `CAP-OTLP-ECOSYSTEM` | RESOLVED | ADDITIVE_COEXISTENCE | KEEP_INCUMBENT |
| `DEP-ADR-004` | `asupersync-dep-p3-api-adrs-h3jspm.4` | `CAP-CONFIG-TOML-JSON`, `CAP-SCENARIO-YAML-JSON` | RESOLVED | ADDITIVE_COEXISTENCE | KEEP_INCUMBENT |
| `DEP-ADR-005` | `asupersync-dep-p3-api-adrs-h3jspm.5` | `CAP-CLI-ASUPERSYNC`, `CAP-CLI-ATP`, `CAP-CLI-ATPD`, `CAP-CLI-OFFLINE-TUNER` | RESOLVED | KEEP_UNTIL_PARITY | KEEP_INCUMBENT |
| `DEP-ADR-006` | `asupersync-dep-p3-api-adrs-h3jspm.6` | `CAP-HTTP-COMPRESSION` | RESOLVED | KEEP_UNTIL_PARITY | KEEP_INCUMBENT |
| `DEP-ADR-007` | `asupersync-dep-p3-api-adrs-h3jspm.7` | `CAP-NKEY-AUTH` | PENDING | - | - |
| `DEP-ADR-008` | `asupersync-dep-p3-api-adrs-h3jspm.8` | `CAP-FUTURES-STREAMS` | RESOLVED | KEEP_UNTIL_PARITY | BLOCKED_PENDING_EVIDENCE |
| `DEP-ADR-009` | `asupersync-dep-p3-api-adrs-h3jspm.9` | `CAP-KAFKA` | PENDING | - | - |
| `DEP-ADR-010` | `asupersync-dep-p3-api-adrs-h3jspm.10` | `CAP-SQLITE` | PENDING | - | - |
| `DEP-ADR-011` | `asupersync-dep-p3-api-adrs-h3jspm.11` | `CAP-TIME-UTC-RFC3339` | PENDING | - | - |
| `DEP-ADR-012` | `asupersync-dep-p3-api-adrs-h3jspm.12` | `CAP-REGEX-PRIVACY` | PENDING | - | - |
<!-- END GENERATED ADR SUMMARY -->

## Authoring the next ADR

1. Re-read the live source, manifest, feature graph, and downstream consumers
   for the capability at claim time. Prior inventories are baselines, not
   permission to skip the read.
2. Write the narrative under `docs/adr/` using the section shape of
   `docs/adr/dep_plan_adr_003_otlp_ecosystem.md`.
3. Add the machine row to `artifacts/dependency_api_adr_registry_v1.json` and
   flip the roster entry from `PENDING` to `RESOLVED`.
4. Regenerate the summary block above, then run the focused contract.

The aggregate terminal `asupersync-dep-p3-api-adrs-h3jspm.13` may not close
while any roster row is still `PENDING`.

## Focused contract

Run:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

Through the canonical suite:

```bash
scripts/run_all_e2e.sh --suite dependency-sovereignty --scenario api-adr-registry-contract
```

## No-claim boundary

This is scoped ADR-registry and public-surface contract evidence only. It does
not prove that planned evidence has run, implementation parity, runtime
correctness, performance, live-service interoperability, broad workspace health,
release readiness, a production dependency exit, or permission to cut over,
narrow functionality, or delete anything.
