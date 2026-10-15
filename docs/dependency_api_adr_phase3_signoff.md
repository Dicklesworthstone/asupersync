# Phase-3 aggregate signoff — dependency-sovereignty owner ADRs

- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Phase: `asupersync-dep-p3-api-adrs-h3jspm`
- Aggregate bead: `asupersync-dep-p3-api-adrs-h3jspm.13`
- Machine artifact: [`artifacts/dependency_api_adr_phase3_signoff_v1.json`](../artifacts/dependency_api_adr_phase3_signoff_v1.json)
- Contract: [`tests/dependency_api_adr_phase3_signoff_contract.rs`](../tests/dependency_api_adr_phase3_signoff_contract.rs)
- Per-ADR registry: [`dependency_api_adr_registry.md`](./dependency_api_adr_registry.md)
- Narratives: [`docs/adr/`](./adr/)

## What this gate is

The terminal Phase-3 decision gate. The per-ADR lane proves each ADR still
describes the live crate — frozen symbols exist, frozen feature definitions are
unchanged, no ADR text authorizes loss. **This lane proves the *set* is complete
and internally consistent**: every capability covered exactly once, every
capability with exactly one primary cutover authority, no UNKNOWN row, no
wideable gap, every gap owned by a live bead, and negative fixtures covering
every ADR.

It authorizes **no source change and no dependency cutover**. It proves only that
the downstream campaigns have unambiguous, no-loss contracts to start from.

Every row below is **derived**. The contract re-derives each one from the live
ADR registry, capability registry and tracker, so a stale row is a test failure
rather than documentation drift.

<!-- BEGIN GENERATED PHASE3 SIGNOFF SUMMARY -->
- Artifact: `dependency-api-adr-phase3-signoff-v1` (schema 1)
- Aggregate bead: `asupersync-dep-p3-api-adrs-h3jspm.13`; phase `asupersync-dep-p3-api-adrs-h3jspm`.
- ADRs: 12 resolved, 0 pending. Capabilities covered: 17.
- Known gaps: 92 across 46 owner beads. Negative fixtures: 20.

| ADR | Capabilities | Decision | Cutover | Gaps |
|---|---|---|---|---|
| `DEP-ADR-001` | `CAP-PERSISTED-TRACE-SNAPSHOT`, `CAP-SERDE-GENERIC` | ADDITIVE_COEXISTENCE | BLOCKED_PENDING_EVIDENCE / KEEP_INCUMBENT | 9 |
| `DEP-ADR-002` | `CAP-PROTOBUF-GENERIC` | KEEP_UNTIL_PARITY | KEEP_INCUMBENT | 6 |
| `DEP-ADR-003` | `CAP-OTLP-ECOSYSTEM` | ADDITIVE_COEXISTENCE | KEEP_INCUMBENT | 7 |
| `DEP-ADR-004` | `CAP-CONFIG-TOML-JSON`, `CAP-SCENARIO-YAML-JSON` | ADDITIVE_COEXISTENCE | KEEP_INCUMBENT | 6 |
| `DEP-ADR-005` | `CAP-CLI-ASUPERSYNC`, `CAP-CLI-ATP`, `CAP-CLI-ATPD`, `CAP-CLI-OFFLINE-TUNER` | KEEP_UNTIL_PARITY | KEEP_INCUMBENT | 10 |
| `DEP-ADR-006` | `CAP-HTTP-COMPRESSION` | KEEP_UNTIL_PARITY | KEEP_INCUMBENT | 7 |
| `DEP-ADR-007` | `CAP-NKEY-AUTH` | KEEP_UNTIL_PARITY | KEEP_INCUMBENT | 8 |
| `DEP-ADR-008` | `CAP-FUTURES-STREAMS` | KEEP_UNTIL_PARITY | BLOCKED_PENDING_EVIDENCE | 7 |
| `DEP-ADR-009` | `CAP-KAFKA` | KEEP_UNTIL_PARITY | KEEP_INCUMBENT | 8 |
| `DEP-ADR-010` | `CAP-SQLITE` | KEEP_UNTIL_PARITY | KEEP_INCUMBENT | 8 |
| `DEP-ADR-011` | `CAP-TIME-UTC-RFC3339` | ADDITIVE_COEXISTENCE | BLOCKED_PENDING_EVIDENCE | 9 |
| `DEP-ADR-012` | `CAP-REGEX-PRIVACY` | KEEP_UNTIL_PARITY | KEEP_INCUMBENT | 7 |
<!-- END GENERATED PHASE3 SIGNOFF SUMMARY -->

## What the sweep found

Twelve ADRs read the source directly rather than trusting the plan. In eleven of
the twelve, the source contradicted the plan's premise. The pattern is
consistent enough to be worth stating: **the plan sized work from crate names and
package counts, and the source read repeatedly found either a much larger
capability behind the name, or a much smaller one that had already been
half-built and abandoned.**

Concrete examples, each recorded in its ADR's `supersedes` list:

- **OTLP** — metrics and traces have *no* production wire encoder; the builder is
  test/fuzz-gated. The external SDK bridge is the only production path for two of
  three signals.
- **Protobuf** — the trade was self-defeating: the finite schemas the plan wanted
  in exchange already exist and are already prost-free.
- **Serde formats** — not an API trim but a *persisted-format break*. No byte
  golden exists for either affected format.
- **CLI** — parity is unmeasurable: no `--help` golden exists anywhere, and 22
  commands are reachable from no binary.
- **Brotli** — the orphaned compression module **has never compiled**.
- **NKey** — spans four subsystems, not NATS-only, and the swap would *add* a
  direct cryptographic dependency.
- **Kafka** — the public API is *already* completely engine-free, which is the
  best possible starting position; but removal was gated on a downstream
  inventory nobody has run.
- **SQLite** — the bead's own description was factually wrong about the
  dependency being optional; the cycle constraint is absolute.
- **regex** — the "fixed scanners" fast path does not exist: all four built-in
  detectors are themselves regex-backed.

Every one of these is a decision that would have been made wrong from the plan
alone.

## Registry defect ledger

The sweep's most reusable finding. Of the twelve capabilities carrying ADRs,
**exactly one `source_owners` row was fully correct**. Eighteen wrong or
incomplete rows across fourteen capabilities are recorded on `asupersync-dvgpji`.

Root cause: the API-surface selectors map module-name *words* rather than actual
imports, so a capability is credited to whatever module shares its name — which
is why the RaptorQ FEC pipeline is credited with two serialization capabilities,
and why the regex capability names an observability facade containing zero regex
references. A secondary pattern names `mod.rs` facades instead of implementations.

Two cheap structural checks would catch nearly all of it:

1. A `source_owners` file must reference at least one of the row's
   `dependency_owners`.
2. Every file importing a `dependency_owner` must appear in `source_owners`.

Check 2 is the omission-direction dual of check 1, and Kafka is why it is needed:
both of that row's entries are genuine, and the row is still only half the
surface.

## Gap ledger

Ninety-two recorded gaps is a finding, not a defect of the ADRs. Most are
**missing evidence rather than missing capability**: absent baselines,
unimplemented scenario ids, and the source-owner rows above. Several registry
baseline commands name scenarios that appear nowhere in the runner script.

Every gap is marked non-wideable and owned by a live bead. A gap records a limit
of the current implementation; it never licenses narrowing the frozen surface.

## Terminal postures

No ADR authorizes a dependency exit. Every capability lands on a preserving
cutover state — either `KEEP_INCUMBENT`, or `BLOCKED_PENDING_EVIDENCE` where an
owned replacement is authorized additively but gated on evidence that does not
yet exist.

`KEEP_UNTIL_PARITY` is a valid terminal decision here, not a deferral. Where the
measurement to justify a swap does not exist, the honest posture is to say so and
keep the working capability.

## Proof

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_phase3_signoff" cargo test -p asupersync --test dependency_api_adr_phase3_signoff_contract -- --nocapture
```

E2E scenario id: `api-adr-phase3-signoff`.

## No-claim boundary

This aggregate certifies **decision completeness and internal consistency only**.
It does not prove that any planned evidence has run, that any capability is
correctly implemented, that any replacement could reach parity, that the
capability registry's source-owner rows are accurate, that performance is
unchanged, or that any dependency may be removed. It authorizes no source change
and no dependency cutover.
