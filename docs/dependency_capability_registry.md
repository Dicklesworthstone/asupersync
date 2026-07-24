# Dependency capability registry

This document is the checked human view of
`artifacts/dependency_capability_registry_v1.json`. The artifact is canonical;
the table below is deterministic and the contract test rejects drift.

## No feature loss

Dependency sovereignty is a means, not the product boundary. The program must
preserve every accepted public API, generic extension point, Cargo feature,
binary, format, protocol, platform behavior, diagnostic, downstream
integration, and documented user journey. A smaller dependency graph never
justifies silently narrowing functionality or making the system harder to use.

`UNKNOWN_BLOCKING` means exactly that: missing evidence blocks cutover. It
never means unused. Broad capabilities remain on their incumbent
implementation (`KEEP_INCUMBENT`) until equal-or-better evidence exists. This
is especially important for arbitrary Serde values, downstream-authored
Protobuf messages, user-supplied regexes, third-party OpenTelemetry
SDK/provider integrations, all four CLI binaries, accepted TOML and YAML,
Brotli, complete NKeys, SQLite, Kafka, TLS/X.509, platform boundaries, and
public Stream implementations.

## What one capability row owns

Every row names:

- the current dependency and source owners;
- public, persisted, wire, security, platform, or operator exposure;
- feature and platform coordinates;
- input, output, error, and resource semantics;
- security and cancellation invariants;
- downstream consumers and a baseline fixture/command;
- every replacement bead, its unit-test owner, its no-mock E2E owner, and
  stable scenario IDs;
- the disposition, evidence state, cutover state, and no-claim boundary.

The auxiliary inventories independently cover all 57 Cargo features, 14
binaries, 298 root exports, 19 API-map entry points, 19 format families, 43
ASUP codes, 33 safety-taxonomy candidates, a curated live downstream
portfolio, and every current `dep-plan` bead. New source or tracker surfaces
therefore fail the focused contract until they receive an explicit mapping.

CLI coverage is deliberately fail-closed while CLI A1 is pending. The registry
pins all six parser/command sources plus the shared exit-code registry by full
source hash and line count, records each command root, all observed environment
variables, the semantic exit-code set, and the help/OsString/accessibility
contract. Any option, alias, default, value parser, constraint, help text, or
exit-path edit therefore forces review. These source snapshots are an
inventory boundary, not a substitute for CLI A1 byte goldens or CLI A11
installed workflows.

## Evidence ownership

CAP A1 is an inventory and governance artifact. It does not pretend that future
runtime evidence already exists:

- CAP A2 owns executable baseline corpora, downstream builds, and observable
  behavior snapshots.
- VER A1 owns the invariant-to-unit/property/model/fuzz evidence matrix.
- VER A2 owns `scripts/run_all_e2e.sh --suite dependency-sovereignty`, stable
  run/scenario/step IDs, validated `summary.json` and `events.ndjson`,
  per-step stdout/stderr, toolchain/source/feature/target/host/RCH provenance,
  normalized errors and cancellation/resource states, canary-secret scans,
  cleanup receipts, and deterministic replay.
- Campaign-specific leaves own protocol/service/format/security/performance
  evidence. The final cutover is always serialized after those gates.

For SQLite specifically, FrankenSQLite is a reverse dependency today. Oracle
and integration work must run in a neutral synthesized consumer or in the
downstream repository; adding FrankenSQLite to asupersync would create a Cargo
cycle and is forbidden.

## Generated summary

<!-- BEGIN GENERATED CAPABILITY SUMMARY -->
- Artifact: `dependency-capability-registry-v1` (schema 1)
- Inventories: 50 capabilities; 57 Cargo features; 14 binaries; 19 formats; 33 journeys; 33 taxonomy candidates; 16 downstream consumers; 103 bead mapping rules.
- Categories: CLI=4, async-api=1, authentication=1, benchmark-tooling=1, codec=2, collection=2, compression=2, concurrency-hot-path=1, configuration=2, database=2, dependency-governance=1, downstream-interop=1, filesystem=2, interop=1, messaging=2, operator-ux=1, parser=1, pattern-matching=1, performance-experiment=1, performance-kernel=1, persisted-format=1, platform=3, platform-io=1, proc-macro=1, public-api=2, runtime-core=1, security=1, security-protocol=1, serialization=2, synchronization=1, telemetry=1, time=1, transport=1, verification=2, verification-runtime=1.
- Dispositions: EXPERIMENT_ONLY=2, INTERNAL_ONLY=1, KEEP_UNTIL_PARITY=21, PRESERVE=8, PRESERVE_AND_REPLACE_IF_PARITY=18.
- Evidence states: BASELINE_EXISTING=4, BASELINE_PLANNED=46.
- Cutover states: BLOCKED_PENDING_EVIDENCE=18, KEEP_INCUMBENT=23, NOT_A_CUTOVER=9.

| Capability ID | Category | Disposition | Evidence | Cutover | E2E owner |
|---|---|---|---|---|---|
| `CAP-ATP-VERSION-SCANNER` | parser | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-d24mms.11` |
| `CAP-AUTH-CREDENTIALS` | security | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-dep-p1-foundations-upksjk.6.3` |
| `CAP-BASE64-CODEC` | codec | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-d24mms.10.6` |
| `CAP-BROWSER-RUNTIME` | platform | PRESERVE | BASELINE_PLANNED | NOT_A_CUTOVER | `asupersync-dep-p1-foundations-upksjk.6.5` |
| `CAP-CACHE-LAYOUT` | performance-experiment | EXPERIMENT_ONLY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-0h6myr.6` |
| `CAP-CLI-ASUPERSYNC` | CLI | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-5z2scg.7.11` |
| `CAP-CLI-ATP` | CLI | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-5z2scg.7.11` |
| `CAP-CLI-ATPD` | CLI | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-5z2scg.7.11` |
| `CAP-CLI-OFFLINE-TUNER` | CLI | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-5z2scg.7.11` |
| `CAP-CONCURRENT-QUEUES` | concurrency-hot-path | EXPERIMENT_ONLY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-0h6myr.2` |
| `CAP-CONFIG-TOML-JSON` | configuration | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-5z2scg.4.5` |
| `CAP-DATABASE-WIRE` | database | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-dep-p1-foundations-upksjk.6.3` |
| `CAP-DEPENDENCY-LEDGER` | dependency-governance | INTERNAL_ONLY | BASELINE_EXISTING | NOT_A_CUTOVER | `asupersync-dep-p1-foundations-upksjk.4` |
| `CAP-DIAGNOSTICS` | operator-ux | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_EXISTING | BLOCKED_PENDING_EVIDENCE | `asupersync-dep-p1-foundations-upksjk.6.2` |
| `CAP-DOWNSTREAM-CONSUMERS` | downstream-interop | PRESERVE | BASELINE_PLANNED | NOT_A_CUTOVER | `asupersync-dep-p1-foundations-upksjk.6.5` |
| `CAP-FUTURES-STREAMS` | async-api | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-d24mms.6.10` |
| `CAP-HASH-MAPS` | collection | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-dep-p1-foundations-upksjk.6.2` |
| `CAP-HEX-CODEC` | codec | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-d24mms.9.4` |
| `CAP-HOST-BENCH-METADATA` | benchmark-tooling | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-dep-p1-foundations-upksjk.6.5` |
| `CAP-HOST-INTROSPECTION` | platform | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-3u3tej.2.7` |
| `CAP-HTTP-COMPRESSION` | compression | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-0h6myr.5.7` |
| `CAP-KAFKA` | messaging | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-dep-p7-kafka-removal-sarszu.2.13` |
| `CAP-LAB-DETERMINISM` | verification-runtime | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-dep-p1-foundations-upksjk.6.2` |
| `CAP-NATS-MESSAGING` | messaging | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-dep-p1-foundations-upksjk.6.3` |
| `CAP-NKEY-AUTH` | authentication | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-dep-p4-nkeys-poc60v.5` |
| `CAP-OTLP-ECOSYSTEM` | telemetry | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-5z2scg.2.9` |
| `CAP-PERSISTED-TRACE-SNAPSHOT` | persisted-format | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-5z2scg.3.7` |
| `CAP-POLLING-SOCKET` | platform-io | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-dep-p1-foundations-upksjk.6.5` |
| `CAP-PROC-MACROS` | public-api | PRESERVE | BASELINE_PLANNED | NOT_A_CUTOVER | `asupersync-dep-p1-foundations-upksjk.6.2` |
| `CAP-PROTOBUF-GENERIC` | serialization | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-5z2scg.1.7` |
| `CAP-PUBLIC-API-TOPOLOGY` | public-api | PRESERVE | BASELINE_EXISTING | NOT_A_CUTOVER | `asupersync-dep-p1-foundations-upksjk.6.2` |
| `CAP-QUIC-HTTP3-ATP` | transport | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-dep-p1-foundations-upksjk.6.3` |
| `CAP-REAL-SERVICE-E2E` | verification | PRESERVE | BASELINE_PLANNED | NOT_A_CUTOVER | `asupersync-dep-p1-foundations-upksjk.6.2` |
| `CAP-REGEX-PRIVACY` | pattern-matching | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-5z2scg.8.5` |
| `CAP-SCENARIO-YAML-JSON` | configuration | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-5z2scg.5.5` |
| `CAP-SERDE-GENERIC` | serialization | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-5z2scg.3.7` |
| `CAP-SIGNALS` | platform | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-3u3tej.1.7` |
| `CAP-SIMD-RAPTORQ` | performance-kernel | PRESERVE | BASELINE_EXISTING | NOT_A_CUTOVER | `asupersync-dep-p1-foundations-upksjk.6.2` |
| `CAP-SQLITE` | database | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-ym2wtv.3.5` |
| `CAP-STRUCTURED-CONCURRENCY` | runtime-core | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-dep-p1-foundations-upksjk.6.2` |
| `CAP-SYNC-LOCKS` | synchronization | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-0h6myr.1.10` |
| `CAP-TEMP-ARTIFACTS` | filesystem | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-dep-p1-foundations-upksjk.6.2` |
| `CAP-TIME-UTC-RFC3339` | time | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-5z2scg.6.7` |
| `CAP-TLS-X509` | security-protocol | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-0h6myr.3.8` |
| `CAP-TOKEN-SLAB` | collection | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-d24mms.8` |
| `CAP-TOWER-COMPAT` | interop | PRESERVE | BASELINE_PLANNED | NOT_A_CUTOVER | `asupersync-dep-p1-foundations-upksjk.6.5` |
| `CAP-TRACE-LZ4` | compression | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-0h6myr.4.4` |
| `CAP-VERIFICATION-PROFILES` | verification | PRESERVE | BASELINE_PLANNED | NOT_A_CUTOVER | `asupersync-dep-p1-foundations-upksjk.6.2` |
| `CAP-VISIBILITY-MACRO` | proc-macro | PRESERVE_AND_REPLACE_IF_PARITY | BASELINE_PLANNED | BLOCKED_PENDING_EVIDENCE | `asupersync-dep-p1-foundations-upksjk.6.5` |
| `CAP-XATTR` | filesystem | KEEP_UNTIL_PARITY | BASELINE_PLANNED | KEEP_INCUMBENT | `asupersync-3u3tej.3.5` |
<!-- END GENERATED CAPABILITY SUMMARY -->

## Focused contract

Run:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_capability_registry" cargo test -p asupersync --test dependency_capability_registry_contract -- --nocapture
```

The contract validates row completeness and negative mutations, exact Cargo
features and binaries, the semantic root-export projection, entry-point
journeys, formats, ASUP codes, safety candidates, downstream manifests, all
current dependency-program beads, and this generated summary.

This is scoped inventory evidence only. It does not prove implementation
parity, runtime correctness, performance, live-service interoperability, broad
workspace health, release readiness, or permission to cut over or delete
anything.
