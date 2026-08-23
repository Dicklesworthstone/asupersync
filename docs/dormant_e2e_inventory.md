# Dormant real E2E inventory

This document is the human-readable companion to
`artifacts/dormant_e2e_inventory_v1.json` for
`asupersync-d24mms.12.1`. It inventories three source files that exist in the
tree but are not declared by `src/lib.rs`. None of their tests currently
compile or run.

## Compile probes

Each file was temporarily declared by itself under
`all(test, feature = "real-service-e2e")` in a reservation-scoped
`src/lib.rs` clean overlay. The declaration was removed after its remote
`cargo test -p asupersync --lib --features real-service-e2e --no-run` probe.
The committed `src/lib.rs` remains unchanged.

| Source | Entrypoints | Result | Error codes | Repair owner |
| --- | ---: | --- | --- | --- |
| `src/real_fs_dir_fs_vfs_integration_e2e_tests.rs` | 5 | blocked: 8 errors | E0432, E0599, E0603 | `asupersync-d24mms.12.2` |
| `src/real_integration_scenarios_e2e_tests.rs` | 17 | blocked: 247 errors | E0061, E0277, E0308, E0423, E0425, E0432, E0532, E0599, E0608 | `asupersync-d24mms.12.3` |
| `src/real_distributed_e2e_tests.rs` | 5 | blocked: 23 errors | E0061, E0277, E0599 | `asupersync-d24mms.12.4` |

The filesystem file imports removed or private filesystem APIs, uses obsolete
runtime/time/synchronization calls, and is Unix-only because its symlink
import is unconditional. Its aggregate wrapper reaches six logical traversal
scenarios: normal, simple-symlink, cycle, broken-link, mixed-tree, and
cross-VFS traversal.

The general integration file has the broadest drift. All 17 wrappers use
`#[tokio::test]`, which is forbidden in core `src/`. Runtime, time, channel,
RaptorQ, HTTP/2, TCP, rate-limit, error, and outcome APIs have also changed.
Unseeded `fastrand`, wall-clock timestamps, stderr logging, and a loopback
listener must be replaced by deterministic fixtures and canonical artifact
logging. `test_comprehensive_integration_scenario` is only a harness-ready
placeholder and is explicitly not coverage evidence.

The distributed file uses real snapshot files and fixed hash-ring seeds, but
identifier constructors, region state, ring calls, and accessors have drifted.
Its wall-clock logger and `DefaultHasher`-derived persisted origin IDs are not
a stable artifact contract.

## Coverage disposition

All 27 entrypoints appear exactly once in the machine inventory. Twenty-six
are `BLOCKED_REPAIR`; the placeholder is `PLACEHOLDER_NOT_EVIDENCE`.
`UNIQUE_CANDIDATE` and `OVERLAP_CANDIDATE` are triage labels, not terminal
supersession decisions. Existing unit, conformance, snapshot, metamorphic, and
real-E2E paths are cited only as adjacent evidence. No dormant journey is
discarded or marked superseded.

The repair children own source modernization:

- A2 restores the filesystem/directory/VFS journeys.
- A3 restores the cross-subsystem journeys and replaces Tokio, randomness,
  wall time, ambient logging, and orphan-prone task patterns.
- A4 restores the distributed hash/snapshot journeys with stable identifiers,
  joined workers, and bounded filesystem lifecycle.
- A5 integrates repaired journeys into the canonical runner and captures
  `summary.json`, `events.ndjson`, process logs, provenance, resource state,
  redaction results, and replay commands.

Every repaired concurrency scenario must assert no task leaks, no obligation
leaks, loser draining after races, and region-close quiescence. A TempDir drop
is not by itself proof of runtime cleanup.

## A2 maintained-lane recovery disposition

`asupersync-d24mms.12.2` preserves the undeclared 1,223-line source file for
audit history and restores its useful journeys in the maintained
`tests/e2e_fs.rs` real-filesystem lane. The dormant file's `MockVfsLayer` did
not implement the current `Vfs` trait and its cross-mount scenario was only a
pair of host-filesystem symlinks. The recovered scenarios instead execute
through `UnixVfs`, `Vfs`, `ReadDir`, and Asupersync's symlink/path operations.

| Dormant inventory row | Maintained scenario row | Disposition |
| --- | --- | --- |
| `DORMANT-FS-001` aggregate | all seven `dormant-fs-*` rows | Equal-or-better active runner coverage, including bounded partial traversal and replay |
| `DORMANT-FS-002` normal traversal | `dormant-fs-normal-recursive-traversal` | Empty, nested, and 256 KiB files with exact directory/file/byte accounting |
| simple-symlink logical scenario | `dormant-fs-simple-symlink-traversal` | Real file and directory symlinks with canonical-file deduplication |
| `DORMANT-FS-003` circular links | `dormant-fs-circular-symlink-detection` | Real three-directory and self cycles with exact cycle count and bounded entry count |
| `DORMANT-FS-004` broken links | `dormant-fs-broken-symlink-handling` | Never-created and removed targets with exact dangling-link count |
| `DORMANT-FS-005` mixed tree | `dormant-fs-mixed-symlink-tree` | Real directories, files, valid links, a cycle, and a dangling link in one traversal |
| cross-VFS logical scenario | `dormant-fs-cross-root-vfs-traversal` | Real bidirectional cross-root traversal; explicitly no mount-isolation claim |
| partial/cancel boundary | `dormant-fs-bounded-partial-traversal` | Entry-budget stop, iterator drop, and complete replay with exact cleanup-visible accounting |

The focused runner accepts a bead override while retaining the historical
default:

```bash
RCH_REQUIRE_REMOTE=1 \
ASUPERSYNC_FS_PARITY_BEAD_ID=asupersync-d24mms.12.2 \
bash scripts/fs_parity_proof_runner.sh \
  target/fs-parity-proof/asupersync-d24mms.12.2
```

Its `scenario_rows.jsonl` and `run_report.json` include exact byte, metadata,
error, bounded-stop, platform-support, and temporary-root cleanup fields.
Unix-only symlink rows emit an explicit unsupported verdict elsewhere; they do
not silently pass. Canonical `scripts/run_all_e2e.sh` integration and aggregate
logging remain owned by A5 (`asupersync-d24mms.12.5`).

## A3 maintained-lane recovery disposition

`asupersync-d24mms.12.3` preserves the undeclared 5,728-line Tokio-era source
for audit history and restores its useful journeys in
`src/real_cross_subsystem_recovery_e2e_tests.rs`. The focused
`cross-subsystem-recovery-e2e` profile includes `proc-macros` for the crate's
test attributes and `obligation-cleanup-e2e` for the real worker-restart
obligation ledger harness; it does not enable the `real-service-e2e` umbrella.

| Dormant row | Maintained operation | Externally observed result and cleanup |
| --- | --- | --- |
| `DORMANT-INT-001` | broadcast fanout after one consumer drops | Both healthy subscribers receive every accepted value; sender drop produces explicit closure |
| `DORMANT-INT-002` | two-tier circuit-breaker recovery | Both breakers open, reject, half-open on virtual time, close, and expose exact transition metrics |
| `DORMANT-INT-003` | isolated `RegionBridge` failure | Failed region reaches `Closed`; the peer accepts additional work; both end with no live work |
| `DORMANT-INT-004` | bounded two-stage MPSC pipeline | Upstream and downstream `Full` boundaries are observed, accepted values are exact, queues drain |
| `DORMANT-INT-005` | placeholder disposition | Exactly one explicit `skip` with `PLACEHOLDER_NOT_EVIDENCE`; it is never counted as executed coverage |
| `DORMANT-INT-006` | supervisor restart with pending acks | Existing real obligation harness asserts empty pending/leak counts and runtime quiescence |
| `DORMANT-INT-007` | pre-admitted zero-delay hedge | `Cx::race_drained` returns one success only after the pending loser is cancelled, dropped, and drained |
| `DORMANT-INT-008` | three bridge replacement generations | Each replacement applies the current real snapshot with monotonic sequence/task state; active bridge closes |
| `DORMANT-INT-009` | broker-generation reconnect | First broadcast generation closes visibly; the next generation resumes exact accepted delivery and closes |
| `DORMANT-INT-010` | interrupted RaptorQ decode | An insufficient decode fails, retained equations resume, and all source bytes reconstruct exactly |
| `DORMANT-INT-011` | runtime panic containment | A caught injected `block_on` panic is followed by successful runtime reuse and explicit subscription closure |
| `DORMANT-INT-012` | virtual-time burst limiting | Three tokens admit, the next request blocks, refill admits recovery work, and all admitted calls complete |
| `DORMANT-INT-013` | loopback/H2 churn | 32 joined TCP connections carry codec-decoded SETTINGS frames; 32 real H2 stream slots reset, prune, and drain |
| `DORMANT-INT-014` | timer-wheel churn | 256 timers split into 128 explicit cancels and 128 expirations; the wheel ends empty |
| `DORMANT-INT-015` | checkpoint/snapshot resume | Four virtual-hour checkpoints match uninterrupted state; an owned `ASUPSNAP` envelope round-trips and validates |
| `DORMANT-INT-016` | bounded memory-pressure recovery | Capacity refusal is exact, drain restores admission, all six accepted values arrive, backlog returns to zero |
| `DORMANT-INT-017` | partitioned snapshot healing | One follower misses sequence 2 while the other advances; healing applies the monotonic snapshot and all bridges close |

Run the focused, remote-required receipt validator with:

```bash
RCH_REQUIRE_REMOTE=1 \
bash scripts/cross_subsystem_recovery_proof_runner.sh
```

The runner uses RCH clean-overlay admission from `HEAD` plus the three compile
inputs (`Cargo.toml`, `src/lib.rs`, and the maintained module), rejects local
fallback, requires all 17 row IDs exactly once, compares `expected` to `actual`
for all 16 active rows, and permits only the named placeholder disposition.
Its `run_report.json`, `scenario_rows.jsonl`, and `run.log` retain the remote
command, source revision, feature profile, deterministic seeds, cancellation
boundaries, cleanup state, and replay command. Canonical
`scripts/run_all_e2e.sh` integration remains owned by A5.

## A4 maintained-lane recovery disposition

`asupersync-d24mms.12.4` preserves the undeclared 828-line distributed source
for audit history and restores its five real capabilities in
`tests/distributed_hash_snapshot_recovery_e2e.rs`. The focused
`distributed-hash-snapshot-recovery-e2e` profile exposes test-only identifiers
without enabling the `real-service-e2e` umbrella. Every snapshot crosses a real
file boundary and an explicit authentication check; every host worker is
joined before its temporary root is explicitly removed.

| Dormant row | Maintained operation | Externally observed result and cleanup |
| --- | --- | --- |
| `DORMANT-DIST-001` | fixed-seed ring scale-up and peer failure | Only keys assigned to the added peer move on scale-up; only keys owned by the failed peer move on removal; membership and vnode ownership are exact |
| `DORMANT-DIST-002` | authenticated snapshot file roundtrip | Signed bytes are written, fsynced, read, authenticated, and compared field-by-field; the closed file and temporary root are absent afterward |
| `DORMANT-DIST-003` | concurrent snapshot persistence with cancellation | Six joined host workers cross two barriers; five publish isolated authenticated files, one coordinator-cancelled worker creates no file, and receipt collection is time-bounded |
| `DORMANT-DIST-004` | real-file failure boundaries | Missing, empty, truncated, and tampered snapshots preserve exact I/O or `SnapshotError` outcomes; no invalid snapshot is published |
| `DORMANT-DIST-005` | peer failure, migration retry, and restart | Failed-peer keys reroute, a tampered transfer fails closed, exact bytes retry and publish, the same peer identity restores its assignment map, and shutdown releases every vnode and data directory |

Run the focused, remote-required receipt validator with:

```bash
RCH_REQUIRE_REMOTE=1 \
bash scripts/distributed_hash_snapshot_recovery_proof_runner.sh
```

The runner admits a clean overlay from `HEAD` containing only `Cargo.toml` and
the maintained integration test, rejects local fallback, bounds the full RCH
command, requires all five scenario IDs exactly once, and accepts no skips,
infrastructure blockers, expected/actual drift, or first-failure receipt. Its
`run_report.json`, `scenario_rows.jsonl`, and `run.log` retain the exact remote
command, source revision, feature profile, fixed seeds, lifecycle/cleanup
state, and replay command. Canonical `scripts/run_all_e2e.sh` integration and
aggregate redaction/provenance reporting remain owned by A5.

## No-claim boundary

This packet proves inventory completeness, source pins, dormant module state,
and captured compile drift only. It does not prove that the dormant tests
compile, run, are deterministic, are superseded, or provide canonical E2E
evidence. It makes no broad workspace, performance, release-readiness,
runtime-correctness, or live-service claim.

The A2 maintained-lane mapping does not claim a virtual mount implementation,
mount isolation, rollback of filesystem mutations after future drop, broad
workspace health, or canonical A5 runner admission. All recovered operations
are awaited before temporary-root removal; the bounded partial row proves an
iterator-drop and replay boundary, not preemptive cancellation of an in-flight
host syscall.

The A3 maintained lane does not claim production throughput, a multi-process
broker, HTTP request/response interoperability beyond the exercised loopback
SETTINGS wire and H2 connection-slot surfaces, durable application checkpoint
payloads beyond the owned runtime snapshot envelope, PBFT/consensus safety, a
real network partition, broad workspace health, release readiness, or canonical
A5 runner admission. `DORMANT-INT-017` proves `RegionBridge` snapshot lag and
healing only. The deliberate panic text in `DORMANT-INT-011` is caught test
input, not an uncaught test failure; the subsequent receipt is emitted only
after the same runtime successfully serves and closes a replacement channel.

The A4 maintained lane does not claim a multi-process remote runtime, socket or
network transport, service discovery, peer TLS identity, WAN retry behavior,
PBFT or consensus safety, a production wire-format freeze, throughput,
performance improvement, broad workspace health, release readiness, or
canonical A5 runner admission. The dormant source never exercised those
surfaces. Its "peers" are deterministic `HashRing` identities and its migration
boundary is authenticated snapshot bytes crossing isolated real files. The
focused test and receipt runner were authored in the same slice, so this is
self-verification rather than independent review; a planted zero-receipt run
must still be retained to show that the runner fails closed.
