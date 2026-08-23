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
