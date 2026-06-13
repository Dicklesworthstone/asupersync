# State Snapshot And Live-Upgrade Readiness

<!-- STATE-SNAPSHOT-LIVE-UPGRADE:SOURCE -->

`artifacts/state_snapshot_live_upgrade_readiness_v1.json` is the checked source
of truth for `asupersync-idea-wizard-fifth-wave-3gaiun.15`.

This readiness track is intentionally narrow. It describes what would be needed
for versioned runtime snapshots and restart-style handoff on selected surfaces.
It does not claim production live upgrade is implemented, and it explicitly does
not support arbitrary hot code reload.

<!-- STATE-SNAPSHOT-LIVE-UPGRADE:SCHEMA -->

## Versioned Snapshot Schema

The current foundation is `RestorableSnapshot` in `src/lab/snapshot_restore.rs`.
It records a schema version and deterministic content hash around a
`RuntimeSnapshot`. The readiness schema requires these sections before any
handoff claim can be made:

| section | why it matters |
|---|---|
| `schema_version` | target runtime must explicitly accept the snapshot version |
| `content_hash` | semantic tampering must fail closed before restore |
| `runtime_snapshot` | source runtime state being handed off |
| `region_tree` | quiescence and ownership validation |
| `task_table` | task-to-region references and terminal state |
| `obligation_table` | permit, ack, lease, and cleanup accounting |
| `logical_time` | deterministic replay and timestamp checks |
| `quiescence_proof` | success requires closed regions to have no live children |

Until a migration table exists, only exact schema-version matches are eligible.
Unknown versions, content hash mismatches, orphan references, cyclic region
trees, non-quiescent closed regions, and unresolved handoff obligations reject
the handoff.

<!-- STATE-SNAPSHOT-LIVE-UPGRADE:MATRIX -->

## Feasibility Matrix

| surface | support class | readiness |
|---|---|---|
| lab restorable snapshot | implemented foundation | ready for focused proof |
| lab determinism roundtrip | implemented test surface | ready for focused proof |
| runtime region quiescence handoff | design required | blocked until runtime API |
| distributed snapshot distribution | adjacent foundation | needs integration proof |
| browser coordinator handoff | bounded browser surface | needs consumer proof |
| arbitrary hot code reload | explicitly unsupported | unsupported |

This matrix separates foundations from product claims. Existing lab snapshots
and deterministic conformance tests are useful evidence, but they do not by
themselves create a public production live-upgrade API.

<!-- STATE-SNAPSHOT-LIVE-UPGRADE:HANDOFF -->

## Handoff Protocol

The proposed restart-style handoff protocol has five phases:

1. `prepare`: choose an explicitly supported surface and target schema version
2. `quiesce`: close selected regions and resolve or abort obligations
3. `snapshot`: capture `RestorableSnapshot` with schema and content hash
4. `validate`: verify hash, structure, and target version acceptance
5. `restore`: restore into a fresh runtime and run to quiescence before success

The operator report must preserve `pass`, `blocked`, `unsupported`, and `stale`
as distinct outcomes. It must not collapse unsupported hot reload into a partial
success.

<!-- STATE-SNAPSHOT-LIVE-UPGRADE:FIXTURES -->

## Fail-Closed Fixtures

The contract includes fail-closed fixture rows for incompatible schema versions,
content hash mismatches, non-quiescent closed regions, orphan task references,
unresolved obligations, and unsupported hot-code-reload claims.

Any one of those rows blocks handoff success until the underlying state or
evidence is corrected and the focused remote proof lane is rerun.

## Validation

Use the focused remote-only contract lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_state_snapshot_live_upgrade_readiness" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test state_snapshot_live_upgrade_readiness_contract --no-default-features -- --nocapture
```

Local Cargo fallback is not evidence for this contract.

<!-- STATE-SNAPSHOT-LIVE-UPGRADE:NO-CLAIMS -->

## No-Claim Boundaries

This readiness contract does not implement production live upgrade, restart
handoff, arbitrary hot code reload, stack migration, live task code mutation,
distributed restore compatibility, browser package upgrade compatibility,
performance improvement, broad workspace health, release readiness, or live RCH
fleet availability.
