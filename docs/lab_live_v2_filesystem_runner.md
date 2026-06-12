# Lab-Live V2 Filesystem Runner

This runner is the first bounded adapter-family lane for
`asupersync-idea-wizard-fifth-wave-3gaiun.5.2`. It covers captured filesystem
semantics only: fixture counters are normalized through
`asupersync::lab::DualRunHarness` on the lab side and
`asupersync::lab::run_live_adapter` on the live side.

The runner intentionally does not claim raw host filesystem parity. The scope
matrix already classifies filesystem, process, signal, and native host effects
as unsupported until they are virtualized or captured. This lane follows that
boundary by treating raw host filesystem probes as `skip`, not `pass`.

## Fixture Set

`artifacts/lab_live_v2_filesystem_runner_v1.json` declares three scenarios:

- `3gaiun.lab_live_v2.filesystem.atomic_write_pass` proves the happy path for
  captured atomic-write counters.
- `3gaiun.lab_live_v2.filesystem.rename_visibility_fail` proves a live-side
  semantic mismatch is preserved in the report when a temporary file becomes
  visible before commit.
- `3gaiun.lab_live_v2.filesystem.raw_host_skip` proves raw host filesystem
  probes remain unsupported and cannot be counted as passing evidence.

Each fixture carries the counters for the lab and live side, a platform policy,
the expected verdict, artifact bundle links, and no-claim text.

## Normalization

The runner compares stable semantic counters only:

- bytes written
- fsync observation
- temporary visibility before commit
- final visibility after rename
- partial reads
- raw host probe intent for the skip fixture

Host-specific values are excluded: paths, mtimes, inodes, device identifiers,
errno values, file watcher timing, and scheduler ordering. A future raw
filesystem lane must add a virtualized or captured host-effect surface before it
can convert those values into comparable evidence.

## Proof Lane

The focused proof command is:

```bash
RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_lab_live_v2_filesystem_runner" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test lab_live_v2_filesystem_runner_contract -- --nocapture
```

This command proves the artifact contract, fixture schema, runner behavior, skip
policy, and documentation markers for this lane.

This lane does not prove process or signal support.

It also does not prove broad workspace health, performance, full adapter
coverage, or raw OS filesystem equivalence.
