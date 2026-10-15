# Managed Channel and Supervisor E2E

The maintained target is [`tests/supervision_regression.rs`](../tests/supervision_regression.rs), using the managed API in [`src/supervision.rs`](../src/supervision.rs). The complete remote lane on 2026-09-06 UTC passed the 40-test native prerequisite, 506 focused units, and all six public tests, including the 90 journeys below and two native SIGTERM subprocesses. The focused selection includes six native registered-finalizer-before-replacement cases: all three restart strategies on current-thread and two-worker sharded runtimes. Each case requires finalizer completion and old-region closure before every replacement spawn, with zero remaining tasks, obligations, timers, or owned regions. All three stages used the same selected source and overlay fingerprint.

The public path compiles a `SupervisorBuilder`, supplies named `ManagedChildBinding` factories through `bind_managed`, and calls `ManagedSupervisor::spawn(&Cx)`. Each factory receives its actual child `Cx` and `ManagedGeneration`. Workers use bounded MPSC mailboxes. The retained `ManagedSupervisorHandle` requests cancellation through `abort()` and waits for the controller's report through `join()`.

The public tests define 18 journeys, repeated on three seeded `LabRuntime` runs, a native current-thread runtime, and a native two-worker runtime with sharded state:

- Six journeys exercise `OneForOne`, `OneForAll`, and `RestForOne` with typed worker errors and actual poll panics. They check the exact affected generations, fresh task/region identities, unchanged unaffected identities, and exact mailbox payloads before and after replacement.
- Nine journeys cross `Permanent`, `Transient`, and `Temporary` restart modes with normal completion, typed error, and actual panic.
- Three journeys cancel inside a child factory, cancel while an actual backoff timer is registered, and exhaust the shared restart intensity while observing escalation to a real parked sibling.

The assertions hold asynchronous cleanup at a real `Pending`, reject premature completion, and require canonical `Complete` events for the actual task/region identities. The interdependent case makes one child's cleanup await another child's witness. An old mailbox must return `SendError::Disconnected` with its unsent value after replacement. Runtime checks require no live tasks or leaked obligations; native runs also require successful shutdown. These are task-owned cleanup callbacks; runtime region finalizers have separate focused tests in the same runner.

Run from `main` after the candidate runner, runtime, and tests are committed at the selected revision:

```bash
cd /data/projects/asupersync
base=$(git rev-parse HEAD)
RCH_REQUIRE_REMOTE=1 bash scripts/test_obligation_cleanup_e2e.sh \
  --managed-supervision --base "$base" --no-overlay
```

`--no-overlay` excludes every uncommitted change. For a test-only candidate whose runtime and runner are already committed at `base`, reserve that exact test path and select it explicitly:

```bash
base=$(git rev-parse HEAD)
RCH_REQUIRE_REMOTE=1 bash scripts/test_obligation_cleanup_e2e.sh \
  --managed-supervision --base "$base" \
  --overlay-path tests/supervision_regression.rs
```

Repeat `--overlay-path` for every additional owned, reserved candidate file. Do not include peer changes or assume omitted edits reached the worker. The runner requires supported RCH clean-overlay capabilities, uses strict remote execution with target reuse disabled, pins later stages to the first selected worker, and joins each stage to the same base and overlay fingerprint. Its Cargo commands use `--locked`, the exact explicit feature list `tls,test-internals`, and bounded build jobs; normal default features remain enabled.

The stages run in this order:

1. The full `runtime_abort_vs_cancel_semantics_audit` target, unfiltered.
2. Focused supervisor, finalizer, region, child-region, runtime-state, native cleanup-budget, external-table finalizer, and private Lab signal-source unit tests.
3. The full `supervision_regression` target, unfiltered, including its owned native SIGTERM subprocess tests. Each child subprocess selects its exact helper test; its filtered count is separate from the parent target's count.

| Setting | Meaning |
| --- | --- |
| `CHECKED_ADMISSION_BUILD_JOBS` | Positive Cargo job count; defaults to `8`. |
| `CHECKED_ADMISSION_CARGO_HOME` | Optional Cargo home forwarded to the remote worker; otherwise the runner uses a supplied `CARGO_HOME`. The path must be valid on that worker. |
| `MANAGED_SUPERVISION_ARTIFACT_DIR` | New output directory for this run. Existing directories are refused to preserve their evidence. |
| `RCH_TARGET_DIR` | Cargo target root used for the remote stages. |

Inspect `native.log`, `units.log`, and `supervision.log` first when a stage fails. Keep their stderr, the first failure, `source-selection.json`, per-stage source receipts, `stages.ndjson`, and `summary.json`. A completed public stage also produces `supervision-journeys.json`. The summary schema is `asupersync.managed_supervision_runner.v1`; its admission receipts and locally selected file hashes do not constitute an independently hashed worker content manifest (`worker_content_manifest_verified` remains false).

The native 60-second watchdog and subprocess 45-second watchdog bound a test attempt. A timeout or forced watchdog kill is a failure; zero selection or a missing drain receipt cannot pass a positive journey. The planted negative subprocesses must receive those refusals. This coverage does not establish broadcast/watch recovery, transparent mailbox migration, dynamic supervisor reconfiguration, a control service, throughput or latency guarantees, or forced termination as successful cleanup. See [the signal recipe](signal_graceful_shutdown_supervision_tree_e2e.md) for the separate native and Lab signal paths.
