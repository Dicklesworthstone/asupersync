# Signal Delivery and Managed Supervisor Shutdown

The maintained public target is [`tests/supervision_regression.rs`](../tests/supervision_regression.rs), driven by [`scripts/test_obligation_cleanup_e2e.sh`](../scripts/test_obligation_cleanup_e2e.sh) in `--managed-supervision` mode. Its remote run on 2026-09-06 UTC passed both actual native SIGTERM subprocesses and rejected the planted zero-selection and early-exit controls. The separate deterministic signal-source tests also passed on three Lab seeds. The additional native registered-finalizer/replacement matrix described in [the channel recipe](channel_supervision_e2e.md) remains unexecuted; the expanded runner still needs a fresh complete result.

The native public path creates `signal::sigterm()`, awaits `Signal::recv()`, calls `ManagedSupervisorHandle::abort()`, and awaits `join()`. It uses the same compiled topology and `ManagedChildBinding` API as [the channel recipe](channel_supervision_e2e.md). The application connects signal delivery to controller cancellation explicitly.

On Unix, `public_managed_supervisor_owned_sigterm_shutdown` reexecutes its exact test in two owned subprocesses: one current-thread native runtime and one two-worker runtime with sharded state. Each subprocess runs four managed workers with bounded MPSC mailboxes. The parent requires this sequence:

1. The child delivers exact work payloads `700`, `701`, `702`, and `703`, then prints `ASUPERSYNC_SUPERVISOR_SIGTERM_READY` only after its real signal receive has returned `Pending`.
2. The parent checks the announced PID against its owned `Child`, confirms the process is alive, and sends actual SIGTERM to that PID.
3. The child observes `Signal::recv()` completion, requests controller cancellation, and waits until all four workers' task-owned asynchronous cleanups have returned `Pending`. The controller must not report completion at this point.
4. Only after `ASUPERSYNC_SUPERVISOR_SIGTERM_CLEANUP_PENDING` does the parent release cleanup through the child's stdin. One worker's cleanup depends on another's actual completion witness.
5. The child requires four starts, four joins, zero replacements, exact payloads, canonical task/region `Complete` events, empty mailbox waiters, no live tasks or leaked obligations, and successful runtime shutdown before printing `ASUPERSYNC_SUPERVISOR_SIGTERM_COMPLETE`.
6. The parent requires the drain receipt, one successfully selected child test, and successful process exit. Stderr remains visible. Actual zero-selection and early-exit negative subprocesses must be rejected by the same receipt checker.

The separate private `managed_supervisor_runtime_signal_source` unit test uses an owned `SignalSlot::record_delivery` and the real `Signal::recv` path under `LabRuntime`. That is model-delivered signal evidence; it does not send an OS signal or expose a public deterministic signal-injection API. The 18 public supervisor journeys repeated across three Lab seeds and two native backends exercise scheduled cancellation independently. Ordinary Lab cancellation is not signal-delivery evidence.

After the candidate runner, runtime, and tests are committed, run the complete lane from `main`:

```bash
cd /data/projects/asupersync
base=$(git rev-parse HEAD)
RCH_REQUIRE_REMOTE=1 bash scripts/test_obligation_cleanup_e2e.sh \
  --managed-supervision --base "$base" --no-overlay
```

The full native cancellation audit runs first, followed by focused supervisor/finalizer/region/state/native-budget and private signal-source units, then the full public `supervision_regression` target. Cargo uses `--locked` and explicit features `tls,test-internals`, with default features still enabled. Every stage requires remote execution, disables target reuse, and must join the selected base and overlay fingerprint. The parent public target is unfiltered; its owned child processes deliberately use exact test selection.

For uncommitted work, use the [explicit reserved-path overlay recipe](channel_supervision_e2e.md). `--no-overlay` never includes working-tree edits. `CHECKED_ADMISSION_BUILD_JOBS` defaults to `8`; `CHECKED_ADMISSION_CARGO_HOME` optionally forwards a worker-valid Cargo home. `MANAGED_SUPERVISION_ARTIFACT_DIR` selects a new evidence directory, and `RCH_TARGET_DIR` selects the target root.

Keep `native.log`, `units.log`, `supervision.log`, the source selection and stage receipts, `supervision-journeys.json` when produced, and `summary.json` (`asupersync.managed_supervision_runner.v1`). Diagnose the first failed stage and its exact source before interpreting later markers. A source admission receipt is not an independently verified worker content manifest.

The 45-second subprocess and 60-second native watchdogs bound test attempts. Forced termination by the test guard is failure cleanup, never a successful graceful drain. These tests do not establish arbitrary-depth supervisor trees, dynamic reconfiguration or control APIs, public Lab signal injection, SIGINT/SIGKILL equivalence, shutdown latency or throughput, synchronous callback preemption, or a production force-kill guarantee. Runtime region-finalizer budget enforcement is covered by separate focused tests; the public signal journey's cleanup belongs to its worker tasks.
