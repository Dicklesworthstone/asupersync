# Signal boundary inventory and terminal gate

<!-- BEGIN SIGNAL BOUNDARY INVENTORY -->

This is the operator-readable companion to
`artifacts/signal_boundary_inventory_v1.json`. It freezes the claim-time
`CAP-SIGNALS` baseline for `asupersync-3u3tej.1.1` at revision
`1d8c77755daac957c52438d09d1dfca9b9c6cfc4`.

The gate outcome is terminal `DEFER`. `signal-hook` remains in place, no
replacement child is authorized, and no source or dependency change is
approved by this inventory. The result is not an endorsement of the current
defects: all thirteen findings are routed to incumbent hardening, registry
maintenance, unsafe-ledger maintenance, or missing platform proof.

## Why the gate is DEFER

The canonical marginal ledger contains 39 `signal-hook` cells: thirteen
profiles across Linux, macOS, and Windows. Removing the edge would save one to
three package versions per cell. The largest Linux/macOS set is
`signal-hook@0.4.4` plus `signal-hook-registry@1.4.8`; Windows also includes
`errno@0.3.14`. Every cell classifies marginal native code as
`declared-inactive`, and the upstream build script is a no-op because
`extended-siginfo-raw` is not enabled. There is no active C compilation and no
proc macro on this edge.

That small graph benefit is outweighed by the boundary a replacement would
inherit: async-signal-safe registration, previous-handler chaining,
concurrent unregister behavior, pending delivery, self-pipe wakeup, Unix ABI
details, Windows CRT limitations, Win32 event handles, process-global
lifetime, thread masks, fork behavior, PID authority, and cross-platform
permission/liveness classification. The incumbent registry owns a mature,
unsafe, process-global implementation of much of that surface.

Current defects are material, including one critical PID-reuse issue, but none
requires replacing `signal-hook`. The safe course is to harden the incumbent
integration and first build the missing real-platform baselines.

## Receive semantics

`asupersync::signal::SignalKind` is a non-exhaustive ten-kind enum. Unix maps
Interrupt, Terminate, Hangup, Quit, User1, User2, Child, WindowChange, Pipe,
and Alarm. Windows maps Interrupt, Terminate, and Quit to the CRT
`SIGINT`, `SIGTERM`, and `SIGBREAK` surface; the remaining kinds are
unsupported.

The first Unix `Signal` construction initializes a process-global
`SignalDispatcher`. It eagerly registers all ten signal kinds with
`signal_hook::iterator::Signals`, starts a detached
`asupersync-signal-dispatch` thread, and retains the iterator handle in a
`OnceLock` for the process lifetime. This means a listener for one kind also
changes the OS disposition of unrelated kinds.

The iterator records pending kinds. Standard OS signals and the upstream
pending slots may coalesce repeated same-kind arrivals. Cross-kind iteration
order is arbitrary. Asupersync increments a per-kind counter for each
iterator emission and independently fans those recorded emissions to every
stream for that kind. The counters preserve multiple upstream emissions; they
cannot recover raw arrivals already coalesced by the OS or incumbent.

Accordingly, the existing `Signal::recv` statement that no delivered signal
notification is lost must be read only at the recorded-dispatcher boundary.
It does not promise one receive per raw OS arrival or a total order across
kinds.

The incumbent chains a prior handler when it is neither default nor ignore.
Unregistering the final action does not restore that prior/default OS
disposition. Registration must happen before arrivals and before competing
handler changes. Signal handlers run on whichever thread the OS interrupts
and must remain async-signal-safe.

`SignalMask` is a separate Unix-only, thread-local contract built on `nix`.
It restores the exact previous mask. A signal blocked in every thread cannot
be delivered. Masking is unsupported on the Windows path.

## Windows receive boundary

The Windows dispatcher installs low-level CRT handlers for the three mapped
kinds and wakes Win32 events consumed by a wait loop. The implementation owns
unsafe `CreateEventW`, `SetEvent`, `WaitForMultipleObjects`, and
`CloseHandle` calls plus `Send`/`Sync` assertions for event handles.

This is not complete Windows console-control parity. CRT registration can race
with delivery or re-registration, `SIGTERM` is not a general Windows
termination channel, and not every console Ctrl-C or Ctrl-Break journey has
the same CRT mapping. The existing Windows completeness test checks source
tokens; it is not a runtime console-control receipt.

## Shutdown, reload, and listener lifetime

`ShutdownController::listen_for_signals` starts one detached blocking thread
per watched kind and each listener exits after its first observed signal. The
method is idempotent per controller but returns `()` and silently discards a
registration failure. Dropping a controller does not dismantle the global
dispatcher.

`ReloadController` similarly starts a detached SIGHUP listener. Its weak
controller state is checked only after a signal wakes the stream, so dropping
an idle controller can leave that thread blocked until a later signal.

`src/cli/signal.rs` is a second public semantic surface: portable signal
counts, cancellation, and escalation thresholds. It does not install an OS
handler. It must not be mistaken for the native receive boundary.

## Daemon and process-control semantics

`atpd` bypasses the Asupersync signal facade. Unix creates a separate
`Signals` iterator for INT, TERM, and HUP. Windows registers atomic flags for
INT, TERM, and BREAK and polls them every 100 ms. Repeated flag arrivals can
collapse, and the polling branch imposes reload-before-interrupt-before-
terminate priority rather than preserving arrival order.

Unix `atpd stop` reads a PID file, sends TERM with raw `kill`, polls
`kill(pid, 0)`, and escalates to KILL after ten seconds. Reload sends HUP.
Neither path fences the PID with process identity before sending. A stale PID
file plus PID reuse can therefore signal an unrelated process. Status treats
`EPERM` as evidence that the process exists, while an inner stop poll treats
any nonzero existence probe as stopped. That permission inconsistency is also
routed.

`src/atp/daemon_control.rs` uses `sysinfo` for process state and Unix
`Process::kill_with` for TERM/KILL. It checks executable identity before
signaling, which is safer than the `atpd` path, but basename matching is weak
and `kill_with` collapses unsupported, missing, and failed states into
`Option<bool>`. Windows uses `taskkill.exe`; reload is unsupported.

`asupersync::process::Child` is the owned-child surface. Unix can signal the
child PID or a configured process group, and cancellation escalates TERM to
KILL before reaping. Windows `Child::kill` is `TerminateProcess` behavior, not
a graceful console signal. These raw-kill, sysinfo, taskkill, and child-handle
paths do not currently share one error or escalation contract.

## Platform and proof baseline

Linux has source coverage, inline injection tests, modeled controller tests,
and one real Unix child journey that sends SIGTERM and observes signal exit.
That proves a send path, not receive cardinality, ordering, registration
lifetime, daemon shutdown, or cross-platform parity.

macOS and supported BSD use the generic Unix source path but have no fresh
runtime receipt. Windows has static source-token assertions but no retained
real console-control delivery/teardown receipt. No retained test covers
fork-after-registration or child reinitialization.

The dependency capability registry plans:

- `signal_graceful_shutdown`
- `signal_repeated_escalation`
- `signal_permission_pid_reuse`

None is implemented by
`scripts/run_dependency_sovereignty_e2e.sh`. The registry's current
`signal_shutdown` command therefore does not name an executable canonical
scenario. Missing evidence remains a blocker, never parity.

## Routed gaps

| Gap | Finding | Route |
| --- | --- | --- |
| `SIG-A1-GAP-01` | receive documentation hides upstream/OS coalescing | signal facade hardening |
| `SIG-A1-GAP-02` | the first listener eagerly registers unrelated kinds | registration lifecycle hardening |
| `SIG-A1-GAP-03` | global/controller listeners are not fully joined or unregistered | structured shutdown hardening |
| `SIG-A1-GAP-04` | Windows CRT races and console semantics lack runtime proof | Windows platform proof |
| `SIG-A1-GAP-05` | stale `atpd` PID files can target unrelated processes | atpd process-authority hardening |
| `SIG-A1-GAP-06` | raw kill, sysinfo, taskkill, and Child errors diverge | process-control contract |
| `SIG-A1-GAP-07` | macOS, BSD, and Windows runtime receipts are absent | cross-platform E2E |
| `SIG-A1-GAP-08` | modeled/injected tests are described as real signal E2E | signal test correction |
| `SIG-A1-GAP-09` | canonical dependency-sovereignty scenarios are missing | CAP-SIGNALS E2E |
| `SIG-A1-GAP-10` | fork behavior is untested and unclaimed | Unix platform proof |
| `SIG-A1-GAP-11` | registry source owners omit major signal/process surfaces | registry maintenance |
| `SIG-A1-GAP-12` | unsafe locators drifted and two files use broad allows | unsafe-ledger maintenance |
| `SIG-A1-GAP-13` | atpd installs a second signal-hook receive model | atpd/facade consolidation |

## Reconsideration gate

`DEFER` may change only through a new owner-reviewed gate with one of these
evidence-backed triggers:

1. a supported-platform production defect is attributable to the incumbent
   and cannot be fixed upstream or while retaining it;
2. an applicable security advisory or maintenance-abandonment record changes
   incumbent risk;
3. a fresh canonical ledger shows an explicit graph or native-code budget
   violation;
4. Linux, macOS, supported-BSD, and Windows runtime baselines cover delivery,
   coalescing, ordering, repetition, handler lifetime, masks, fork, process
   permissions, stale PIDs, cancellation, and teardown, and an owner accepts
   that exact contract;
5. an independent unsafe review proves a narrower design whose process-global
   and ABI burden is no greater than the incumbent boundary.

Until then, `implementation_children_authorized` is false. This terminal
`DEFER` prevents implementation and dependency cutover while allowing the
thirteen incumbent-hardening and proof gaps to proceed under their own
ownership.

## Validation and no-claim boundary

Run the focused contract through remote compilation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path artifacts/signal_boundary_inventory_v1.json \
  --overlay-path docs/signal_boundary_inventory.md \
  --overlay-path tests/signal_boundary_inventory_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_signal_boundary_inventory" \
  cargo test -p asupersync \
  --test signal_boundary_inventory_contract -- --nocapture
```

No local Cargo fallback is approved. This inventory does not prove release
readiness, runtime performance, raw signal cardinality, total order, fork
safety, PID identity safety, or macOS/BSD/Windows runtime parity. This
inventory does not authorize deletion, dependency removal, replacement
implementation, or cutover.

<!-- END SIGNAL BOUNDARY INVENTORY -->
