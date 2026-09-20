# Checked ownership for ordinary remote execution

`distributed::remote_owned::run_remote` is an additive path for executing one
named computation with real local child-region and checked lease ownership.
It reuses `RemoteCap`, `RemoteRuntime`, `spawn_remote`, `RemoteHandle::join` and
`RemoteHandle::close`. Existing spawn/handle signatures, fallbacks, V1-V3 wire
formats, and runtime defaults are unchanged. Callers of the old entry point do
not automatically acquire this new ownership contract.

## Execute and interpret the result

Supply a live task's `Cx` with an attached remote capability/runtime, an explicit
timer driver, destination/name/input, and `RemoteRunConfig`. The timeout starts
before child-region admission. Region constraints use the existing
`ChildRegionSpec` and cannot restore attenuated capabilities.

```rust,ignore
use asupersync::cx::ChildRegionSpec;
use asupersync::distributed::remote_owned::{run_remote, RemoteRunConfig};
use asupersync::remote::{ComputationName, NodeId, RemoteInput};
use std::time::Duration;

// cx belongs to a real task and already has its explicitly provisioned RemoteCap.
let report = run_remote(
    &cx,
    NodeId::new("worker"),
    ComputationName::new("encode-block"),
    RemoteInput::new(encoded_request),
    RemoteRunConfig {
        timeout: Duration::from_secs(30),
        child: ChildRegionSpec::inherit(),
    },
).await?;
if !report.is_success() {
    // Inspect trigger, task, close, and cancel_error without treating a remote
    // payload, an attempted cancellation, or a closed channel as success.
    return handle_remote_failure(report);
}
let reply = report.task.expect("is_success checked task result");
// Decode and independently validate the application-specific Success payload.
```

The example deliberately leaves route provisioning and application decoding to
the embedding application. `NativeRemoteRuntime` provides the existing V3 mTLS
implementation; deterministic/custom runtimes can use the same ownership path.
No addresses, certificate policy, keys, new protocol, discovery, or retry loop
are supplied by this module. Missing remote/runtime/timer authority refuses.
The legacy deterministic no-runtime fallback is not accepted by the new API.

The local proxy is a task in a freshly allocated child region. It registers a
checked `ObligationKind::Lease` through that admitted task's gateway BEFORE remote
registration or dispatch. Quota refusal never becomes untracked execution. The
proxy rechecks cancellation and deadline after the runtime's admission callback.
There are no fabricated arena IDs and no token handoffs across task owners.
The actual SpawnRequest carries the admitted proxy's origin region/task IDs.

## Cancellation is not terminal collection

A parent cancellation or invocation deadline cancels only the invocation child.
The proxy's cancel-aware join then uses `RemoteHandle::close` to request remote
cancellation and collect the existing runtime's terminal result uninterruptibly.
The checked lease stays owned until that result/failure is classified and the
RemoteHandle is destroyed. A successful, uncancelled remote Success can commit;
remote failures, cancellation, lost channels and transport errors abort. A lost
checked settlement is reported rather than converted to successful accounting.

`RemoteHandle::is_finished()` includes both buffered and consumed results. The
adapter does not use that boolean to infer whether a cancelled join consumed a
reply. It checks `try_join`, preserving a concurrently buffered exact result or a
genuine already-consumed Cancelled error before deciding whether to call close.
A late Success remains available as data but cannot commit a cancelled proxy.

Every obtained child region is closed and its retained subtree/finalizer outcome
is included in the report, including after spawn refusal. An ordinary returned
remote payload does not bypass local close. Cancellation/deadline is rechecked
after close, so a late close cannot turn a missed caller budget into success.
`Ok(report)` alone is not success. `is_success()` requires timely completion, a
remote Success, winning local checked commit, and successful child/finalizer
close. Remote business failures, local task panics, and close errors remain
separate. Debug of the report/reply does not print application bytes or remote
diagnostic payloads.

Continue polling the runner to receive its actual close report. Dropping it
requests child close through the existing region owner; the proxy and checked
lease remain owned by that region while remote terminal collection proceeds.
A forcibly dropped proxy requests best-effort remote cancellation and aborts its
local checked token. No path fabricates a synchronous drain receipt from Drop.
Unrelated invocations and the shared NativeRemoteRuntime are not globally closed.

The configured timeout initiates cancellation, not a universal shutdown bound.
Scheduler admission must progress; a custom RemoteRuntime that never sends a
terminal, a stuck callback, or runtime cleanup escalation can prevent graceful
drain. A reported transport failure is still ambiguous about remote effects. A
local child close/checked abort is not a certificate that an arbitrary remote
process stopped or rolled back. The contract of the configured remote runtime
and its server determines the meaning of its terminal result. In particular,
legacy callback panic/registration rollback behavior is not repaired here.

## Validation targets

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib distributed::remote_owned::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls,test-internals --test remote_owned_native -- --nocapture
```

Focused tests use actual checked LabRuntime reservations and mailbox counters,
plus whole public-API execution on the native runtime. They cover zero quotas,
missing gateways, dispatch refusal/panic, pending cancellation, lost senders,
buffered replies, exact consumed errors, forced proxy drop and redacted output.

The native target uses the real V3 mTLS service and NativeRemoteRuntime. Before
cancellation it witnesses the remote handler returning Pending and the origin
proxy's actual reserved Lease through native diagnostics. The remote handler
withholds cleanup after cancellation, and the test requires the local lease and
invocation to remain pending until that cleanup is released. A second invocation
on the same remote runtime must still complete. Separate cases cover successful
reply, caller cancellation, invocation deadline, and dropping the runner on both
current-thread and two-worker runtimes. Diagnostics stay on their runtime owner
thread even when optional features make them non-Send. Global harness teardown
runs only after the per-invocation ownership assertions.

These are authored tests until executed. They are not compiler, native pass,
performance, cross-process failure, or arbitrary-transport quiescence evidence.

## Shared per-peer admission

`RemoteExecutor` adds opt-in aggregate and per-logical-peer admission around the
same runner. Configure `RemoteAdmissionLimits` (peer count, total invocations,
total original input bytes) and a fixed set of `RemotePeerLimits` (per-peer
invocations, aggregate input bytes, and per-request input bytes). No limits are
implicitly unbounded. Zero invocation capacity disables that admission; zero
byte capacity can still admit an empty request when an invocation slot exists.
Unknown or duplicate peers refuse instead of adding or replacing policy.

`executor.run(&cx, node, computation, input, config).await` uses the caller's
existing remote capability and the same `RemoteRunReport`. Creating its future
does not reserve anything. On first poll, all counters are checked together,
without wrapping, before child-region admission or remote dispatch. Saturation
returns a typed `RemoteAdmissionError`; there is no request queue, auto-retry,
priority scheduling, or hidden wait. `usage()` and `peer_usage()` expose current
logical charges, and `close_admission()` permanently prevents new admissions
across every clone without cancelling existing calls or closing their transport.

An admitted call owns one reference-counted charge shared by the calling scope
and the actual region-owned proxy. The scope retains its share through the
child's close/finalizer receipt. The proxy's share is destroyed AFTER its future,
remote handle and checked lease. Whichever owner finishes last releases the
charge. In particular, dropping or timing out a caller cannot recycle its peer
slot while its still-owned proxy waits for remote terminal collection. Cancellation
and terminal collection do not acquire a second credit, so a saturated data plane
cannot block those operations at this admission layer. Backend control-channel
and transport liveness requirements remain unchanged.

These are logical outbound quotas, not exact process memory or inbound peer
admission. Count original input lengths, not caller copies, serialization or TLS
expansion, responses, runtime metadata or backend caches; retain the transport's
own independent limits. Different labels for the same physical host have separate
quotas. Operators must provision meaningful labels. Separately constructed
executors have separate budgets, and direct `run_remote` / `spawn_remote` calls
bypass this opt-in layer. No new address, certificate, membership or route authority
is acquired. The generic per-peer transport/priority/async-admission work remains
broader than this outbound implementation.

Additional focused tests cover exact/zero/overflow limits, fixed configuration,
thread contention, reentrant callbacks, scope/proxy drop ordering, setup refusal,
and cancelled or dropped callers awaiting a delayed terminal. The four added
native V3 scenarios run the same actual mTLS journey through `RemoteExecutor`,
retain request-byte charges through deliberately withheld remote cleanup, reject
same-peer saturation without dispatch, and allow a second logical destination to
progress on the same listener. That alias is not a separate physical host or PKI
identity. All earlier unbounded-runner scenarios remain selected as well.
