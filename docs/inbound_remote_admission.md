# Inbound remote execution admission

`distributed::remote_owned::RemoteServiceAdmission` adds peer-specific execution
limits to handlers in the existing `RemoteComputationRegistry`. It complements
the outbound `RemoteExecutor`; its counters are independent of caller-side gates.
Neither API silently changes existing `spawn_remote`, registry, or listener users.

Construct it with `RemoteAdmissionLimits` and a bounded iterable of
`(NodeId, RemotePeerLimits)`. Register each protected handler with
`admission.register::<InputSchema, OutputSchema, _, _>(&mut registry, name,
ChildRegionSpec::inherit(), handler)`. The schemas, name, and raw invocation type
are unchanged. Build the usual certificate-bound peer policy from that registry
and run the existing mTLS computation service. The type is also usable through
explicit local registry dispatch; that route relies on its caller's admitted
session and is not proof of network authentication.

All registrations using the same admission object, and every clone of that
object or registry, share aggregate and per-logical-peer invocation/input-byte
limits. A request origin string cannot switch accounts: only the invocation's
admitted session peer selects its quota. Explicit TLS grants remain necessary;
quotas do not grant execution authority or discover network destinations. Aliases
for the same physical principal are independently provisioned logical peers.

The first dispatch poll checks cancellation, configured peer, original payload
length, and all shared limits before user code is invoked. Ordinary `register`
refuses saturation without queues, implicit retries, or priority scheduling.
Unknown peers are refused even if the surrounding service accidentally grants
them the computation. An empty request may use zero byte allowance; zero invocation
capacity denies it. No runtime spawn/region authority means refusal, not fallback.

## Ownership and cancellation

An admitted request transfers its one charge into a runtime-owned coordinator.
The coordinator opens a child region, spawns the user handler there, and awaits
both handler completion and subtree/finalizer close. The whole coordinator future
is destroyed before its charge is released. Body errors and panics do not skip
close; a returned value is not enough for Success when cancellation or cleanup
failed. Factory/destructor/subtree panics retain Panicked classification with
payload-free adapter messages. Application-returned outcomes/errors otherwise
retain their existing form.

The dispatch waiter observes its Cx cancellation explicitly. Dropping that waiter
also requests cancellation of the coordinator. The coordinator keeps the request
charged while remaining work drains, even when the network result receiver no
longer exists. No cleanup task is detached from the runtime. User code must keep
owned work under the supplied child Cx; captured external contexts can create
work outside this ownership boundary. Deliberate forgetting, forced teardown,
and indefinitely blocking code do not acquire a fabricated drain guarantee.

`usage()` and `peer_usage()` expose current logical charges. `close_admission()`
permanently refuses new executions without cancelling already admitted work.
Existing V3 cancellation, renewal and terminal collection do not acquire a new
execution slot. The service's separate connection/frame/control limits still
apply. V2/V3 duplicate terminal replay is not a new execution; closing admission
does not erase already retained replies. A quota refusal is an ordinary Failed
outcome and may itself be retained by the existing idempotency policy. Retrying
with the same key does not automatically retry execution after capacity changes.

## Explicit bounded backpressure and reservations

`RemoteServiceAdmission::new_queued(limits, peers, queue_limits)` opts into waiting.
`RemoteQueueLimits` independently bounds total/per-peer waiting count and declared
original input bytes. Zero queue capacity denies waiting but does not prevent
immediate admission. Use `register_waiting(..., child_spec, wait_timeout, handler)`
for selected computations. Ordinary `register` still refuses saturation. Both
registration modes and all clones share the SAME active counters and queue.

The wait queue starts no extra coordinator and does not invoke or decode through
the user handler. Original request input stays with its dispatch future and is
charged while waiting. On admission it moves to the active accounting domain,
retained through the existing handler/subtree cleanup. These are two independent
bounded domains, not double charging or an exact bound on frame copies/RSS.

Waiters use the context's explicit timer and cancellation observer. Cancellation,
disconnect/drop, closure and deadline remove a waiter without user execution.
Closing wakes pending waiters; their waiting charges remain visible until the
owning futures poll or drop. A cancelled active operation does not release quota
until its complete coordinator is destroyed, so its queued successor cannot run
merely because a cancellation request was sent. Existing V3 control operations
and retained terminal replay do not enter this queue. Admission timeouts/refusals
are Failed outcomes subject to existing idempotency retention, not automatic retry.

Order is FIFO within a logical peer and oldest currently feasible peer head
across peers. A peer blocked by its own active quota does not block another peer.
A byte-heavy head blocks later requests for its own peer, but another peer may
progress. No priority/control-authority promotion or starvation bound is promised.
Queue selection/removal uses bounded scans; throughput has not been benchmarked.
On an enabled queue, immediate admissions cannot overtake an eligible waiter or
an earlier same-peer waiter. Never-polled futures allocate no queue ticket.

Outbound `RemoteExecutor::new_queued` uses the same mechanism. Its `reserve(&cx,
&node, input_len, wait_timeout)` returns a non-cloneable `RemoteReservation` for
that exact node and length. Hold it to retain active quota, drop it to release,
or consume `reservation.run(&cx, computation, input, run_config)`. A size mismatch
never dispatches. Execution uses the existing scope/proxy shares of ONE charge;
external caller drop does not recycle it while the proxy is draining. Issued
reservations remain valid after admission closes, as already-admitted work does.
`run_waiting` combines reservation and execution. Waiting and execution intervals
are separately explicit; no new interval extends the inbound service lease.
`queue_usage()` / `peer_queue_usage()` report waiting charges separately from
active `usage()`. Direct unwrapped APIs still bypass this opt-in budget.

## Limits and validation

This is execution admission AFTER TLS/framing/idempotency dispatch, not protection
against all unauthenticated resource use. Keep the listener's connection, frame,
handshake, first-frame and retained-record bounds. Charges exclude prior input
copies, serialization expansion, outputs, TLS buffers, and application memory.
There is no output-byte reservation, bounded priority queue, or global cross-
process fairness claim. Existing unwrapped registry handlers bypass this gate.

The focused tests drive real local runtime tasks through public registry dispatch.
The native tests use actual V3 mTLS sessions without the outbound executor. They
witness a parked handler before renewal/cancellation, withhold its cleanup, and
require same-peer refusal, another peer's progress, and no slot reuse until drain.
Other cases cover independent byte/peer refusals and retained-idempotency replay.
The queue tests additionally witness actual queued count/bytes before cancellation,
disconnect, deadline or active-handler retirement; queued input must not execute
early, overflow must refuse, and another authenticated peer must progress.
Logical test identities share a fixture certificate; this is not a production
PKI-separation claim. Tests are authored until these commands execute:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib distributed::remote_owned::admission::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls,test-internals --test remote_service_admission_native -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls,test-internals --test remote_queue_native -- --nocapture
```
