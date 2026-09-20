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
length, and all shared limits before user code is invoked. Saturation refuses
without queues, implicit retries, or priority scheduling. Unknown peers are
refused even if the surrounding service accidentally grants them the computation.
An empty request may use zero byte allowance; zero invocation capacity denies it.
No runtime spawn/region authority means refusal, not inline fallback.

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
Logical test identities share a fixture certificate; this is not a production
PKI-separation claim. Tests are authored until these commands execute:

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib distributed::remote_owned::admission::service::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls,test-internals --test remote_service_admission_native -- --nocapture
```
