# Runtime-owned membership leases

`distributed::membership::owned::OwnedMembershipController` is an opt-in bridge
from authenticated membership decisions to checked runtime lease obligations.
The existing metadata controller, SWIM view, legacy lease manager, and their
service registration remain unchanged.

Construct the controller with the same independently provisioned authority,
epoch, member floors and limits as `MembershipLeaseController`, plus an explicit
`TimerDriverHandle`. This does not acquire routes, TLS credentials, runtime task
identity or an obligation. Signed authority decisions must still pass both the
configured peer identity check and the independent membership MAC.

## Own the lease in the task that admitted it

`try_grant(&cx, &node, incarnation, duration)` first reserves bounded local
admission, then registers a checked `ObligationKind::Lease` through that task's
runtime gateway. The second policy check closes concurrent revocation/closure
races during runtime admission. A missing gateway refuses rather than returning
an untracked guard. Runtime and membership quotas are independent; unsuccessful
runtime admission does not consume the lifetime successful-grant allowance.

The returned `OwnedMembershipLease` is non-cloneable. `release(self)` requires the
real checked commit to win. Drop posts an explicit abort. Dead/Left, replacement
by a newer incarnation, expiry and controller closure abort the affected tokens.
The runtime's existing mailbox projects these operations into its obligation
arena and trace; publication of a checked terminal is not immediate application
of every arena/diagnostic update. No arena IDs are derived from tickets.

Keep the guard within its admitting task. Merely moving it to another task is
NOT a checked runtime handoff. Completing the holder while another task retains
its guard can still be reported as a leak by the runtime. There is no automatic
holder transfer, saga execution, remote cancellation, or compensation in this API.
Normal Rust ownership cannot make a deliberately forgotten owner safe.

The lifetime `max_lease_ids` bound includes successful grants plus simultaneous
pending registrations, not just currently active guards. Controller-local IDs
never wrap or reuse, including rejected attempts. Guards retain their own runtime
token; cloning a controller does not duplicate obligations. The explicitly
supplied controller timer is the clock for all its guards.

## Timers and cancellation

Drive `controller.run(&cx).await` in a task owned by the application, or call
`expire()` at owner-controlled deadlines. The library never spawns a detached
expiry loop. Only one driver can run; dropping or cancelling that driver closes
admission and aborts outstanding local leases. `close()` also wakes an idle
driver. With no driver and no explicit `expire()` calls, time passing alone does
not publish expiry; renew/release still reject their own overdue guards.

The driver waits on actual timer readiness, its owning context's cancellation,
and a predicate-aware notification when the earliest deadline changes. Adding an
earlier deadline, shortening/lengthening one through renewal, or closing an
empty controller cannot fall through a check-then-register lost-wakeup window.
`ended().await` uses the same predicate-aware primitive. Deadline ties expire.
Suspicion pauses new grants but permits renewal of existing unexpired ones.

Checked terminals are chosen BEFORE a terminal local status can be observed.
This prevents a holder awakened by revocation from completing with an unresolved
reservation. All selected terminal posts precede notification; gateway and waiter
callbacks run outside controller locks. Notification fanout attempts the remaining
callbacks even when one panics, then resumes the first panic. It does not suppress
ordinary application panics or prove termination of blocking callbacks.

## Existing authenticated transport

Use `service::register_owned_membership_service(&mut registry, controller.clone())`
instead of `register_membership_service` in a registry. Both use the existing V1
computation name and request/response schema. Provision the usual certificate-bound
peer admission policy; the existing `submit_membership_update` client is unchanged.
The handler refuses a contended controller rather than blocking on its policy
lock. A successful echo means the exact decision was accepted and local terminal
posts issued, not that remote work stopped, compensation ran, or all runtime
projection/drain work completed. The handler does not start the expiry driver.

Native test `membership_owned_native` waits until a holder's `ended()` future has
actually returned Pending AND diagnostics show its real reserved Lease obligation
before delivering a signed Dead statement through the mTLS service. The owner must
wake with `Revoked`, reject clean release, and finish without parent cancellation
or a leaked obligation. Separate tests cover real timer expiry and external driver
drop. Tests cover current-thread and multi-thread native runtimes where specified.
They are authored until executed, not native success or performance receipts.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib distributed::membership::owned::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls,test-internals --test membership_owned_native -- --nocapture
```

This does not persist authority freshness or discover the newest incarnation after
restart. Restore independently trusted epoch/floors as for the metadata controller.
A local lease invalidation is not a remote-work quiescence certificate.
