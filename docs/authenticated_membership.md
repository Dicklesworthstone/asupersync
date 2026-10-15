# Authenticated membership and incarnation-fenced leases

The opt-in `distributed::membership::authority` module joins explicit membership
authority with the existing `Lease` lifecycle. It leaves `Swim`, `MembershipView`,
`MembershipLeaseReactor`, `MembershipLeaseManager`, and their existing contracts
unchanged. Raw UDP membership observations are not authorization decisions.

## Authority, sequence, and rejoin

Construct a `MembershipLeaseController` with one provisioned authority `NodeId`,
an authority epoch, an independent membership-authentication key, a fixed vector
of `MembershipFloor` entries, and `MembershipControllerLimits`. A floor binds each
allowed node to its minimum subject incarnation and last accepted sequence.
Even a provisioned node cannot receive a lease until a fresh authenticated Alive
statement advances that floor. These labels never supply addresses, certificates,
remote spawn capabilities, or runtime obligation IDs.

A `MembershipUpdate` wraps an existing `MembershipEvent` and a per-member sequence.
The authority deliberately approves a decision and calls `authenticated_bytes`.
A failure detector can supply observations, but no helper automatically signs or
promotes them. The controller checks the existing domain-framed HMAC before parsing
labels or changing state. Encoding is fixed-version and at most 581 bytes; label
lengths, UTF-8, tags, exact framing, authority identity and epoch are checked.

Sequence numbers strictly advance across incarnations within the authority epoch.
An exact duplicate of the latest statement is idempotent; different contents at
the same sequence are a conflict. Older sequence or incarnation values are refused.
A newer sequence cannot resurrect a Dead/Left incarnation. A higher incarnation
retires every old lease and can receive new grants only when its accepted state is
Alive. Delayed death from an older incarnation cannot revoke a rejoined member.
Suspicion pauses new grants but retains existing leases, including their ability
to renew before expiry; an authorized same-incarnation refutation can resume grants.

## Lease and cleanup ownership

`try_grant` accepts a caller-created `Lease` only for the exact Alive incarnation.
It returns a `MembershipLeaseId` binding member, incarnation and generation-bearing
`ObligationId`. Every refusal returns the unconsumed Lease. The caller remains
responsible for resolving its real runtime obligation. One obligation identity
cannot be reused by a later incarnation or another member, even after release or
revocation acknowledgement. All accepted IDs remain remembered within the explicit
lifetime `max_lease_ids` ceiling; exhaustion refuses instead of evicting fences.
A new runtime generation of the same arena slot is a different obligation identity.

`renew`, `release`, and `expire` reuse the existing Lease state machine. Deadlines
win against renewal at expiry; backward owner clocks are rejected. `release`
returns the terminal Lease so the owner can commit its RuntimeState obligation.
`next_expiry` exposes the earliest deadline for an owner-scheduled timer; the
controller itself spawns no timer, worker, or background task.

Revoked/expired obligations enter a retained `revocations()` outbox in deterministic
order. Inspecting it, receiving another event, or admitting a new incarnation does
not consume cleanup instructions. Abort the actual obligation and perform required
compensation, then call `acknowledge_revocation` with its exact token. This method
records the caller's acknowledgement; it cannot verify that external cleanup ran.
The outbox is bounded by the lifetime admitted-ID limit, not an unbounded event log.
Do not drop a controller with outstanding leases or unprocessed cleanup. No API
here certifies remote quiescence or stops already-running remote code.

## Existing mTLS service integration

Use `distributed::membership::service::register_membership_service` to install
`asupersync.distributed.membership-authority.v1` in the existing computation
registry. Keep the controller in an application-owned `Arc<parking_lot::Mutex<_>>`.
Configure a V1 `RemotePeerAdmissionPolicy` from the complete schema registry and
use `grant_tls_peer` for the provisioned authority, then serve with the existing
native mTLS listener. Registration does not grant access. The handler independently
checks that the admitted peer equals the controller authority, so accidentally
granting an observer this computation cannot authorize membership changes.

`submit_membership_update` uses a caller-provisioned `RemoteComputationClient`,
V1 hello, owning `Cx`, and signed bytes. The client's existing finite deadlines
and pre-delivery retry rules remain in force. No new transport envelope/version,
resolver, routing update, queue, retry policy or detached task is introduced.
The service refuses a busy controller instead of blocking an executor worker.
Its exact-statement echo acknowledges admission, not persistence, current liveness,
or completed obligation cleanup. Cancellation/connection loss can follow a state
transition. An exact latest retry is idempotent; an older replay remains stale.
Do not use retained V2/V3 service receipts across controller replacement.

Authority key holders can assert membership; authentication does not prove they
made a correct failure-detection decision. Before restart, independently restore
trusted epochs/floors and ensure old obligations are drained. A previously terminal
member needs a minimum incarnation STRICTLY ABOVE the retired incarnation (or must
remain unprovisioned if it reached u64::MAX); sequence alone does not encode terminal
state. Do not recreate a controller with stale bootstrap floors. This module does not
persist them, elect an authority, perform automatic discovery-to-route updates, or
connect revocations to arbitrary application runtimes. Those remain separate
integration work. Memory bounds describe retained counts and bounded labels, not
exact allocator overhead, caller copies, or total process RSS.

## Validation

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib distributed::membership::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --features tls,test-internals --test membership_authority_native -- --nocapture
```

The unit tests cover authority/floor admission, malformed authenticated statements,
terminal/rejoin fencing, lifecycle ownership and retained cleanup. Native scenarios
use actual SWIM events approved by the test authority and the real TCP/mTLS service,
with current-thread/multithread clients. Wrong-key and wrongly authorized-peer
cases must reach application refusal, not merely fail TCP/TLS. A lock-holder witness
and failure-only watchdog cover busy-owner refusal. Lease IDs in native tests are
local fixtures: these do not establish automatic RuntimeState obligation discharge.
Tests are authored, not execution evidence until the above commands run.
