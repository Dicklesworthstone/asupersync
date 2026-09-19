# Hedged symbol distribution

`SymbolDistributor::distribute` retains its default all-eligible-replica fanout.
Opt into quorum-first behavior with `DistributionConfig::hedge_enabled = true`.
No new transport or wire format is used; the existing `RemoteSymbolTransport`
and authenticated symbol service work unchanged.

Hedged calls initially admit the required acknowledgement count, bounded by
`max_concurrent`. A failed attempt is replaced on the next poll without waiting
for `hedge_delay`. When enough attempts remain pending but quorum is not yet
established, one additional eligible replica is admitted after the delay, then
one per subsequent interval. A late timer wake does not cause a catch-up burst.
A zero delay admits at most one speculative replica per poll. Existing attempts
are polled before a due hedge, avoiding a backup when the quorum is already ready.

All normal and speculative attempts share the same concurrency ceiling. Capacity
remains occupied until its send future and acknowledgement timer are destroyed.
Each attempt gets a fresh `ack_timeout` on admission, not on initial planning.
At full capacity the driver waits for actual completion, timeout, or cancellation;
it does not spin on an expired hedge timer. A pending transport still requires
an explicit context timer driver; ready-only transports remain supported without
one. Neither delay nor timeout can preempt synchronous provider work inside a poll.

The quorum denominator is the unique authorized, nonempty replica plan, including
backups not yet contacted. It never shrinks after a failure. A verified quorum
ends the operation immediately; mathematical impossibility also stops further
admission. `Local` needs no remote sends; `All` has no spare votes and an individual
failure makes success impossible. Non-local empty plans never establish quorum.

Reports retain assignment order. Already observed errors and acknowledgements
are preserved. Unresolved attempts and unstarted backups after success appear as
`Cancelled` failures with distinct messages; this is local loser retirement, not
a claim that the parent context was cancelled. Quorum-impossible skips instead
use `QuorumNotReached`. `symbols_distributed` and symbol metrics count only first
transport polls, not queued plans, speculative reservations, or skipped backups.

Every owned send and timer is retired before output. External future drop also
retires them through ordinary Rust ownership. This does NOT undo transmitted
bytes, delete a stored batch, certify remote quiescence, or prove durable storage.
Storage acknowledgement still depends on the configured authenticated transport.
Use immutable object identities and retain the actual successful replica set for
later recovery; a cancelled loser may have stored a batch despite a missing reply.

Focused validation (the runner and toolchain must be available):

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib distributed::distribution::
```
