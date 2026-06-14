# ASUP-E601 - Database Pool Acquire Timeout

## Symptom

`[ASUP-E601]` means an asynchronous database connection-pool acquire waited in
the pool's FIFO waiter queue for the full
[`DbPoolConfig::connection_timeout`](../../src/database/pool.rs) budget without a
connection being released, and returned `DbPoolError::AcquireTimeout`.

It is distinct from the generic `DbPoolError::Timeout`, which also covers
cancellation and connection-creation timeouts. `AcquireTimeout` specifically
means "you reached your turn budget while waiting for capacity", so it should be
treated as load backpressure, not a transient connect error.

## Probable Causes

- The pool is saturated: all `max_size` connections are checked out and none
  were released before the acquire deadline.
- Connections are held too long (slow queries, or a leaked
  `AsyncPooledConnection` guard that never returns to the pool), so FIFO waiters
  never reach the head of the queue within budget.
- `DbPoolConfig::max_size` or `connection_timeout` is too low for the offered
  concurrency.

## Fix

- Raise `DbPoolConfig::max_size`, or shorten connection hold time, so the FIFO
  waiter queue drains within the budget.
- Increase `DbPoolConfig::connection_timeout` if the workload legitimately needs
  a longer acquire budget.
- Treat `AcquireTimeout` as backpressure: shed or retry the request at a higher
  layer rather than retrying the acquire immediately (the waiter already used
  its full budget, so an immediate retry just re-queues behind the same load).

## Example

A pool with `max_size = 1` hands its only connection to a long-running
transaction. A second `pool.get(cx).await` enters the FIFO waiter queue and,
because the connection is never released, exhausts its `connection_timeout`
budget. The acquire returns `Err(DbPoolError::AcquireTimeout)` whose display
starts with `[ASUP-E601]`.

## Related

- `ASUP-E204`
- `ASUP-E103`
