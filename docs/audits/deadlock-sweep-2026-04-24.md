# Deadlock Sweep 2026-04-24

Bead: `asupersync-drggpw`

Scope:
- `src/channel/mpsc.rs`
- `src/channel/fault.rs`
- `src/sync/once_cell.rs`
- `src/sync/pool.rs`
- `src/sync/rwlock.rs`
- `src/sync/semaphore.rs`
- `src/combinator/rate_limit.rs`
- `src/combinator/bulkhead.rs`

Method:
- Queried `audit_index.jsonl` first to avoid duplicate blind re-audits.
- Grepped for await-holding-lock patterns and lock-order hotspots in `channel/`, `sync/`, `obligation/`, and `combinator/`.
- Verified concrete control flow in the matched hotspots instead of treating grep hits as findings.

Findings:
- No concrete await-holding-lock deadlock was confirmed in the audited paths.
- No lock-order inversion against the documented `E > D > B > A > C` ordering was confirmed in the audited paths.
- No follow-up bead was filed because no candidate survived code-path verification.

Verified hotspots:
- `src/channel/mpsc.rs`
  `Reserve::poll` acquires `shared.inner`, decides readiness, and drops the lock before returning `Pending`, `Ready`, or waking a cascaded waiter. `Sender::send` awaits only the `Reserve` future and never holds a mutex guard across the await boundary.
- `src/channel/fault.rs`
  `auto_flush_including_current` and `flush` take `reorder_buffer`/`rng` locks only for local buffer extraction and shuffling. Both drop those guards before `self.inner.reserve(cx).await`.
- `src/sync/once_cell.rs`
  `get_or_init` and `get_or_try_init` perform the user future `f().await` only after the CAS transition to `INITIALIZING`. No waiter-list mutex is held across the await; cancellation resets state through `InitGuard`.
- `src/sync/pool.rs`
  `warmup` carries a `CreateSlotReservation` across `timeout(..., self.create_resource()).await`, but that reservation is not a mutex guard. The pool state mutex is not held across resource creation or timeout waits.
- `src/sync/rwlock.rs`
  `ReadFuture::poll` and `WriteFuture::poll` lock `state` only within one poll step, update waiter queues, then drop the lock before returning `Pending` or guards. The custom future structure avoids any lock guard surviving to an `.await`.
- `src/sync/semaphore.rs`
  `AcquireFuture::poll` uses one scoped `state` lock per poll step, removes or refreshes waiters under that lock, and drops it before wakeups and return. Cancellation cleanup also releases the lock before waking the next waiter.
- `src/combinator/rate_limit.rs`
  Queue/state locking is synchronous and contained inside non-async queue-management methods. The grep hits do not cross any `.await` points.
- `src/combinator/bulkhead.rs`
  Queue/bulkhead registry locking is likewise synchronous queue bookkeeping. No async wait path was found that retains a lock guard across suspension.

Notes:
- `src/channel/mpsc.rs` had live worktree edits during the audit, but the current snapshot still preserved the lock-drop-before-suspend behavior in `Reserve::poll`.
- This sweep was static only. No running deadlock reproduction was available to inspect with `gdb`/`strace`.
