# Browser local-spawn ownership and shutdown safety

The README proof-note gate applies because the edited `src/runtime/builder.rs`
contains existing unsafe test environment helpers. This repair changes local
request routing and browser-runtime shutdown in safe Rust. It does not change
an unsafe block, allowance, environment helper, or the ledger boundary
`unsafe-src-runtime-builder-rs`.

Each queued local request now carries a private `Weak<SpawnMailbox>` identity.
The weak reference retains the allocation identity without keeping the runtime
alive. Pointer comparison against the active owner's `Arc` is therefore valid
even if an older runtime has already stopped: its allocation cannot be reused
while a queued weak reference exists. An ownerless drainer cannot take an owned
request. The public `LocalSpawnRequest` fields and all public signatures remain
unchanged.

Native workers and browser pumps install their own lane owner before admission.
Nested native drives leave owned entries reachable and select only their own
requests, preserving FIFO within each owner. Only legacy unowned harness entries
are set aside. The empty-lane scheduler check avoids additional owner lookups
and reference-count operations.

The native background thread retains its owner guard through the handoff check,
after the dispatch loop's nested guard has ended. Otherwise an ownerless query
would miss its queued requests and permit a loan that strands a `!Send` factory
on the background thread. The handoff regression starts with an observed queued
request and an outstanding loan request, then verifies refusal, execution on the
owning thread, release of pending credit, and destruction of the local capture.

Browser teardown closes spawn admission and waits for admitted publishers before
stopping the scheduler. It then extracts only its own queued local requests and
resolves them with the shutdown cancellation reason after releasing the lane
borrow. Retiring that runtime's local store drops parked futures outside the
store borrow. Neither operation moves a `!Send` future to another thread or
holds the runtime-state lock across a user destructor or completion callback.
Native worker teardown retains its established retirement protocol.

The adjacent `asupersync-kxlmkc` repair keeps the native handoff states and
notifications intact while moving destruction of an offered, returned, or
late-returning worker outside the driver's slot mutex. A worker can own a
user-provided evidence sink whose destructor re-enters shutdown. Publishing
`Closed` before releasing the mutex makes that re-entry observe the terminal
state without attempting to acquire a lock already held by its caller.
Four regressions attach such a sink to a real worker and check both mutex
availability and successful shutdown re-entry. Assertions run after the
destructor returns, so the old lock cycle is detected without hanging a test.
The fourth covers the background wait loop observing scheduler shutdown while
an offer remains unclaimed; that path also releases the mutex before retirement.

The stopped browser worker is removed from its pump with `try_lock` and dropped
after releasing that mutex. If shutdown occurs during an active task poll, the
busy pump retains the worker until that poll returns. The pump then repeats
local-store retirement before dropping the worker, covering a local future
returned as `Pending` after the first retirement. Removing the worker also
prevents a retained pump handle from keeping admitted `Send` futures alive via
the worker's runtime-state references.

The original library pump test remains unchanged. Public regression tests cover
queued and already-polled pending futures, exact shutdown join results, capture
release, two-runtime admission/shutdown isolation, nested native shutdown, and
FIFO across a nested native drive. A focused unit test also verifies that an
ownerless drain cannot consume a reserved request and that its eventual owner
can cancel it and release the pending credit.
Additional public tests cover a retained pump with an admitted pending `Send`
task and the last runtime owner being dropped inside a local task's poll.

This note explains the ownership invariants; it is not a formal proof, browser
deployment test, performance result, or release approval. Source-specific remote
test results, compiler checks, and any remaining gate failures are recorded on
`asupersync-a18rx3`.
