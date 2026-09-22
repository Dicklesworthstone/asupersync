# Joint multi-stream, clock and entropy replay

`asupersync::io::replay_group_session` records one completed-effect timeline
across multiple explicitly supplied byte streams, one observation clock and
an entropy root with its fork descendants. Unlike separate byte-group and
source tapes, clock/entropy calls cannot silently move across I/O completions.

## Live capture

Construct `RecordingGroupSession::new(entropy, clock, limits)` using already
authorized `Arc<dyn EntropySource>` and `Arc<S: TimeSource>` capabilities. Limits
independently bound streams, total effects, each stream's operations/bytes,
aggregate entropy/forks and clock samples. No source is sampled by construction.

Register already-open connections with `register(id, io)`. IDs are unique
caller-selected labels, not authenticated peer identities. Different concrete
I/O types may share one session. Use `session.entropy()` and `session.clock()`
where the real consumer accepts those traits; entropy forks remain wrapped.

After draining users, recover each original provider with `io.into_inner()`
and call `session.finish()`. Finish with live streams is retryable and does not
finish either shared source. A dropped stream, provider panic, capture limit,
or overlapping/reentrant provider call refuses the whole window. Successful
live results are never replaced by capture errors. Returning a provider does
not close it; original network/task ownership remains the caller's responsibility.

## Offline execution

`capture.replay()` creates no live providers. Open each captured ID once through
`ReplayGroupSession::open`. An early I/O operation parks until its recorded
prerequisite completes, including prerequisites on the clock or an entropy fork.
Wrong operations on the eligible stream fail immediately. Synchronous clock and
entropy calls cannot park: reordering/exhaustion returns typed errors from
`try_*` methods or a typed panic through infallible capability traits.

The first divergence stays sticky across all providers even when an application
ignores an I/O error or catches a panic. Original recorded I/O failures are replayed
as observations, not misclassified as divergence. Dropping an unfinished byte
stream invalidates the session and wakes parked peers. Extra operations on an
exhausted stream fail even when other streams still have remaining observations.

Manually driven consumers must call `verify_complete()` after draining users.
Alternatively `run(max_polls, factory)` borrows the session for a boxed consumer,
drops that future before verification and accepts output only after every effect
was consumed. `run_send` preserves Send for caller-owned native tasks; neither
method spawns tasks. Application errors are ordinary replay output, not fabricated
success. Poll budgets do not bound a non-returning poll or a permanently parked
future; an outer owner must supply deadlines/cancellation.

## Portable, protected captures

`to_canonical_bytes(max_bytes)` exports the complete window in `ASUPGSC` V1;
`from_canonical_bytes(bytes, GroupSessionDecodeLimits)` admits the entire encoding,
metadata, stream/effect counts and all nested component bounds. No partial session
escapes. Decoding retains stream IDs, entropy source topology and cross-provider
order. Component OS/version constraints remain unchanged. Import alone does not
prove successful replay of a consumer's request shapes or original failure.

Canonical bytes are plaintext with an unkeyed corruption checksum. For actual
captures on native targets, use `ReplayArchiveSealer::seal_group_session` and
`ReplayArchiveKey::open_group_session`. Authenticated profile 4 cannot be replaced
by independent/ordered single-stream sessions or byte-only group profiles. The
existing dedicated-key, unique key/nonce-prefix, expected source/capture binding
and rollback limitations apply. All profiles share one non-wrapping counter.
Encoded temporaries/decryption scratch have zeroizing owners; caller copies,
files, swap and original providers do not. No storage or key lookup is implicit.

## Scope and validation

This is completed-effect replay, not production scheduler replay. Pending live
polls, readiness timing, timer driving, connection establishment, cancellation
and unwrapped effects are not captured. Within one stream operation order remains
strict; the standalone byte group's split halves are a separate interface.

The implementation includes 34 unit tests across the core, codec, archive and
Send driver, plus two native fresh-process journeys. Native journeys capture two
real TCP connections, require a witnessed Pending read before the peer responds,
verify nonce-derived request/marker bytes, retire original providers, and transfer
only encrypted bytes to an offline child. A changed-write negative control must
invalidate the actual replay, not merely fail process startup.

These tests are authored, not executed evidence. Rust/Cargo/rustfmt and RCH were
unavailable in the authoring environment; the remote-required attempt stopped at
`rch: command not found` (exit 127). No compiler, native, performance, release, or
full incident-replay success is claimed. Related `br-asupersync-bi2462.8` remains open.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-group-session-validation cargo test -p asupersync --lib io::replay_group_session::
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-group-session-validation cargo test -p asupersync --lib io::replay_archive::group_session::
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-group-session-validation cargo test -p asupersync --test replay_group_session_native
```
