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

## Connection attempts and retries

A consumer can now start before connection establishment, rather than receiving
preconnected streams. Use `ConnectionAttempt::new(journal_id, data_id)` for each
attempt. The IDs must differ and share the session's existing stream namespace;
use fresh IDs on every retry, including failures to the same destination.

On native targets, `session.connect_tcp(attempt, address).await` invokes the real
nonblocking TCP connector at that concrete `SocketAddr`. It automatically binds
the IP family, address, port, IPv6 flow information and scope ID. It performs no
DNS, TLS, implicit retry or socket-option changes. Authorize the destination
first, use the existing runtime context, and retain an outer deadline/cancellation
owner. This adapter does not grant network authority or create tasks.

For an authorized custom connector, use
`session.connect_with(attempt, request_key, max_request_bytes, factory).await`.
The factory is invoked once on the first poll. Bind all target, protocol, TLS,
authentication and custom-option decisions into the stable request key. Its
fingerprint is recorded, not its plaintext bytes, but predictable request keys
can still disclose information through guessing; protect captures as sensitive.

The connector is an **opaque effect provider**. Its construction, polls,
destruction and stream capability queries must not call this session's wrapped
clock, entropy or I/O providers. That would hide required effects inside code
which offline replay intentionally does not execute. Such overlap refuses the
capture while preserving normal live results. Other tasks may use the session
between source polls. No timeline lock is held across a callback or `Pending`.

Native connection errors are returned unchanged. Successful streams return a
`RecordingConnection<T>` implementing the normal byte traits; return its provider
with `into_inner` after draining users. Capture limits/collisions do not replace
a real result or throw away a successfully connected stream: forwarding continues,
but the whole capture is refused. Dropping an attempted connection owns/drops its
actual source future and refuses capture instead of inventing a terminal result.
Dropping an unpolled attempt makes no source call or timeline entry.

Offline, use `replay.connect_tcp(attempt, address).await`, or
`replay.connect(attempt, request_key).await` for the custom form. These APIs have
**no live factory or network fallback**. Early attempts and completions park on
the joint timeline. Failed attempts reproduce their I/O error kind/native code;
custom error strings and payloads are not reproduced. Success exposes only the
recorded data stream bound to that request. Changed targets/keys, reused IDs,
malformed success records and missing streams invalidate replay even when their
I/O errors are ignored. Cancelling an attempted replay also invalidates the group.
The caller still owns retry policy and must verify complete consumption.

Each attempt uses one logical journal stream with precisely two observations:
a three-slice request-fingerprint write (domain, data ID, request key), and a
one-byte success or native-error read. These are **not network bytes**. Success
also registers its actual data stream. Global stream/effect limits include both;
private journal limits are two operations, one read byte, three vectored slices
and the admitted request extent. Ordinary data-stream limits are unchanged.
Import limits must admit both kinds of streams. The TCP key is 36 fixed bytes;
custom request hashing is bounded by `max_request_bytes`. The pinned source future
and provider allocations, total concurrent attempts, execution time and retained
caller buffers require separate application/runtime admission bounds.

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
Connection journals reuse this exact format/profile, not a new sidecar or codec.
They are logical conventions checked by `connect`, not new OS-event claims or
capability restrictions on an owner who deliberately calls lower-level `open`.

## Scope and validation

This is completed-effect and opaque connection-result replay, not production
scheduler replay. Pending live polls, readiness timing, timer driving, connection
handshake/DNS/TLS internals, cancellation outcomes and unwrapped effects are not
captured. Within one stream operation order remains strict; the standalone byte
group's split halves are a separate interface. Application errors depending on
unrecorded connector error messages cannot be claimed as faithfully reproduced.

The original implementation includes 34 unit tests across the core, codec,
archive and Send driver, plus two native fresh-process journeys. Those journeys
capture two real TCP connections, require a witnessed Pending read before the
peer responds, verify nonce-derived request/marker bytes, retire original
providers, and transfer only encrypted bytes to an offline child. A changed-write
negative control must invalidate replay, not merely fail process startup.

Connection replay adds 20 core and eight TCP binding/persistence/Send unit tests,
plus two native journeys in `tests/replay_connect_native.rs`. The native journeys
retain a bound non-listening socket to obtain a real refused connection without
a freed-port race, retry into two actual TCP connections, require a Pending read,
and run the same generic application offline in a new child. Actual connection
error kind/code, both clock samples, nonce and reply bytes must match the live
output digest. Ciphertext crosses stdin; nonsecret endpoint configuration and
the expected digest are supplied explicitly. A changed-destination negative
control must invalidate the final output even when its I/O error is ignored.
The two variants use current-thread and two-worker native runtime configurations.

These tests are authored, not executed evidence. Rust/Cargo/rustfmt and RCH were
unavailable in the authoring environment; the remote-required attempts stopped at
`rch: command not found` (exit 127). No compiler, native, performance, release, or
full incident-replay success is claimed. Related `br-asupersync-bi2462.8` remains open.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-group-session-validation cargo test -p asupersync --lib io::replay_group_session::
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-group-session-validation cargo test -p asupersync --lib io::replay_archive::group_session::
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-group-session-validation cargo test -p asupersync --test replay_group_session_native
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-connect-replay-validation cargo test -p asupersync --lib io::replay_group_session::connect:: -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/asupersync-connect-replay-validation cargo test -p asupersync --test replay_connect_native -- --nocapture
```
