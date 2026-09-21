# Multi-stream byte-I/O capture and offline replay

`asupersync::io::replay_group` records a bounded window across several already
open, explicitly supplied byte streams. Use it for a consumer whose result
involves more than one connection: a request to one service followed by another,
or multiple independent peers whose responses are combined. The group preserves
one observed order of completed I/O across all registered streams, not merely
one unrelated tape per connection.

The adapters reuse the existing `RecordingIo` and `ReplayIo` implementations.
Scalar and vectored request shapes, write fingerprints, read bytes, original
error kinds/native codes, flush and shutdown remain governed by those engines.
Existing single-stream and ordered clock/entropy session APIs are unchanged.

## Capture ownership

Create `IoRecordingGroup` with explicit `IoGroupCaptureLimits`, register each
provider under a unique caller-chosen `u64`, and pass the returned adapters to
the actual consumer. Different provider types can share one group. Registration
queries the provider's vectored-write capability outside the group lock but does
not read or write bytes. A refused registration returns the original provider.
Identities are application labels, not addresses or authenticated peer identities.

```rust,ignore
use asupersync::io::replay::IoCaptureLimits;
use asupersync::io::replay_group::{IoGroupCaptureLimits, IoRecordingGroup};

// `first` and `second` are streams already authorized and opened by their owner.
let group = IoRecordingGroup::new(IoGroupCaptureLimits {
    max_streams: 2,
    max_events: 256,
    per_stream: IoCaptureLimits::new(128, 64 * 1024, 64 * 1024, 16),
});
let mut a = group.register(17, first).map_err(|failure| failure.error)?;
let mut b = group.register(29, second).map_err(|failure| failure.error)?;
let application_result = consumer(&mut a, &mut b).await;

// After all users of these adapters are drained, return each original provider.
let first = a.into_inner();
let second = b.into_inner();
let tape = group.finish()?;
// Keep application_result separate: a complete capture may reproduce an error.
```

`into_inner` ends that stream's capture; it does not close the original provider.
`finish` succeeds only once, after every stream has finalized and each component
window is complete. `LiveStreams` can be retried. Dropping an adapter instead of
finalizing, a provider poll panic, a component refusal, or an exhausted global
order bound invalidates the entire capture. No partial group is published.
Capture refusals do not replace the underlying live I/O result. Remaining
component storage is still limited independently; there is no unbounded log.

Independent live provider polls may overlap. The group assigns their observed
order after each provider returns and before the adapter returns to its caller.
Neither provider calls nor waker callbacks execute under the group mutex. This
ordering is NOT kernel-event timing or an ordering of remote side effects.

## Offline execution

`tape.replay()` retains no original provider, socket, reactor or host capability.
Open each captured identity with `IoReplayGroup::open` exactly once. Opening order
need not match registration order. Unknown and duplicate opens return typed
refusals; there is no network fallback.

An early poll on another stream returns `Pending`. Finishing the prerequisite
wakes that stream's latest waiter. On the eligible stream, changing the operation
kind or request shape fails immediately. An extra operation on a locally exhausted
stream fails even if another stream has a remaining tail. The first error remains
sticky for the whole group, including when the consumer ignores its I/O error.
An original captured I/O failure, by contrast, is replayed without being confused
with divergence. A dropped incomplete stream poisons the group and wakes peers.

Always call `verify_complete()` after draining users. It includes the tails of
streams never opened. A capture with no operations on a stream does not require
opening that empty stream. Verification is a point-in-time check, not a runtime
join or an irreversible shutdown of the replay providers.

Within ONE stream, the consumer must reproduce its operation order: independently
reordered read/write halves are not supported by this strict group interface.
Across streams, polling preference may change while completed-operation order
is enforced. A borrowed pending operation can leave at most that stream's latest
waker until subsequent progress, polling or stream destruction. No timer or busy
loop manufactures a missing prerequisite; the caller owns deadlines/cancellation.

## Bounded persistence and authenticated archives

`RecordedIoGroup::to_canonical_bytes` and `from_canonical_bytes` persist the entire
group atomically as a logical envelope. The format is `ASUPMIO`, version 1:
stream identities, unchanged canonical component tapes, global operation order,
and a domain-separated checksum. Framing, count/storage bounds, unique identities,
stream ordinals, coverage counts and every nested tape are checked before a group
is returned. Exact component operation kinds/request shapes are additionally
checked during replay; import alone does not establish executable equivalence.
The existing I/O tape's OS restriction still applies.

The checksum detects corruption, NOT malicious replacement. On native targets,
prefer `ReplayArchiveSealer::seal_io_group` and `ReplayArchiveKey::open_io_group`.
These reuse the existing XChaCha20-Poly1305 envelope with authenticated profile 3.
Profiles 1 (independent session) and 2 (ordered session) retain their existing
bytes and cannot be opened as groups. Authentication precedes group decoding.
The sealer uses ONE non-wrapping nonce sequence across all three profiles.

Supply a dedicated secure key, a nonce prefix unique for that key across all
processes/restarts, and independently trusted expected source/capture bindings.
See `encrypted_replay_archives.md` for provisioning and rollback limits. The
adapter performs no implicit key lookup, entropy draw, file write or network I/O.
Plaintext encodings/scratch have zeroizing owners; caller copies and storage do
not. Debug output omits payloads. Caller-chosen stream IDs are not secret labels.

Capture memory combines per-stream allowances and global order metadata. Import
uses separate entire-envelope, stream/event-count, group-metadata and per-stream
encoded/decoded bounds. Group metadata includes temporary descriptors, sorted IDs
and coverage counts. Component allowances multiply by admitted stream count.
Input bytes, allocator overhead, provider memory and later bounded replay slots
remain separate. Encoding holds bounded temporary component bytes and a bounded
final output concurrently. These synchronous operations do not promise an async
cancellation, exact RSS, performance or wall-clock bound.

## Validation and limits

The two-commit batch adds 28 unit tests and two native process tests. Primitive
coverage includes actual multi-threaded capture, lost-wake-sensitive registration,
latest wakers, hostile callbacks, failed capture, strict ordering, and abandonment.
Codec/archive tests include truncation/bit changes, forged identities/ordinals,
independent bounds, nested corruption, profile/key substitution, nonce exhaustion,
and an independently generated system-libsodium known-answer vector.

The native journeys use two real loopback TCP connections on current-thread and
two-worker runtimes. A peer must witness a real pending read before responding.
Original providers are retired; only encrypted bytes reach a fresh subprocess.
The offline consumer reverses polling preference, must reproduce the same
application error, and must consume the whole group. Pending wake timing is not
claimed as reproduced by this completed-poll format.

```sh
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib io::replay_group::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --lib io::replay_archive::io_group::
RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p asupersync --test replay_group_native
```

Rust/Cargo/rustfmt/RCH were unavailable in the authoring environment. These Rust
tests were authored but NOT compiled or executed. Lexical checks, source review,
Git blob comparisons and independent libsodium/reference-format checks are not
Rust execution evidence. This feature does not record connection establishment,
clock/entropy effects, pending readiness, cancellation, task schedules or arbitrary
concurrent-program behavior, and is not whole-application replay or attestation.
