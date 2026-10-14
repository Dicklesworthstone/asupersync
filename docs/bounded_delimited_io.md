# Bounded buffered record input

`asupersync::io::ext::AsyncBufReadExt` provides opt-in bounds for protocols
that accept delimiter-separated bytes from untrusted or unbounded sources.
The existing `read_until` and `split` methods keep their unbounded behavior.
No text decoding, new buffer layer, task, or background reader is introduced.

## Read one bounded record

```rust
use asupersync::io::AsyncBufRead;
use asupersync::io::ext::AsyncBufReadExt;
use std::io;

async fn read_header<R: AsyncBufRead + Unpin + ?Sized>(
    reader: &mut R,
    retained: &mut Vec<u8>,
) -> io::Result<usize> {
    reader.read_until_limited(b'\n', retained, 8 * 1024).await
}
```

`max_len` is a limit on the resulting vector length, including its existing
prefix and the delimiter. Dropping a pending borrowing wait preserves appended
bytes. Restart with the same vector and bound to retain the same allowance;
only the count returned by an individual wait starts again at zero.

A vector already longer than the supplied limit is `InvalidInput`, before a
source poll. Input extending past the limit is `InvalidData`: the accepted
prefix is retained and the first byte beyond the allowance remains unread.
This decision does not wait for EOF or discard the rest of the record. Raising
the bound is an explicit caller decision. Clearing the vector and restarting
without resynchronizing would incorrectly treat a continuation as a new record.

EOF without a delimiter is still accepted, including exactly-full EOF. Protocols
requiring a delimiter must check the final byte themselves. A zero limit permits
only EOF; a delimiter alone would still require one byte in the vector.

## Stream bounded segments

`reader.split_limited(delimiter, max_segment_bytes)` returns the existing `Split`
stream, but with a per-segment limit excluding the separator. Empty segments are
allowed at a zero limit. Exactly-full segments may end at a separator or EOF.
Consecutive separators yield empty segments; a trailing separator does not add
an extra empty segment, just as for `split`.

The first oversized segment emits a single `InvalidData` error and fuses the
stream. It never reports a successfully truncated record. `Split::into_parts()`
recovers `(reader, partial_segment)`, including the bytes already consumed before
an error or a dropped borrowing wait. The reader is still positioned inside
that same record, at its first unconsumed continuation byte. `into_inner()` keeps
its historical behavior of discarding the partial segment.

Ordinary source errors preserve their original error and accumulated prefix;
they do not reset the limit. Keep the `Split` itself across dropped `next` waits.
Both bounded operations retain the existing cooperative refill budget, so an
always-ready source does not monopolize one poll indefinitely.

## Explicit allocation-free resynchronization

When the protocol permits discarding the rest of an oversized record, use
`skip_until_limited` to create a `SkipUntilSession` over the same reader:

```rust
use asupersync::io::AsyncBufRead;
use asupersync::io::ext::AsyncBufReadExt;
use std::io;

async fn discard_remainder<R: AsyncBufRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<()> {
    let mut recovery = reader.skip_until_limited(b'\n', 64 * 1024);
    recovery.run().await?;
    if !recovery.delimiter_found() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "record delimiter missing"));
    }
    Ok(())
}
```

The operation scans and consumes buffered slices without collecting the discarded
record or allocating a scratch byte buffer. Its byte limit includes the delimiter
but not the prefix already accepted by an earlier read or split. A delimiter is
consumed exactly once; following-frame bytes remain in the reader. EOF is a
separate observable result: successful discard does not prove a delimiter was
found unless `delimiter_found()` is true.

Keep the recovery session across dropped `run()` waits to retain its byte budget.
`bytes_skipped()` is cumulative across waits and ordinary source errors; the
returned success count is cumulative too. A new wait never resets the allowance.
Do not construct a new session on each timeout unless the intention is to grant
another allowance. Successful completion is memoized, and a size refusal is
sticky with the first excess byte left unread. `into_inner()` deliberately
returns the reader for closing or a caller-authorized further recovery attempt.

Provider errors propagate unchanged. A provider panic propagates too, but leaves
the session poisoned rather than silently retrying an unknown source position.
Confirmed consumed bytes are only a lower bound after such a panic. There is no
automatic rollback or resynchronization, and dropping the session itself loses
its counter (not its already-performed consumption).

This helper bounds total discarded bytes and refills per poll (32). It has no
`Cx` observer, deadline, owned producer task, or forced-termination mechanism.
The caller chooses cancellation by dropping its borrowing wait and is responsible
for source closure when recovery fails. Upstream buffers and arbitrary provider
work still retain their own limits. The focused additional tests are in
`src/io/ext/buf_read_ext/skip_until/tests.rs`; they include a native duplex source
that parks mid-discard, resumes on a later wait, and delivers the following record
without waiting for the peer to close. Like the first bounded-read tests, they
were authored without a Rust runner and are not executed-runtime evidence.

## Boundaries and validation

These bounds cover retained record bytes, not a vector's allocated capacity,
upstream read-ahead, total input length, or downstream queues. Arbitrary provider
panics and hidden producer work do not acquire stronger guarantees from these
helpers. Dropping the owning buffer/stream can still discard retained data.

The focused tests live in `src/io/ext/buf_read_ext/limited_tests.rs`. They cover
zero/exact/oversized limits, binary input, prefix retention, cancellation/restart,
source errors, bounded refills, and native duplex input that stays open beyond
a rejected record. These tests were authored without Cargo, rustc, rustfmt, or
RCH available and have NOT been compiled or executed in that environment.
Use the repository-authorized Rust validation path before treating them as
runtime evidence. Source review and whitespace checks are not Rust execution.
