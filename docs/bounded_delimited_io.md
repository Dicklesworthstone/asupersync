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
