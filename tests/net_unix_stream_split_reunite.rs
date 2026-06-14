#![allow(missing_docs)]
#![cfg(unix)]
//! `UnixStream` split/reunite integration tests. `tests/net_tcp.rs` covers the
//! TCP twin, but the Unix domain `into_split`/`reunite` path has no `tests/*.rs`
//! coverage, and neither side covers the mismatched-halves error path.
//!
//!   - `unix_stream_split_halves_do_io_then_reunite`: the read/write halves of a
//!     split stream carry data both ways, and the matching halves reunite into a
//!     working `UnixStream`.
//!   - `unix_stream_reunite_rejects_mismatched_halves`: reuniting halves that
//!     originated from different streams returns `ReuniteError`.
//!
//! Real connected `UnixStream::pair()` sockets, no mocks; every read follows a
//! write on the connected peer, so the first poll is `Ready` (no reactor parking).

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::unix::UnixStream;
use std::io;

use futures_lite::future::block_on;

/// The split halves carry data in both directions, and the matching halves
/// reunite into a `UnixStream` that is still usable.
#[test]
fn unix_stream_split_halves_do_io_then_reunite() {
    let result = block_on(async {
        let (a, mut b) = UnixStream::pair()?;
        let (mut a_read, a_write) = a.into_split();

        // b -> a's read half.
        b.write_all(b"hi").await?;
        let mut buf = [0u8; 8];
        let n = a_read.read(&mut buf).await?;
        assert_eq!(
            &buf[..n],
            b"hi",
            "the read half receives bytes written by the peer"
        );

        // Reunite a's matching halves back into a stream.
        let mut a_reunited = a_read
            .reunite(a_write)
            .map_err(|_| io::Error::other("matching halves should reunite"))?;

        // The reunited stream still works: a_reunited -> b.
        a_reunited.write_all(b"yo").await?;
        let mut buf2 = [0u8; 8];
        let n2 = b.read(&mut buf2).await?;
        assert_eq!(&buf2[..n2], b"yo", "the reunited stream still carries data");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "split half I/O and reunite should succeed: {result:?}"
    );
}

/// Reuniting a read half with a write half from a *different* stream must fail
/// with `ReuniteError` rather than silently producing a frankenstream.
#[test]
fn unix_stream_reunite_rejects_mismatched_halves() {
    let result = block_on(async {
        let (a, _a_peer) = UnixStream::pair()?;
        let (c, _c_peer) = UnixStream::pair()?;

        let (a_read, _a_write) = a.into_split();
        let (_c_read, c_write) = c.into_split();

        // a_read belongs to the first pair, c_write to the second.
        let reunited = a_read.reunite(c_write);
        assert!(
            reunited.is_err(),
            "reuniting halves from different streams must return ReuniteError"
        );

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "mismatched-halves reunite check should run: {result:?}"
    );
}
