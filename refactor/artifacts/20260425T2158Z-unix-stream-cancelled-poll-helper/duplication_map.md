# Duplication Map

- `src/net/unix/stream.rs`
  - repeated `Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")))`
  - sites: connect wait loops, ancillary poll loops, `AsyncRead`, `AsyncReadVectored`, `AsyncWrite`, `poll_flush`, `poll_shutdown`
