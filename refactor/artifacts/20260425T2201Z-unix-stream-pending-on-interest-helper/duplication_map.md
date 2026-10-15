# Duplication Map

- `src/net/unix/stream.rs`
  - repeated `register_interest(...); Poll::Pending` branches on `WouldBlock`
  - sites: ancillary send/recv, `poll_read`, `poll_read_vectored`, `poll_write`, `poll_write_vectored`, `poll_flush`
