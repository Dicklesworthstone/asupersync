# Duplication Map

- `src/net/unix/datagram.rs`
  - repeated `Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")))`
  - sites: `send_to`, `recv_from`, `send`, `recv`, `poll_recv_ready`, `poll_send_ready`, `peek`, `peek_from`
