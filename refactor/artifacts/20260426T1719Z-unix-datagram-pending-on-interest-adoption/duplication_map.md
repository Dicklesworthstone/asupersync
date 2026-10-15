# Duplication Map

- `src/net/unix/datagram.rs`
  - repeated `register_interest(...); Poll::Pending` branches
  - sites: `send_to`, `recv_from`, `send`, `recv`, `poll_recv_ready`, `poll_send_ready`, `peek`, `peek_from`
