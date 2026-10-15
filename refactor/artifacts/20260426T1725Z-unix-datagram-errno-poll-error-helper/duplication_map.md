# Duplication Map

- `src/net/unix/datagram.rs`
  - repeated `Poll::Ready(Err(io::Error::from_raw_os_error(errno as i32)))`
  - sites: `poll_recv_ready`, `poll_send_ready`, `peek`, `peek_from`
