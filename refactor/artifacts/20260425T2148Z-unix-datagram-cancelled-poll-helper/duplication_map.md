# Duplication Map

- Clone family: repeated cancelled `Poll::Ready(Err(...))` branches in
  `src/net/unix/datagram.rs`.
- Type: I (exact clone).
- Repeated shape:
  - return interrupted `io::Error` with message `"cancelled"`

