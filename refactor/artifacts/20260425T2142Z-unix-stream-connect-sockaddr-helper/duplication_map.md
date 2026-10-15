# Duplication Map

- Clone family: Unix stream connect constructors in `src/net/unix/stream.rs`.
- Type: II (parametric clone).
- Repeated shape:
  - create a Unix stream socket
  - set nonblocking mode
  - connect to a `SockAddr`
  - wait for `EINPROGRESS` via `wait_for_connect`
  - convert into `UnixStream`

