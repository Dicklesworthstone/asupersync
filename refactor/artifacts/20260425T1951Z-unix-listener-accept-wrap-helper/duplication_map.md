# Duplication Map

- Clone family: repeated accepted-stream wrapping in `UnixListener::poll_accept`.
- Type: I (exact clone).
- Repeated shape:
  - `UnixStream::from_std(stream).map(|stream| (stream, addr))`

