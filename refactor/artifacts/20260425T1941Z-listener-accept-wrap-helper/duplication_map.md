# Duplication Map

- Clone family: repeated accepted-stream wrapping in `TcpListener::poll_accept`.
- Type: I (exact clone).
- Repeated shape:
  - `TcpStream::from_std(stream).map(|stream| (stream, addr))`

