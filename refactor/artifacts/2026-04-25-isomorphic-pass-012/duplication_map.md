# Duplication Map

- Clone family: wasm TCP unsupported-result shims outside `stream.rs` and `split.rs`.
- Type: II (parametric clone).
- Sites:
  - `src/net/tcp/socket.rs`: `TcpSocket::listen`
  - `src/net/tcp/socket.rs`: `TcpSocket::connect`
  - `src/net/tcp/listener.rs`: `TcpListener::bind`
  - `src/net/tcp/traits.rs`: `TcpListenerBuilder::bind`
- Repeated shape:
  - bind/consume args in a wasm-only block
  - discard arguments to silence unused warnings
  - return `Unsupported` with a fixed operation string
