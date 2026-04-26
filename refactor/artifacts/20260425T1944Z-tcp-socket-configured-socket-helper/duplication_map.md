# Duplication Map

- Clone family: duplicated socket2 family/domain/reuse setup in
  `TcpSocket::listen` and `TcpSocket::connect`.
- Type: III (gapped clone).
- Shared shape:
  - derive domain from `TcpSocketFamily`
  - create `socket2::Socket`
  - apply `reuseaddr` and `reuseport`
- Bounded variation:
  - `listen` then binds/listens/nonblocks
  - `connect` optionally binds then delegates to `connect_from_socket`

