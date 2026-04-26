# Duplication Map

- Clone family: `TcpSocket::new_v4` and `TcpSocket::new_v6`.
- Type: II (parametric clone).
- Repeated shape:
  - construct identical `TcpSocketState`
  - vary only the `TcpSocketFamily` discriminant

