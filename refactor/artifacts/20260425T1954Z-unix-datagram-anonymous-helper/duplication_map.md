# Duplication Map

- Clone family: non-path-cleaning Unix datagram constructors in
  `src/net/unix/datagram.rs`.
- Type: II (parametric clone).
- Repeated shape:
  - store `inner`
  - set `path` to `None`
  - set `cleanup_identity` to `None`
  - set `registration` to `None`

