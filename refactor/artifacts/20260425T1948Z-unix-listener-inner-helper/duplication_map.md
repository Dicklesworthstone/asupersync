# Duplication Map

- Clone family: non-cleanup and bound Unix listener constructors in
  `src/net/unix/listener.rs`.
- Type: III (gapped clone).
- Shared shape:
  - initialize `accept_waiters`
  - store `inner`
  - store `path`
  - store `cleanup_identity`
  - initialize `registration` to `None`

