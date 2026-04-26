# Duplication Map

- Clone family: wasm TCP unsupported helper stacks duplicated in
  `src/net/tcp/stream.rs` and `src/net/tcp/split.rs`.
- Type: II (parametric clone).
- Repeated shape:
  - discard unused wasm-only arguments
  - return `Unsupported` using the same parent error constructor
  - wrap poll sites in `Poll::Ready(Err(...))`

