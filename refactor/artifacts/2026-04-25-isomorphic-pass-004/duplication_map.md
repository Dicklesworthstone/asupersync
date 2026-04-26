# Duplication Map — pass 004

Target file: `src/net/tcp/split.rs`

- Repeated wasm-only unsupported-result branches in the owned split halves' `local_addr` and `peer_addr` methods.
- One remaining wasm-only `Err(...)` return in `OwnedReadHalf::reunite`.
- Candidate shape: Type II parametric clone for the unsupported-result branches, plus one trivial same-semantics style cleanup.
