# Duplication Map — pass 003

Target file: `src/net/tcp/stream.rs`

- Repeated wasm-only unsupported-result branches in `from_std`, `peer_addr`, `local_addr`, `shutdown`, `set_nodelay`, `nodelay`, `set_ttl`, and `ttl`.
- Candidate shape: Type II parametric clone with identical dropped-argument pattern and identical unsupported error wrapper.
