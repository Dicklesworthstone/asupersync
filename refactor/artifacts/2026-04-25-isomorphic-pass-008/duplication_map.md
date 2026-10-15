# Duplication Map — pass 008

Target file: `src/net/tcp/stream.rs`

- Residual direct wasm unsupported-result branches still bypassing the local helper macro in `connect`, `connect_socket_addr`, and `set_keepalive`.
- Candidate shape: Type II parametric clone with identical unsupported error construction and identical dropped-argument behavior.
