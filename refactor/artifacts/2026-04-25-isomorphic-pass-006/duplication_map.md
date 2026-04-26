# Duplication Map — pass 006

Target file: `src/net/tcp/stream.rs`

- Repeated wasm-only `browser_tcp_poll_unsupported(...)` shims in `TcpStream`'s wasm `AsyncRead` and `AsyncWrite` impls.
- Candidate shape: Type II parametric clone with identical dropped-argument handling and identical poll error wrapper, varying only by operation string and argument tuple.
