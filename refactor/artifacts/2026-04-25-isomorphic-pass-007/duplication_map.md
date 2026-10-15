# Duplication Map — pass 007

Target file: `src/net/tcp/split.rs`

- Repeated wasm-only `browser_tcp_poll_unsupported(...)` shims across borrowed and owned split halves.
- Candidate shape: Type II parametric clone with identical dropped-argument handling and identical poll error wrapper, varying only by operation string and argument tuple.
