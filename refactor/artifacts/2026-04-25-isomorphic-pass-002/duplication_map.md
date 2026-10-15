# Duplication Map — pass 002

Target file: `src/net/udp.rs`

- Repeated wasm-only unsupported-result branches in `bind`, `connect`, `send_to`, `recv_from`, `send`, `recv`, `peek_from`, and `from_std`.
- Repeated wasm-only unsupported-poll branches in `poll_recv_from`, `poll_send`, `poll_recv`, and `poll_peek_from`.
- Candidate shape: Type II parametric clone with identical dropped-argument pattern and identical error construction, varying only by operation string and return wrapper.
