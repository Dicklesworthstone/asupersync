# Duplication Map — pass 005

Target file: `src/net/udp.rs`

- Residual cleanup left after pass 002: one dead inner wasm-only branch inside the non-wasm-only `poll_send_to`, one uncollapsed wasm unsupported-result branch in `recv_from`, and the now-almost-stale wasm-only `needless_return` suppression.
- Candidate shape: low-risk same-surface cleanup; remove dead conditional code and prove the suppression is unnecessary.
