# Duplication Map

- `src/net/unix/split.rs`
  - repeated fallback `WouldBlock` wake-and-pending path in borrowed halves
  - repeated `register_interest(...); Poll::Pending` path in owned halves
