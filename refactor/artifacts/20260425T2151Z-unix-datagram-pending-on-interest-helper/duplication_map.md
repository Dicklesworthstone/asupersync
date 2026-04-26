# Duplication Map

- Clone family: repeated register-interest-and-return-pending branches in
  `src/net/unix/datagram.rs`.
- Type: II (parametric clone).
- Repeated shape:
  - call `register_interest(cx, interest)`
  - return `Poll::Ready(Err(err))` on failure
  - otherwise return `Poll::Pending`

