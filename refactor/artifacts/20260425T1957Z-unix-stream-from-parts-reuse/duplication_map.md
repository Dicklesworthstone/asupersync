# Duplication Map

- Clone family: `UnixStream` constructors that hand-build the same
  `Arc<net::UnixStream> + Mutex<Option<IoRegistration>>` shell.
- Type: II (parametric clone).
- Repeated shape:
  - wrap `net::UnixStream` in `Arc`
  - store `registration`
  - reuse the same lazy-registration invariant

