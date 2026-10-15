# Duplication Map

- Clone family: unsupported fallback returns inside the `io_uring` stub reactor.
- Type: I (exact clone).
- Sites:
  - `IoUringReactor::new`
  - `Reactor::register`
  - `Reactor::modify`
  - `Reactor::deregister`
  - `Reactor::poll`
  - `Reactor::wake`
- Repeated shape:
  - return `Err(unsupported())`
