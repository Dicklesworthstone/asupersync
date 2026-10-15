# Duplication Map

- Clone family: unsupported fallback returns inside the non-BSD kqueue stub.
- Type: I (exact clone).
- Sites:
  - `KqueueReactor::new`
  - `Reactor::register`
  - `Reactor::modify`
  - `Reactor::deregister`
  - `Reactor::poll`
  - `Reactor::wake`
- Repeated shape:
  - construct the same `Unsupported` error inline
  - return it immediately
