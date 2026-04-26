# Duplication Map

- Clone family: unsupported fallback returns inside the non-Windows IOCP stub.
- Type: I (exact clone).
- Sites:
  - `IocpReactor::new`
  - `Reactor::register`
  - `Reactor::modify`
  - `Reactor::deregister`
  - `Reactor::poll`
  - `Reactor::wake`
- Repeated shape:
  - construct the same `Unsupported` error inline
  - return it immediately
