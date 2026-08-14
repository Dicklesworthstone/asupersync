# Database, Messaging, Filesystem, Process, Signal

This file covers the broad system-integration surfaces beyond the core runtime.

## Database

Native database surfaces exist behind features:

- `database::sqlite` — blocking-pool bridge over bundled `rusqlite` with
  cancel-safe wrappers that respect region deadlines; row streams are
  connection-exclusive and dropped transactions roll back eagerly (v0.4.0),
- `database::postgres` — native binary protocol v3 directly over `TcpStream`,
  SCRAM-SHA-256 auth,
- `database::mysql` — native wire protocol, native + `caching_sha2` auth.

All three support prepared statements, transactions, and connection reuse
(README "Database Integration").

Migration guidance:

- prefer native clients when doing full replacement,
- pass `&Cx` through transactional and query code,
- treat cancellation and deadlines as part of the API contract,
- make connection ownership and pooling explicit.

Important limitation:

- SQLx compile-time `query!` style macros are explicitly unsupported in the repo's migration matrix.
- If you depend on them today, either keep SQLx behind compat temporarily or redesign around native query paths.

## Messaging

Native messaging surfaces exist (`src/messaging/{redis,nats,kafka}.rs`), but
the README coverage map still classifies messaging clients as
In progress / Early. Redis PubSub validates control acknowledgements as of
v0.4.0.

Good fits to inspect first:

- in-process pub/sub,
- request/reply,
- bounded backpressure and lifecycle tests.

Be conservative with:

- durable fabric/control-plane claims unless current source and tests prove them,
- Kafka advanced consumers,
- Redis cluster failover,
- NATS JetStream.

If your workload depends on a feature that the repo classifies as partial, either:

- validate it carefully before adopting it,
- or keep that slice behind a boundary bridge until the native surface is sufficient.

## Filesystem

Prefer `fs::*` over `tokio::fs`, but note the deliberately conservative scope:
`src/fs/` is a partial blocking-backed facade, not full `tokio::fs` parity.
It currently exposes `File`, buffered readers/writers, metadata,
directory/path helpers, `try_exists`, `write_atomic`, `UnixVfs`, and platform
capability reports. Most operations are async facades over
`spawn_blocking_io`; poll-based `File` traits still use direct blocking I/O,
recursive directory removal and large copies inherit standard-library
partial-state semantics, and Linux `io_uring` support is limited to
feature-gated helper paths.

Migration checklist:

- replace file reads/writes/metadata/path ops,
- test cleanup and rename semantics,
- validate any niche behavior such as symlink handling or platform quirks,
- keep deterministic or isolated fixtures in tests.

## Process

Prefer `process::*` over `tokio::process`.

Migration checklist:

- replace command spawning,
- handle structured exit and shutdown,
- verify stdio flows,
- test cancellation and reaping behavior.

Known caveat:

- PTY-oriented workflows are explicitly unsupported and need an external crate or a kept boundary.

## Signal

Prefer `signal::*` over `tokio::signal`.

Important caveat:

- Unix coverage is the strongest path,
- Windows signal coverage is still partial in the repo's matrix.

If Windows signal semantics are central to the app, validate them explicitly before claiming full native parity.
