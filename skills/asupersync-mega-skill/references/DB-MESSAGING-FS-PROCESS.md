# Database, Messaging, Filesystem, Process, Signal

This file covers the broad system-integration surfaces beyond the core runtime.

## Database

Native database surfaces exist behind features:

- `database::sqlite`
- `database::postgres`
- `database::mysql`

Migration guidance:

- prefer native clients when doing full replacement,
- pass `&Cx` through transactional and query code,
- treat cancellation and deadlines as part of the API contract,
- make connection ownership and pooling explicit.

Important limitation:

- SQLx compile-time `query!` style macros are explicitly unsupported in the repo's migration matrix.
- If you depend on them today, either keep SQLx behind compat temporarily or redesign around native query paths.

## Messaging

Native messaging surfaces exist, but some areas remain partial.

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

Prefer `fs::*` over `tokio::fs`.

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
