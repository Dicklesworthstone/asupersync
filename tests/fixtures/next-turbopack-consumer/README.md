# Next Turbopack Maintained Example

Fixture beads:
- `asupersync-3qv04.6.3` for packaged-consumer validation
- `asupersync-3qv04.9.3.3` for the maintained Next example with explicit client/bridge split

Purpose:
- publish the maintained Next.js App Router example for Browser Edition
- demonstrate the supported client-hydrated direct-runtime path
- make the server and edge bridge-only boundary explicit in code
- validate package import resolution from `@asupersync/next`

This fixture is executed through:
- `scripts/validate_next_turbopack_consumer.sh`

The validation script copies this fixture into a temporary workspace and installs
local package copies to keep runs deterministic and side-effect free.

## What This Example Shows

- `app/page.jsx`
  server-rendered overview page that makes the support boundary explicit
- `app/client-runtime-panel.jsx`
  client component that boots Browser Edition through
  `createNextBootstrapAdapter(...)`
- `app/api/server-bridge/route.js`
  serialized node/server bridge example using `createNextServerBridgeAdapter(...)`
- `app/api/edge-bridge/route.js`
  edge route that reports direct-runtime diagnostics and keeps the edge path
  bridge-only

## Boundary Rules

- Client components may create and own the Browser Edition runtime directly.
- Server components and route handlers must stay on serialized bridge-only
  boundaries.
- Edge routes must not initialize Browser Edition directly; this example returns
  diagnostics that make that restriction visible instead.

## Deterministic Validation

Run the maintained example through the canonical validation path:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_next_turbopack_consumer.sh
```

The validation artifacts are emitted under:

```text
target/e2e-results/next_turbopack_consumer/
```
