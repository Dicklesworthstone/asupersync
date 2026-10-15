# Service-Worker Broker Consumer Fixture

Fixture bead:
- `asupersync-n6kwt.7.2` for the maintained browser-run service-worker broker lane

Purpose:
- validate the bounded service-worker broker helpers against real browser service-worker lifecycle behavior
- prove the package keeps direct runtime fail-closed on service-worker hosts while still allowing bounded broker registration, durable work descriptors, and durable handoff records
- exercise restart-style durable reconciliation by reopening the broker store after writes and verifying the persisted registration, work, and handoff records remain readable
- prove mismatch diagnostics stay explicit by forcing a broker-protocol-version mismatch without widening the service-worker support claim
- clean up durable broker state and unregister the service worker so the fixture remains replayable

This fixture is executed through:
- `scripts/validate_service_worker_broker_consumer.sh`

The validation script copies this fixture into a temporary workspace and installs
local package copies to keep runs deterministic and side-effect free.

## What This Example Shows

- `src/main.ts`
  browser main-thread bootstrap that registers the maintained service worker,
  waits for control, asks it to run the bounded broker scenario, records the
  rendered result, and unregisters the worker after the handoff/cleanup report
- `src/service-worker.ts`
  service-worker host code that proves `detectBrowserServiceWorkerBrokerSupport()`
  stays truthful, writes broker registration/work/handoff records with
  `BrowserServiceWorkerBrokerStore`, reopens the durable store to prove restart
  reconciliation inputs stay present, explicitly calls `registerBroker()`,
  `persistBrokerWork()`, and `persistDurableHandoff()`, forces a protocol
  mismatch diagnostic, and clears the durable namespace before returning the
  summary
- `scripts/check-bundle.mjs`
  verifies the built bundle still carries the service-worker broker markers
  (`service-worker-broker-bootstrap`,
  `service-worker-broker-registration`,
  `service-worker-broker-handoff`,
  `service-worker-broker-mismatch`,
  `service-worker-broker-cleanup`) and preserves the
  `service_worker_direct_runtime_not_shipped` reason code
- `scripts/check-browser-run.mjs`
  serves the built fixture, launches Chromium, waits for the page to render the
  final broker result, and asserts that registration, restart-style reopen,
  durable handoff, mismatch downgrade diagnostics, and cleanup all stay aligned

## Deterministic Validation

Run the maintained example through the canonical validation path:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_service_worker_broker_consumer.sh
```

The validation artifacts are emitted under:

```text
target/e2e-results/service_worker_broker_consumer/
```

The canonical validator writes both `summary.json` and `browser-run.json` so
future regressions can inspect the browser-observed broker lifecycle directly.
