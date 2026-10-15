# Dedicated Worker Consumer Fixture

Fixture beads:
- `asupersync-18tbo.4` for the maintained dedicated-worker example and onboarding lane

Purpose:
- validate a real dedicated-worker consumer build against packaged Browser Edition outputs
- demonstrate the supported direct-runtime worker bootstrap path for `@asupersync/browser`
- make worker startup, message coordination, and shutdown explicit in maintained example code
- prove the no-throw `createBrowserRuntimeSelection()` / `createBrowserScopeSelection()`
  fallback story across truthful worker selection, preferred-lane mismatch, and
  lane-health demotion/recovery
- exercise a worker-safe IndexedDB round-trip plus explicit `BrowserArtifactStore`
  export, cleanup, quota-guard, and download-fallback behavior

This fixture is executed through:
- `scripts/validate_dedicated_worker_consumer.sh`

The validation script copies this fixture into a temporary workspace and installs
local package copies to keep runs deterministic and side-effect free.

## What This Example Shows

- `src/main.ts`
  main-thread bootstrap that spawns a dedicated worker, records the worker
  support snapshot, and requests graceful shutdown after the worker reports
  readiness
- `src/worker.ts`
  dedicated-worker bootstrap that detects direct-runtime support, initializes a
  Browser Edition runtime, proves `createBrowserRuntimeSelection()` and
  `createBrowserScopeSelection()` stay on the no-throw path, proves the bounded
  lane-health retry window first, then forces a lane-health demotion with
  `reportBrowserLaneUnhealthy()`, proves recovery with
  `resetBrowserLaneHealth()`, performs a `BrowserStorage` round-trip,
  persists/export-clears evidence through `BrowserArtifactStore`, proves
  `downloadArchive()` fails closed in workers, and reports shutdown completion
  back to the main thread
- `scripts/check-bundle.mjs`
  verifies the bundled app still carries the durable-storage and artifact-export
  markers plus the selection/demotion markers (`worker-runtime-selection-baseline`,
  `worker-scope-selection-preferred-main-thread`,
  `worker-runtime-selection-demoted`, `worker-runtime-selection-recovered`,
  `worker-artifact-download-unavailable`, `worker-artifact-quota-guard`)
- `scripts/check-browser-run.mjs`
  serves the built app, launches Chromium, waits for the dedicated worker to
  finish, and asserts the rendered browser-run state proves truthful worker-lane
  selection, no-throw preferred-lane mismatch handling, fail-closed health
  demotion, and healthy recovery

## Chaos scenario inventory

The maintained browser-run evidence publishes a `scenario_inventory` so release
gates can reason about the important failure families instead of treating this
fixture as a black-box smoke test. The current inventory covers:

- `worker_bootstrap_baseline`
  proves the direct dedicated-worker lane stays selected on the no-throw path
- `preferred_lane_mismatch_truthful_worker_selection`
  proves a requested main-thread preference still reports the truthful worker
  lane without throwing
- `worker_loss_retry_window`
  proves the first worker-loss signal stays inside the bounded retry window
- `worker_loss_fail_closed_demotion`
  proves exhausted retry budget demotes fail-closed instead of silently
  downgrading
- `prerequisite_drift_reason_precedence`
  proves current prerequisite drift reports the live prerequisite failure rather
  than stale demotion state
- `lane_health_recovery`
  proves `resetBrowserLaneHealth()` restores the dedicated-worker lane
- `graceful_shutdown_handoff`
  proves the worker and main thread reach `shutdown_complete` with shutdown
  reason `fixture-handoff-complete`

## Deterministic Validation

Run the maintained example through the canonical validation path:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh
```

The validation artifacts are emitted under:

```text
target/e2e-results/dedicated_worker_consumer/
```

The canonical validator writes `summary.json`, `browser-run.json`, and the build
log with artifact pointers under `artifacts`, plus stable `replay_commands` for
rerunning the maintained checks. `summary.json` preserves the
`scenario_inventory`, while `browser-run.json` carries the browser-observed
diagnostics for worker loss, demotion, prerequisite drift, recovery, and
shutdown.
