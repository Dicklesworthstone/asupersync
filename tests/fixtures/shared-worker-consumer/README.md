# Shared-Worker Coordinator Consumer Fixture

Fixture bead:
- `asupersync-n6kwt.6.2` for the maintained SharedWorker bootstrap/reuse/fallback lane
- `asupersync-n6kwt.6.3` for the bounded browser-run proof of churn and crash-recovery semantics

Purpose:
- validate the real-browser SharedWorker coordinator helpers against actual same-origin multi-page reuse
- prove the SharedWorker lane stays an optional topology optimization layered over the existing execution ladder rather than a widened semantics claim
- exercise explicit attach admission, topology snapshotting, client detach, protocol-version mismatch fallback, and crash-before-handshake fallback
- leave behind a deterministic browser-run validator that future regressions can replay directly

This fixture is executed through:
- `scripts/validate_shared_worker_consumer.sh`

The validation script copies this fixture into a temporary workspace and installs
local package copies to keep runs deterministic and side-effect free.

## What This Example Shows

- `src/main.ts`
  page bootstrap that asks `@asupersync/browser` to attach to a same-origin
  SharedWorker coordinator, records the selected mode and diagnostics, waits
  for multi-page reuse when requested, captures a topology snapshot through the
  public coordinator client, and closes the coordinator or fallback runtime
  explicitly
- `src/shared-worker.ts`
  shared-worker host code that accepts explicit handshake registration, tracks
  joined clients, emits topology snapshots, rejects protocol drift cleanly, and
  can intentionally terminate before responding so the browser-facing helper is
  forced onto its fallback lane
- `scripts/check-bundle.mjs`
  verifies the built bundle still carries the attach/reuse/mismatch/crash
  markers plus the topology and detach markers used by the maintained browser
  proof
- `scripts/check-browser-run.mjs`
  serves the built fixture, launches Chromium, opens two same-origin pages to
  prove real SharedWorker reuse, then exercises protocol mismatch and crash
  fallback scenarios against separate coordinator names

## Scenario Inventory

The maintained browser-run evidence publishes a `scenario_inventory` so release
gates can reason about the important failure families instead of treating this
fixture as a smoke test. The current inventory covers:

- `shared_worker_attach_baseline`
  proves a page can attach to the SharedWorker coordinator on the supported path
- `shared_worker_multi_page_reuse`
  proves two same-origin pages observe one coordinator topology with both
  clients present
- `shared_worker_protocol_mismatch_fallback`
  proves protocol drift fails closed to the fallback lane instead of attaching
  partially
- `shared_worker_attach_crash_fallback`
  proves a coordinator that disappears before answering the handshake is
  treated as a bounded bootstrap failure and downgraded explicitly
- `shared_worker_client_detach_cleanup`
  proves the fixture closes client handles explicitly after the browser-run
  proof instead of leaving ports attached indefinitely
- `shared_worker_client_churn_rejoin`
  proves a fresh same-origin client can reattach cleanly after earlier clients
  detach, without widening the direct-runtime claim
- `shared_worker_crash_recovery_reconnect`
  proves that after a crash-before-handshake downgrade, a later attach on the
  same worker name can start a fresh coordinator and return to the bounded
  SharedWorker lane

## Deterministic Validation

Run the maintained example through the canonical validation path:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_shared_worker_consumer.sh
```

The validation artifacts are emitted under:

```text
target/e2e-results/shared_worker_consumer/
```

The canonical validator writes both `summary.json` and `browser-run.json` so
future regressions can inspect the browser-observed attach, reuse, client
churn rejoin, mismatch, crash fallback, and crash-recovery reconnect behavior
directly.
