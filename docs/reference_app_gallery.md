# Reference App Gallery

<!-- REFERENCE-APP-GALLERY:SOURCE -->

`artifacts/reference_app_gallery_v1.json` is the checked source of truth for
`asupersync-idea-wizard-fifth-wave-3gaiun.8`.

This gallery is a proof-backed index over existing examples, fixtures, docs, and
e2e tests. It does not create new production applications and does not turn
reference coverage into a production-readiness claim.

<!-- REFERENCE-APP-GALLERY:JOURNEYS -->

## Journeys

| journey | support class | primary evidence |
|---|---|---|
| `http-db-service` | checked reference | HTTP and database e2e tests plus reference-service docs |
| `websocket-stream` | checked reference | WebSocket e2e, conformance, and protocol goldens |
| `background-worker-graceful-drain` | checked reference | SPORK supervised app plus graceful-drain tests |
| `browser-client` | fixture-backed | Rust browser consumer fixture and browser matrix contracts |
| `distributed-remote-cluster` | checked reference | distributed e2e, remote invariants, and snapshot goldens |
| `atp-loopback-transfer` | blocked adapter | ATP loopback tests with fail-closed adapter caveats |

Rows with `blocked-adapter` support class must render as blocked. They are kept
in the gallery because they are valuable user journeys, but they cannot be
presented as passing reference-app coverage.

<!-- REFERENCE-APP-GALLERY:LOGS -->

## Structured Logs

Every journey row must define deterministic log fields:
`journey_id`, `scenario_id`, `seed` or fixture identity, `proof_command`,
`support_class`, `outcome`, and `artifact_path`.

The gallery redaction policy is `reference-app-gallery-redaction-v1`. Raw
request/response bodies, absolute host paths, secrets, tokens, credentials, and
passwords are forbidden in gallery logs.

<!-- REFERENCE-APP-GALLERY:VALIDATION -->

## Validation

Use the focused remote-only contract lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_reference_app_gallery" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test reference_app_gallery_contract --no-default-features -- --nocapture
```

Local Cargo fallback is not evidence for this contract.

<!-- REFERENCE-APP-GALLERY:NO-CLAIMS -->

## No-Claim Boundaries

This gallery does not create new production reference apps, run every journey,
prove production deployment readiness, prove broad workspace health, prove
release readiness, prove live RCH fleet availability, authorize local Cargo
fallback, or turn blocked adapter rows into passing coverage.
