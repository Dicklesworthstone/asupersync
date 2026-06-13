# Platform Capability Matrix

<!-- PLATFORM-CAPABILITY-MATRIX:SOURCE -->

This document is the human-readable companion to
`artifacts/platform_capability_matrix_v1.json` for
`asupersync-idea-wizard-fifth-wave-3gaiun.12`.

The matrix records the coarse support policy for four host roles:

| platform id | host role | scope |
|---|---|---|
| `linux` | native | Linux runtime with epoll, optional io_uring, filesystem, process, signal, and feature-gated TLS lanes. |
| `macos_bsd` | native | BSD-family runtime with kqueue and Unix filesystem, process, and signal semantics. |
| `windows` | native | Windows runtime with IOCP and narrower process/signal semantics. |
| `browser` | wasm host | Browser package and host APIs. This is not native OS parity. |

The checked artifact is intentionally conservative. It is a routing and
claim-boundary map, not a live platform probe.

<!-- PLATFORM-CAPABILITY-MATRIX:STATUS-POLICY -->

## Status Policy

| status | counts as supported | pass verdict allowed | meaning |
|---|---:|---:|---|
| `supported` | yes | yes | The capability is admitted for the platform when its cited proof lane is fresh. |
| `feature_gated` | no | no | A feature, package, target, or host lane must be selected and proven separately. |
| `partial` | no | no | The platform has a narrower subset; the row must render as skip or fail until a narrower claim is made. |
| `unsupported` | no | no | The host does not provide the capability. |
| `not_applicable` | no | no | The capability belongs to another host role. |

Only `supported` rows may include `pass` in `runtime_verdicts`.
`feature_gated`, `partial`, `unsupported`, and `not_applicable` rows are kept so
operators can see why a feature is unavailable, but they never count as green
support evidence.

## Capability Families

| family | examples |
|---|---|
| `reactor` | epoll, kqueue, IOCP, browser reactor, io_uring feature lane |
| `filesystem` | native file operations, sparse files, symlinks, atomic rename, browser storage exclusion |
| `process` | child process management, wait, pipe, and cancellation cleanup |
| `signal` | Unix signal streams, Windows subset, Ctrl+C, graceful shutdown |
| `tls` | rustls feature lane and root-store policy |
| `browser` | fetch, WebSocket, storage, entropy, time, and host API capabilities |
| `toolchain` | Rust 2024 nightly, native targets, and wasm package constraints |

The contract test at `tests/platform_capability_matrix_contract.rs` verifies that
each required capability covers every required platform, cites live source or
docs paths, and carries a nonempty no-claim boundary.

## Validation

Use the remote-only proof lane declared in the artifact:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_platform_capability_matrix" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test platform_capability_matrix_contract -- --nocapture
```

Local Cargo fallback is not evidence for this contract.

<!-- PLATFORM-CAPABILITY-MATRIX:NO-CLAIMS -->

## No-Claim Boundaries

This matrix does not prove broad workspace health, release readiness, live RCH
fleet availability, performance, runtime correctness, or cross-platform e2e
success. It also does not replace ATP host probes, browser package fixture
evidence, or feature-specific proof lanes such as `io-uring`, `tls`, and
wasm/browser support.

Skipped, partial, feature-gated, unsupported, and not-applicable rows are
negative or deferred evidence. They are never support evidence.
