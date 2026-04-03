# Stub/Placeholder Disposition Matrix (A1)

> Authoritative inventory for epic `asupersync-v2ofj7`.
> Frozen by SapphireHill on 2026-04-03.
> Each surface has exactly one disposition. Downstream tracks reference this file.

## Disposition Categories

| Code | Meaning | Closure Evidence Required |
|------|---------|--------------------------|
| **IMPLEMENT** | Surface needs real runtime behavior | Unit tests + E2E coverage |
| **CONVERGE** | Duplicate surface — choose one canonical owner | Ownership frozen, non-canonical reduced |
| **QUARANTINE** | Move to harness-only / test-only scope | cfg gate + documentation |
| **DOCUMENT** | Honest contract already exists, just needs truthful docs | Doc update + no stale language |
| **RETIRE** | Remove or deprecate the misleading public shape | Removal or #[deprecated] |
| **RESOLVED** | Already fixed (by prior agent or this session) | Verification probe in Z0a |

## Surface Inventory

### Surface 1: WASM boundary split-brain
- **Files**: `asupersync-wasm/src/{exports.rs, error.rs, types.rs}`
- **State**: Comment-only placeholders (6-22 lines each). `asupersync-browser-core` has the real implementation.
- **Disposition**: **CONVERGE** → Track B (B1→B2→B3)
- **Target**: `asupersync-browser-core` is canonical. `asupersync-wasm` either forwards or is deprecated.
- **Adjacent epic**: `asupersync-3qv04` (Browser Edition)

### Surface 2: quorum! macro placeholder
- **File**: `src/combinator/quorum.rs`
- **State**: **RESOLVED** — permanent `compile_error!` macro was removed by prior agent (bead `6yj6zn`).
- **Disposition**: **RESOLVED**
- **Evidence**: Macro no longer exists in source. Functional API `Quorum::new()` is complete.

### Surface 3: try_join! macro placeholder
- **File**: `src/combinator/timeout.rs`
- **State**: **RESOLVED** — permanent `compile_error!` macro was removed by prior agent (bead `3eztk2`).
- **Disposition**: **RESOLVED**
- **Evidence**: Macro no longer exists. Functional API `Scope::join()` with FailFast is complete.

### Surface 4: TLS compute_spki_sha256
- **File**: `src/tls/types.rs:478-491`
- **State**: **RESOLVED** — real implementation using `x509_parser` + `ring::digest` exists when `tls` feature enabled. cfg-off path returns proper "tls feature not enabled" error.
- **Disposition**: **RESOLVED** (bead `v2ofj7.4.1`)
- **Evidence**: Function parses X.509 DER, computes SHA-256 of SPKI. Feature-gated correctly.

### Surface 5: Kafka StubBroker harness contract
- **File**: `src/messaging/kafka.rs:490-623`
- **State**: Decision frozen for Track E: the brokerless path behind `#[cfg(not(feature = "kafka"))]` is a harness-only deterministic in-process broker shared by the producer and consumer fallback APIs. It exists for tests and contract validation, not as a production Kafka broker substitute.
- **Disposition**: **DOCUMENT** → Track E (E1→E2→E3)
- **Target**: E2 aligns public naming/feature-gating with the harness-only contract. E3 removes stale wording and makes the non-production status obvious anywhere this lane is described.

### Surface 6: remote.rs phase-0 API surface
- **File**: `src/remote.rs`
- **State**: Types and API shape exist. Network transport not implemented. Doc comments explicitly say "Phase 0" and "does not perform real network operations."
- **Disposition**: **IMPLEMENT** → Track F (F1→F2→F3)
- **Target**: Either implement transport-backed remote execution or explicitly mark the API as experimental/unsupported.

### Surface 7: Session types — typestate without transport
- **File**: `src/obligation/session_types.rs`
- **State**: Protocol typestate machinery exists and compiles. Send/recv advance type state but don't communicate over any real transport.
- **Disposition**: **IMPLEMENT** → Track G (G1→G2→G3)
- **Target**: Wire session channels to a concrete transport bridge, or explicitly document the typestate-only scope.

### Surface 8: Legacy UringReactor shim
- **File**: `src/runtime/reactor/uring.rs`
- **State**: Detached legacy source file. `src/runtime/reactor/mod.rs` does not include or re-export `src/runtime/reactor/uring.rs`, so `UringReactor` is not part of the live public export graph today. If retained, H2 must make that status explicit instead of leaving a misleading standalone shim on disk.
- **Disposition**: **RETIRE** → Track H (H2/v2ofj7.8.6)
- **Target**: Either remove/archive the detached shim or turn any remaining public story into an explicit deprecated alias to `IoUringReactor`.

### Surface 9: IoUringReactor cfg-off surface
- **File**: `src/runtime/reactor/io_uring.rs:1079+`
- **State**: `src/runtime/reactor/mod.rs` re-exports `IoUringReactor` on Linux targets. With `feature = "io-uring"` it is the real implementation; without that feature the same Linux-only public symbol intentionally returns `Unsupported`.
- **Disposition**: **DOCUMENT** → Track H (H3/v2ofj7.8.7)
- **Target**: Ensure docs and error messages are maximally clear. No code change needed.

### Surface 10: macOS/kqueue reactor stub
- **File**: `src/runtime/reactor/macos.rs:644-721`
- **State**: Detached duplicate source file. The live public `KqueueReactor` export comes from `src/runtime/reactor/kqueue.rs` via `src/runtime/reactor/mod.rs`; `src/runtime/reactor/macos.rs` is not in the current compiled module graph.
- **Disposition**: **DOCUMENT** → Track H (H4/v2ofj7.8.8)
- **Target**: Reconcile stale docs/comments/waivers so contributors do not mistake `macos.rs` for the active public backend surface.

## H1 Reactor Support Matrix (Frozen 2026-04-03)

This is the authoritative Track H public-contract snapshot. Downstream H2-H4 work
must preserve or deliberately update this matrix rather than inferring behavior
from detached source files.

| Target / feature | Public symbols in `runtime::reactor` | Live source | Current truthfulness target |
|------------------|--------------------------------------|-------------|-----------------------------|
| Linux | `EpollReactor` | `src/runtime/reactor/epoll.rs` | Always-available live Linux backend |
| Linux + `io-uring` feature | `IoUringReactor` | `src/runtime/reactor/io_uring.rs` | Real io_uring backend |
| Linux without `io-uring` feature | `IoUringReactor` | `src/runtime/reactor/io_uring.rs` | Intentional `Unsupported` export; H3 must keep docs/errors/tests honest |
| macOS / FreeBSD / OpenBSD / NetBSD / DragonFlyBSD | `KqueueReactor` | `src/runtime/reactor/kqueue.rs` | Live BSD-family backend |
| Windows | `IocpReactor` | `src/runtime/reactor/windows.rs` | Live Windows backend |
| `wasm32` | `BrowserReactor` | `src/runtime/reactor/browser.rs` | Live browser/host-event backend |
| Deterministic tests | `LabReactor` | `src/runtime/reactor/lab.rs` | Virtual replayable backend |
| Detached legacy file | none (`UringReactor` is not re-exported) | `src/runtime/reactor/uring.rs` | H2 cleanup target |
| Detached duplicate file | none (`macos.rs` is not re-exported) | `src/runtime/reactor/macos.rs` | H4 cleanup target |

### Surface 11: BrowserEntropy "stub" language
- **File**: `src/util/entropy.rs:135-154`
- **State**: **RESOLVED** — implementation is a real CSPRNG wrapper around `getrandom`. Language updated to "honest thin wrapper" by prior agent (bead `v2ofj7.4.3`).
- **Disposition**: **RESOLVED**
- **Evidence**: No stale "stub" language remains. Working implementation.

### Surface 12: AuthenticationTag cryptographic contract
- **File**: `src/security/tag.rs:15-247`
- **State**: **RESOLVED** — `AuthenticationTag` now uses a domain-separated HMAC-SHA256 over symbol identity and payload bytes. `zero()` remains only as an explicit invalid-test sentinel.
- **Disposition**: **RESOLVED** (bead `v2ofj7.4.2`)
- **Evidence**: `src/security/tag.rs` computes/verifies HMAC-SHA256 directly and the stale phase-0 stand-in language is removed from security docs.

### Surface 13: Conformance panic-based dummies
- **File**: `conformance/src/runner.rs:950-1220`
- **State**: 29 instances of `panic!("dummy ...")` across DummyMpscSender, DummyFile, DummyTcpListener, DummyTcpStream, DummyUdpSocket, etc.
- **Disposition**: **QUARANTINE** → Track I (I2/v2ofj7.9.2)
- **Target**: Replace panic!() with `Err(Unsupported)` or wire real Asupersync backends.

## Hygiene Surfaces (not from original audit, added during planning)

### Surface 14: Stray artifacts
- **Files**: `src/a.out`, `src/test_multipart_panic.rs`
- **Disposition**: **RESOLVED** (bead `5js195`)
- **Evidence**: Files deleted 2026-04-03.

### Surface 15: Crate-level `#![allow(dead_code)]`
- **Files**: `src/lib.rs:55`, `src/messaging/subject.rs:3`
- **Disposition**: **RETIRE** → bead `ir13xz`
- **Target**: Remove crate-level suppression, fix all resulting warnings, add `#![deny(dead_code)]`.

### Surface 16: transport/mock unconditionally public
- **File**: `src/transport/mod.rs:8`
- **Disposition**: **RESOLVED** (bead `lf1lfv`)
- **Evidence**: Module gated behind `test-internals` by YellowCanyon.

### Surface 17: unimplemented!() in test harnesses
- **Files**: `examples/test_manual.rs:18`, `tests/split_utf8_read_line.rs:18`
- **Disposition**: **IMPLEMENT** → Track I (I1/v2ofj7.9.1)
- **Target**: Replace `unimplemented!()` with `Poll::Ready(Ok(()))` or proper delegation.

### Surface 18: API skeleton in project root
- **File**: `asupersync_v4_api_skeleton.rs`
- **Disposition**: **RETIRE** → Track I (I3/v2ofj7.9.3)
- **Target**: Move to `docs/design/` or archive.

## Disposition Summary

| Disposition | Count | Surfaces |
|-------------|-------|----------|
| RESOLVED | 7 | #2, #3, #4, #11, #12, #14, #16 |
| IMPLEMENT | 3 | #6, #7, #17 |
| DOCUMENT | 3 | #5, #9, #10 |
| CONVERGE | 1 | #1 |
| QUARANTINE | 1 | #13 |
| RETIRE | 3 | #8, #15, #18 |
| **Total** | **18** | |

## Track-to-Surface Mapping

| Track | Surfaces | Dispositions |
|-------|----------|-------------|
| A | This document | — |
| B | #1 | CONVERGE |
| C | #2, #3 | RESOLVED (both done) |
| D | #4, #11, #12 | #4 RESOLVED, #11 RESOLVED, #12 RESOLVED |
| E | #5 | DOCUMENT |
| F | #6 | IMPLEMENT |
| G | #7 | IMPLEMENT |
| H | #8, #9, #10 | RETIRE, DOCUMENT, DOCUMENT |
| I | #13, #17, #18 | QUARANTINE, IMPLEMENT, RETIRE |
| Z | All | Verification of above |
| Hygiene | #14, #15, #16 | #14 RESOLVED, #15 RETIRE, #16 RESOLVED |
