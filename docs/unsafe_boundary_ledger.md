# Unsafe Boundary Ledger

`artifacts/unsafe_boundary_ledger_v1.json` is the canonical inventory of
unsafe-code boundaries in the committed source tree. The ledger exists because
the workspace denies unsafe code by default, but still has legitimate narrow
exceptions for OS FFI, platform probes, target-specific SIMD, interior-mutability
primitives, test harnesses, fuzz targets, and satellite compatibility crates.

The ledger is an inventory and schema baseline. It is not a claim that every
platform-specific unsafe path was freshly executed on every host. UNSAFE-2 is
responsible for turning this baseline into a live-source contract test that
fails on unledgered unsafe additions or stale rows.

## Generation Scope

The v1 baseline was generated from committed `HEAD`, not from the dirty working
tree. That keeps the artifact reproducible from the commit that adds it and
avoids absorbing peer-owned uncommitted source edits into a tracker/artifact
commit.

The recorded scan ignores comments and string literals for unsafe syntax
matches. It records these site kinds:

- `allow_unsafe_code`
- `unsafe_block`
- `unsafe_fn`
- `unsafe_impl`
- `unsafe_trait`

## Row Schema

Each `sites[]` row must include:

- `site_id`: Stable identifier derived from the source path.
- `path`: Repository-relative Rust source path.
- `category`: Safety boundary class from the category table.
- `scope`: Current row granularity. The v1 rows are file-or-item boundaries.
- `feature_or_platform_gate`: Relevant `cfg` or Cargo feature context.
- `why_safe_rust_is_insufficient`: Why this boundary exists.
- `safety_invariant`: The invariant reviewers must preserve.
- `expected_evidence`: The evidence class required before relying on the row.
- `explicit_no_claims`: Boundaries that must not be inferred from this row.
- `operation_locators`: The unsafe/allow sites found in the path.

UNSAFE-2 may split broad file rows into narrower item rows when enforcement
needs per-block precision. If it does, it must keep stable identifiers or record
the migration in the child bead closeout.

## Category Evidence

| Category | Boundary | Expected evidence |
| --- | --- | --- |
| `reactor-ffi` | epoll, kqueue, io_uring, IOCP, and raw OS handles | RCH cargo checks/tests for the target-gated module plus focused reactor tests; platform-specific rows must state which hosts were not executed. |
| `filesystem-ffi` | raw file descriptors and platform filesystem handles | Focused filesystem tests plus ownership/drop assertions; no double-close or stale-handle reuse. |
| `process-signal-ffi` | PIDs, process groups, signals, waits, Windows events | Process lifecycle tests that tolerate exit races and do not assume global process state is stable. |
| `env-var-mutation` | process-global environment changes | Test isolation proof or serialized setup/restore; never cite as production runtime safety proof. |
| `platform-resource-metrics` | OS resource/load/socket table APIs | Bounds checks around returned sizes and focused metric parser/probe tests. |
| `simd-kernel` | target-feature-gated GF(256) kernels | Scalar parity tests, feature-gate proof, and architecture-specific RCH or documented no-host boundary. |
| `sync-internal-cell` | manual Send/Sync and interior mutable primitives | Loom, lab, or deterministic concurrency tests covering aliasing, drop, and wake protocol invariants. |
| `secret-memory-security` | zeroization and timing-security operations | Tests that prove the unsafe exists for security semantics and does not expose invalid references. |
| `database-test-or-ffi-boundary` | database protocol audit or invalid-data construction | Test-only confinement and sanitization/rejection assertions. |
| `network-ffi` | sockets and raw streams | Socket ownership and nonblocking setup tests. |
| `browser-boundary` | browser/wasm interop | Wasm/browser boundary tests or documented host limitation. |
| `compat-boundary` | satellite compatibility crate shims | Opt-in compatibility tests; must not weaken core runtime no-Tokio claims. |
| `conformance-boundary` | conformance binaries and vendor comparison helpers | Conformance-only tests; must not be cited as default production proof. |
| `fuzz-target` | fuzz harness raw wakers, pinning, or allocators | Fuzz harness build/smoke evidence; outside production runtime proof. |
| `test-or-lab-harness` | raw-waker and deterministic fixture helpers | Focused unit/lab tests; no production API claim. |
| `channel-test-boundary` | channel fixture extraction | Single-owner/drop invariant test for the fixture. |
| `stream-test-boundary` | stream fixture pinning or state access | Pin/ownership assertion in the fixture test. |
| `observability-test-boundary` | invalid telemetry/resource data construction | Sanitization/rejection tests only. |
| `atp-platform-boundary` | ATP platform capability or journal probes | Platform-gated RCH command or explicit no-host boundary. |

## Review Rules

New unsafe code is acceptable only when all of these are true:

1. The safe-Rust alternative was considered and is insufficient for the local
   boundary.
2. The new site has a ledger row with a concrete safety invariant.
3. The row names the evidence needed for its category.
4. The implementation uses the narrowest practical `#[allow(unsafe_code)]`
   scope. Prefer item-scope allows over file-scope allows when the boundary is
   narrow.
5. The proof lane or test evidence does not overclaim. Test-only, fuzz,
   conformance, compat, and platform-specific rows must say what they do not
   prove.

## Follow-Up Contract

UNSAFE-2 should add a checked scanner that compares live source against this
ledger and fails when:

- a new unsafe block, unsafe fn, unsafe impl, unsafe trait, or unsafe-code allow
  scope appears without a row;
- a row points at a removed or changed site;
- a broad allow scope has no child-site list or explicit local justification;
- diagnostics cannot identify the path, line, site kind, and suggested row
  skeleton.
