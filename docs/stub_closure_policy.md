# Stub Closure Policy (A2)

> Defines what "resolved" means for each disposition category.
> Consumed by Track Z for scan ratchets and closure verification.
> Companion to `docs/stub_disposition_matrix.md`.

## Policy by Disposition

### IMPLEMENT — Surface needs real runtime behavior

**Closed when:**
1. Implementation exists and handles happy path, error path, and cancellation.
2. Unit tests cover: normal operation, error conditions, edge cases (empty input, max values).
3. Doc comments describe the actual behavior (no "Phase 0" or "placeholder" language).
4. `cargo check --all-targets` clean.

**Regression gate:** Code review + test coverage.

### CONVERGE — Duplicate surface reduced to one owner

**Closed when:**
1. Canonical owner chosen and documented.
2. Non-canonical crate either forwards to canonical, is deprecated, or has non-misleading role.
3. No two crates independently claim the same public boundary.

**Regression gate:** Workspace-level build check.

### QUARANTINE — Moved to harness/test-only scope

**Closed when:**
1. Code is behind `#[cfg(test)]` or `#[cfg(feature = "test-internals")]`.
2. No production code path can reach the quarantined surface.
3. Behavior is explicit (returns errors) not silent (panic/noop).

**Regression gate:** `cargo check --no-default-features` must not see the surface.

### DOCUMENT — Honest contract exists, needs truthful docs

**Closed when:**
1. Doc comments and module-level docs accurately describe current behavior.
2. No stale "placeholder", "stub", "Phase 0", or "not yet implemented" language.
3. Feature-gated paths have clear error messages naming the missing feature.

**Regression gate:** Text scan for stale language patterns.

### RETIRE — Remove or deprecate misleading public surface

**Closed when:**
1. Surface is either deleted, marked `#[deprecated]`, or converted to type alias.
2. No standalone "always returns Unsupported" method impls remain.
3. Migration guidance exists if the surface was ever public.

**Regression gate:** The live export graph in `src/runtime/reactor/mod.rs` must not
re-export `UringReactor`, and any remaining `UringReactor` definition must be an
explicit deprecated alias or otherwise clearly non-authoritative.

### RESOLVED — Already fixed by prior work

**Closed when:**
1. Fix verified by structural probe in `tests/stub_resolution_audit.rs`.
2. Audit record exists in `audit_index.jsonl` or disposition matrix.

**No further action needed.**

## Scan Rules (consumed by Z1)

| Rule | Pattern | Violation If |
|------|---------|-------------|
| No crate-level dead_code | `#![allow(dead_code)]` in lib.rs | Present |
| No permanent compile_error! | `compile_error!` in combinator/ | Missing cfg guard within 5 lines above |
| No stray binaries | `*.out, *.exe, *.o` in src/ | Any match |
| No todo! in production | `todo!()` in src/ (non-comment) | Any match |
| No unimplemented! in production | `unimplemented!()` in src/ (non-comment) | Any match |
| Mock is gated | `pub mod mock` in transport/mod.rs | Missing cfg attribute |
| Skeleton not in root | `asupersync_v4_api_skeleton.rs` | File exists at root |

## Waiver Format

Intentional exceptions documented in `.stub-allowlist.txt`:

```
# Format: path:symbol (reason) [disposition]
src/runtime/reactor/io_uring.rs:IoUringReactor (Linux export; without `io-uring` feature methods return Err(Unsupported)) [DOCUMENT]
src/messaging/kafka.rs:StubBroker (cfg(not(feature = "kafka")) harness broker) [DOCUMENT]
src/transport/mock.rs:SimNetwork (cfg(any(test, feature = "test-internals")) test double) [QUARANTINE]
conformance/src/runner.rs:Dummy* (test-only runtime doubles) [QUARANTINE]
```

Detached duplicate or legacy files such as `src/runtime/reactor/uring.rs` and
`src/runtime/reactor/macos.rs` are not waiver-eligible `DOCUMENT` surfaces; they
remain explicit cleanup targets under Track H until reconciled.

## Audit Record Format

After each track closes, append to `audit_index.jsonl`:

```json
{"file":"<path>","lines":0,"batch":999,"date":"YYYY-MM-DD","agent":"<name>","verdict":"RESOLVED","bugs":0,"notes":"Stub resolution: <surface#> <disposition>"}
```
