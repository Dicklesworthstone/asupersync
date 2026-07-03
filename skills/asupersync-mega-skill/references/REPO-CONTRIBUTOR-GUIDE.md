# Working Inside the Asupersync Repo

Rules from AGENTS.md for AI coding agents working in this codebase.

## Critical Rules

1. **NEVER delete files** without express written permission. Even files you created.
2. **NEVER run destructive commands** (`git reset --hard`, `git clean -fd`, `rm -rf`) without explicit user authorization.
3. **Work only on `main`**. Do not create branches or worktrees. In the live
   Asupersync workflow, the legacy compatibility ref is mirrored only by the
   exact command in `AGENTS.md`; do not add branch-name references to docs or
   code.
4. **Rust 2024 edition**, nightly toolchain (pinned in `rust-toolchain.toml`).
5. **Cargo only** -- no other package manager.
6. **`#![deny(unsafe_code)]`** with per-module `#[allow(unsafe_code)]` where required.
7. **No backwards compatibility** concern -- early development, do things the right way.

## Forbidden Crates

Keep Tokio and Tokio-backed framework crates out of core `src/`: `tokio`,
`hyper`, `reqwest`, `axum`, `async-std`, `smol`, and crates that pull Tokio into
production core. Scoped exceptions live in `asupersync-tokio-compat/`,
conformance scaffolding, fuzz/bench/differential support, and explicitly
feature-gated adapter edges. `tower` can be an optional adapter surface; do not
turn it into the core runtime story.

## Code Editing Discipline

- **Never** run scripts that process/change code files. Make changes manually.
- **Never** create file variations (e.g., `mainV2.rs`, `main_improved.rs`).
- New files only for genuinely new functionality. Bar is very high.
- Revise existing code files in place.

## Compiler Checks (Mandatory After Code Changes)

```bash
export CARGO_TARGET_DIR=/tmp/asupersync-cargo-target-$USER-$(date +%s)
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo check --all-targets
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo clippy --all-targets -- -D warnings
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo fmt --check
```

This is the default live-`AGENTS.md` lane for substantive changes. Use a narrower
command only when the user, bead, or proof-lane manifest explicitly narrows the
scope. Do not silently fall back to local builds when remote `rch` proof is
required; preserve the failing command and blocker instead.

Repo-internal proof is not the same thing as a downstream migration inventory.
The helper script `scripts/audit-target.sh` may run local `cargo tree` for an
arbitrary target project; it does not satisfy an Asupersync repo proof lane.

## Testing

Every module includes inline `#[cfg(test)]` unit tests. Tests must cover:
- Happy path
- Edge cases (empty input, max values, boundary conditions)
- Error conditions

For concurrency-sensitive behavior, prefer deterministic lab-runtime tests.

### Test Commands

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo test -p asupersync <filter>
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo test -p asupersync-macros
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo test -p asupersync-conformance
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo test -p frankenlab
```

### Test Categories

| Area | Focus |
|------|-------|
| `types/` | IDs, outcomes, budgets, policies, serialization round-trips |
| `record/` | Task/region/obligation record creation, state transitions |
| `runtime/` | Scheduler fairness, state management, region lifecycle |
| `cx/` | Capability context, scope API, structured concurrency contracts |
| `channel/` | Two-phase reserve/send, MPSC/oneshot, cancel-correctness |
| `sync/` | Mutex, RwLock, Semaphore, Pool, Barrier, OnceLock -- cancel-awareness |
| `combinator/` | Join, race, timeout, bulkhead, retry -- loser drain correctness |
| `cancel/` | Cancellation protocol, symbol cancel, drain/finalize lifecycle |
| `obligation/` | Permit/ack/lease commit/abort, no-leak invariant |
| `lab/` | Virtual time, deterministic scheduling, DPOR, oracles |
| `net/` + `io/` | Async I/O adapters, socket integration |
| `http/` | HTTP/1.1, HTTP/2 protocol correctness |
| `codec/` | Framing, encoding/decoding round-trips |
| `conformance/` | Cross-component conformance suite |
| `benches/` | Scheduler, timer wheel, reactor, cancel/drain, RaptorQ |

### E2E and Benchmarks

```bash
./scripts/run_all_e2e.sh
NO_PREFLIGHT=1 ./scripts/run_raptorq_e2e.sh --profile fast --bundle
cargo bench --bench scheduler_benchmark
cargo bench --bench timer_wheel
```

## Feature Flags

| Flag | What |
|------|------|
| `proc-macros` | Default proc-macro surface: `scope!`, `spawn!`, `join!`, `join_all!`, `race!` |
| `nightly-outcome-try` | Default nightly `Outcome` ergonomics |
| `test-internals` | Opt-in test helpers -- NOT for production |
| `runtime-metrics` / `metrics` | Runtime counters and telemetry surfaces |
| `wasm-browser-*` | Canonical browser profiles |
| `tls` / `tls-native-roots` / `tls-webpki-roots` | TLS via rustls |
| `sqlite` / `postgres` / `mysql` | Database clients |
| `quic` / `http3` / `atp-cli` | Feature-gated QUIC/H3/ATP surfaces; `atp-cli` implies TLS |
| `io-uring` | Linux io_uring reactor |
| `tower` | Tower Service adapter |
| `lock-metrics` | ContendedMutex tracking |
| `loom-tests` | Loom verification |
| `simd-intrinsics` | AVX2/NEON GF(256) for RaptorQ |

## Output Style

- Core code should not write to stdout/stderr
- Use structured tracing via `Cx::trace` for observability
- Keep tests deterministic; avoid time-based logging outside lab runtime

## Key Dependencies

| Crate | Purpose |
|-------|---------|
| `thiserror` | Error derivation |
| `crossbeam-queue` | Lock-free queues |
| `parking_lot` | Fast sync primitives |
| `polling` | Portable epoll/kqueue/IOCP |
| `slab` | Pre-allocated storage |
| `smallvec` | Stack-allocated vectors |
| `pin-project` | Safe pin projections |
| `serde` + `serde_json` | Serialization |
| `socket2` | Low-level sockets |
| `rustls` | TLS (optional) |
| `rusqlite` | SQLite (optional) |
| `proptest` | Property testing (dev) |
| `criterion` | Benchmarks (dev) |

## Dependency Policy

- Prefer `std`/`core` and small, focused crates
- No other executor/runtime in core
- New crates must preserve determinism in lab runtime
- No ambient globals

## Multi-Agent Environment

Other agents may be working on the project simultaneously. Treat their changes as your own -- never stash, revert, overwrite, or disturb their work.

Start repo-internal sessions by reading `AGENTS.md` and `README.md`, then use
Agent Mail reservations before editing. Reserve exact files/globs, tie
reservations and messages to the bead id when one exists, and avoid broad
claims.

## Session Completion Protocol

1. File issues for remaining work
2. Run quality gates (if code changed)
3. Update issue status
4. Pull/rebase, sync beads, and commit path-limited changes.
5. Push `main`, then mirror the legacy compatibility ref with
   `git push origin main:master` when the live repo instructions require it.
6. Release reservations and hand off context. If push/rebase is blocked by peer
   state, report the exact command and blocker.

## Key Documentation

| File | Purpose |
|------|---------|
| `asupersync_plan_v4.md` | Design bible and core invariants |
| `asupersync_v4_formal_semantics.md` | Small-step operational semantics |
| `TESTING.md` | Comprehensive testing guide |
| `TESTING_FOR_AGENTS.md` | Current testing instructions for agents |
| `AGENTS.md` | AI agent guidelines (source of truth) |
| `README.md` | Project overview |
| `CHANGELOG.md` | Current release notes, Unreleased scope, and tag/release caveats |
| `artifacts/api_surface_map_v1.json` | Machine-readable public API map |
| `artifacts/proof_lane_manifest_v1.json` | Proof-lane source of truth |
| `artifacts/proof_status_snapshot_v1.json` | Current proof status snapshot |
| `artifacts/phase6_methodology_gate_enforcement_contract_v1.json` | Direct-main vs PR/release-review gate contract |
| `docs/atp_bench_matrix_spec.md` | ATP benchmark acceptance contract |
| `scripts/atp_bench/MATRIX.md` | Current ATP matrix ledger |

## RCH (Remote Compilation Helper)

`rch` offloads cargo builds to remote workers:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo build --release
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo test
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=$CARGO_TARGET_DIR cargo clippy
rch doctor       # health check
rch workers probe --all  # test connectivity
```

If unavailable, preserve the remote-proof failure instead of quietly proving a
different local command.

## Phase 6 / Release-Gate Artifacts

For hot-path, safety, release-review, or proof-policy work, read the current
README Phase 6 policy-gate section before choosing validation. Triggered gates
may require scoped `rch` benchmark output, golden checksums, flamegraphs, or
proof-note artifacts committed with the change. A green broad `check`/`clippy`
run is not a substitute for a triggered artifact gate.

Do not infer release status from `Cargo.toml` version alone. `CHANGELOG.md`
separates published GitHub Releases from plain tags and active Unreleased work;
verify tags, releases, Cargo/package metadata, and changelog together.

## UBS (Ultimate Bug Scanner)

```bash
ubs file.rs                          # specific file
ubs $(git diff --name-only --cached) # staged files
ubs --ci --fail-on-warning .         # CI mode
```

Exit 0 = safe. Exit >0 = fix and re-run.

## Beads Issue Tracking

```bash
br ready              # show ready work
br list --status=open # all open
br show <id>          # issue details
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason "Completed"
br sync --flush-only  # export (no git ops)
```

Always `br sync --flush-only && git add .beads/` before ending sessions.

## ATP Benchmark Discipline

For ATP work, `scripts/atp_bench/run_matrix_cell.sh`,
`scripts/atp_bench/score_matrix.py`, `scripts/atp_bench/MATRIX.md`,
`docs/atp_bench_matrix_spec.md`, and `docs/atp_rq_beat_rsync_ledger.md` are the
evidence spine. Do not claim a win unless the current matrix cell beats tuned
rsync under the requested crypto/auth/link conditions with SHA/tamper checks and
timing/byte evidence.

A single fresh matrix cell can support only that scoped cell/regression claim.
Headline ATP claims such as "beats rsync" require whole-matrix evidence and must
report weak spots, stale cells, failures, and no-claim boundaries instead of
cherry-picking favorable cells.
