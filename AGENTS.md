# AGENTS.md — asupersync

> Guidelines for AI coding agents working in this Rust async runtime codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Git Branch: ONLY Use `main`, NEVER `master`

**The default branch is `main`. The `master` branch exists only for legacy URL compatibility.**

- **All work happens on `main`** — commits, PRs, feature branches all merge to `main`
- **Never reference `master` in code or docs** — if you see `master` anywhere, it's a bug that needs fixing
- **The `master` branch must stay synchronized with `main`** — after pushing to `main`, also push to `master`:
  ```bash
  git push origin main:master
  ```

**If you see `master` referenced anywhere:**
1. Update it to `main`
2. Ensure `master` is synchronized: `git push origin main:master`

---

## RULE 2: NO GIT BRANCHES. NO GIT WORKTREES. EVER.

**`main` is the one and only branch. Period.** There is no exception. There is no "just for this one little thing." There is no "temporary" branch. There is no "short-lived" worktree. There is **no justification** a branch or a worktree can have that overrides this rule.

This project has exactly **one** source of truth: `main`. We want it to always carry the latest, most optimized, most correct, most mature code. Every commit goes directly to `main`. Every agent works on `main`. Every build and test runs against `main`.

### FORBIDDEN — zero tolerance

Any of the following, by any agent, for any reason, is a violation:

- `git branch <anything-other-than-main>` — creating a new branch
- `git checkout -b <foo>` / `git switch -c <foo>` — creating and switching to a new branch
- `git worktree add ...` — creating a worktree (with or without `--detach`, with or without a branch name)
- Pushing a non-main ref to `origin` (`git push origin <foo>`, `git push origin HEAD:<foo>`, `git push --set-upstream origin <foo>`)
- Creating pull requests, draft PRs, or any "feature branch" pattern
- Per-agent / per-pane / per-bead / per-task branches like `pane-7-fix-x`, `codex/<uuid>-*`, `claim-<bead>`, `close-<bead>`, etc.
- Working in a scratch clone at `/tmp/asupersync-*` or `/data/projects/asupersync-*` to "isolate" changes
- Any tool, harness, or automation that creates branches or worktrees as a side effect. If you find one, disable it or change it to operate on `main` directly. **The harness does not get a pass.**

### WHY THIS RULE EXISTS

When agents proliferate branches and worktrees:

- Real accretive work gets stranded on branches that nobody remembers to merge.
- Disk usage explodes — each full worktree is ~6 GB; dozens of them fill the disk and starve `rch`.
- Context fragments — different agents end up editing stale snapshots of the same file.
- The "single source of truth" invariant of the project is broken, and we stop being able to answer "what is the current state of the code" with one command.
- Conflict resolution explodes — once N branches exist, merging them costs more than writing the code from scratch.

The project has already been bitten by this, repeatedly, at scale. The user has had to manually reconstruct state from chaos. **Never again.**

### WHAT YOU DO INSTEAD

- **Commit to `main` directly.** If your work-in-progress isn't ready to commit, don't commit yet — keep it in your working tree.
- **Coordinate via MCP Agent Mail + advisory file reservations.** Reserve the files or globs you are about to edit with `file_reservation_paths(...)` and release them when done. That is the isolation mechanism for this project. It is the only isolation mechanism for this project.
- **Use bead IDs + reservations as your "branch."** The conceptual "feature branch" of a bead like `asupersync-jp6pq9` is: (1) the bead itself, (2) a file reservation on the files it touches, (3) a commit to `main` referencing `br-asupersync-jp6pq9` in the subject. That's it. No branch object in git needs to exist.
- **Rebase / stash instead of branching.** If you need to pause work to pull in others' changes, `git fetch && git rebase origin/main` or `git stash` — never `git switch -c wip`.

### ENFORCEMENT

If you see a branch other than `main` (local or remote), a worktree other than the project root, or a scratch clone at `/tmp/asupersync-*` or `/data/projects/asupersync-*`:

1. **Stop whatever else you were doing.**
2. Audit every non-main branch and worktree for commits / uncommitted work that is *not yet on main*.
3. Cherry-pick (or port by hand) any truly unique accretive work onto `main`.
4. `git worktree remove --force <path>` every non-main worktree.
5. `git branch -D <name>` every non-main local branch.
6. `git push origin --delete <name>` every non-main remote branch.
7. Commit, push, and sync `master` from `main`.
8. Tell the user in your next reply what you cleaned up.

Do all of this *before* starting any other task. There is no task in this project more important than not relapsing into the branch-proliferation failure mode.

---

## Toolchain: Rust & Cargo

We only use **Cargo** in this project, NEVER any other package manager.

- **Edition:** Rust 2024 (nightly required — see `rust-toolchain.toml`)
- **Dependency versions:** Explicit versions for stability; keep the set minimal
- **Configuration:** Cargo.toml workspace with members pattern
- **Unsafe code:** Denied by default (`#![deny(unsafe_code)]`) — specific modules that require unsafe (e.g., epoll reactor FFI) can use `#[allow(unsafe_code)]`

### Async Runtime: THIS IS IT (NO TOKIO)

**This project IS the async runtime. Tokio and the entire tokio ecosystem are FORBIDDEN.**

- **Structured concurrency**: `Cx`, `Scope`, `region()` — no orphan tasks
- **Cancel-correct channels**: Two-phase `reserve()/send()` — no data loss on cancellation
- **Sync primitives**: `asupersync::sync::Mutex`, `RwLock`, `OnceCell`, `Semaphore`, `Pool` — cancel-aware
- **Deterministic testing**: `LabRuntime` with virtual time, DPOR, oracles
- **Capability security**: All effects flow through explicit `Cx`; no ambient authority

**Forbidden crates**: `tokio`, `hyper`, `reqwest`, `axum`, `tower` (tokio adapter only — the `tower` feature flag exists for trait compat), `async-std`, `smol`, or any crate that transitively depends on tokio.

**Pattern**: All async functions take `&Cx` as first parameter. The `Cx` flows down through structured concurrency scopes.

### Dependency Policy

- Prefer `std`/`core` and small, focused crates
- **Do not** introduce another executor/runtime into core
- Any new crate must preserve determinism in the lab runtime and avoid ambient globals
- Phase 0: Dependencies added must preserve determinism in the lab runtime

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `thiserror` | Ergonomic error type derivation |
| `crossbeam-queue` | Lock-free concurrent queues |
| `parking_lot` | Fast synchronization primitives |
| `polling` | Portable epoll/kqueue/IOCP polling |
| `slab` | Pre-allocated storage for fixed-size records |
| `smallvec` | Stack-allocated small vectors |
| `pin-project` | Safe pin projections |
| `serde` + `serde_json` | Serialization |
| `socket2` | Low-level socket configuration |
| `rustls` | TLS support (optional, via `tls` feature) |
| `rusqlite` | SQLite async wrapper (optional, via `sqlite` feature) |
| `proptest` | Property-based testing (dev) |
| `criterion` | Benchmarking (dev) |
| `rayon` | Data parallelism for CPU-bound work (dev/bench only) |

### Workspace Members

| Crate | Purpose |
|-------|---------|
| `asupersync` | Main runtime crate — scheduler, regions, channels, sync, IO, net, HTTP |
| `asupersync-macros` | Proc macros for structured concurrency (`scope!`, `spawn!`, `join!`, `race!`) |
| `asupersync-browser-core` | Browser Edition Rust boundary crate for wasm-facing runtime/package surfaces |
| `asupersync-tokio-compat` | Legacy Tokio-boundary compatibility crate kept outside the core runtime feature graph |
| `conformance` | Conformance test suite for async runtime specifications |
| `franken_kernel` | FrankenSuite type substrate (`TraceId`, `DecisionId`, `PolicyId`, `SchemaVersion`) |
| `franken_evidence` | Canonical `EvidenceLedger` schema for FrankenSuite decision tracing |
| `franken_decision` | Decision Contract schema and runtime for FrankenSuite |
| `frankenlab` | Deterministic testing harness: record, replay, and minimize concurrency bugs |
| `drop_unwrap_finder` | Audit/refactor helper CLI for finding drop/unwrap anti-patterns in the tree |

### Feature Flags

```toml
[features]
default = ["test-internals", "proc-macros"]
messaging-fabric = []          # Native FABRIC messaging lane
wasm-browser-preview = []      # Guarded browser-targeted compilation surface
wasm-runtime = ["wasm-browser-preview"]
browser-io = []
browser-trace = []
deterministic-mode = []
native-runtime = []
wasm-browser-dev = ["wasm-runtime", "browser-io"]
wasm-browser-prod = ["wasm-runtime", "browser-io"]
wasm-browser-deterministic = ["wasm-runtime", "deterministic-mode", "browser-trace"]
wasm-browser-minimal = ["wasm-runtime"]
test-internals = [...]         # Internal test helpers (Cx::new(), etc.) — NOT for production
metrics = [...]                # OpenTelemetry metrics provider
tracing-integration = [...]    # Structured logging and spans (zero-cost when disabled)
proc-macros = [...]            # scope!, spawn!, join!, race! macros
tower = [...]                  # Optional Tower adapter for AsupersyncService
trace-compression = [...]      # LZ4 compression for trace files
debug-server = []              # Debug HTTP server for runtime inspection
config-file = [...]            # TOML config file loading for RuntimeBuilder
lock-metrics = []              # ContendedMutex wait/hold time tracking
io-uring = [...]               # Linux io_uring reactor (kernel 5.1+)
tls = [...]                    # TLS support via rustls
tls-native-roots = [...]       # Native root certificates for TLS
tls-webpki-roots = [...]       # webpki root certificates for TLS
cli = [...]                    # CLI tooling (trace inspection)
sqlite = [...]                 # SQLite async wrapper with blocking pool
postgres = []                  # PostgreSQL async client with wire protocol
mysql = []                     # MySQL async client with wire protocol
quic = []                      # Native QUIC rollout surface
http3 = ["quic"]               # Native HTTP/3 rollout surface
kafka = [...]                  # Kafka client integration via rdkafka
compression = [...]            # HTTP response compression (gzip/deflate/Brotli)
simd-intrinsics = []           # Unsafe AVX2/NEON GF(256) kernels for RaptorQ
loom-tests = [...]             # Loom concurrency tests for scheduler verification
```

### Release Profile

Use the release profile defined in `Cargo.toml`. If you need to change it, justify the performance/size tradeoff and how it impacts determinism and cancellation behavior.

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files in this repo. Brittle regex-based transformations create far more problems than they solve.

- **Always make code changes manually**, even when there are many instances
- For many simple changes: use parallel subagents
- For subtle/complex changes: do them methodically yourself

### No File Proliferation

If you want to change something or add a feature, **revise existing code files in place**.

**NEVER** create variations like:
- `mainV2.rs`
- `main_improved.rs`
- `main_enhanced.rs`

New files are reserved for **genuinely new functionality** that makes zero sense to include in any existing file. The bar for creating new files is **incredibly high**.

---

## Backwards Compatibility

We do not care about backwards compatibility—we're in early development with no users. We want to do things the **RIGHT** way with **NO TECH DEBT**.

- Never create "compatibility shims"
- Never create wrapper functions for deprecated APIs
- Just fix the code directly

---

## Output Style

Asupersync is a library/runtime. Core code should not write to stdout/stderr.

- Use structured tracing via `Cx::trace` (or equivalent) for observability.
- Keep tests deterministic; avoid time-based logging outside the lab runtime.
- If a CLI is added, keep its output minimal, deterministic, and documented.

---

## Compiler Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced:**

```bash
# Check for compiler errors and warnings
cargo check --all-targets

# Check for clippy lints (pedantic + nursery are enabled)
cargo clippy --all-targets -- -D warnings

# Verify formatting
cargo fmt --check
```

If you see errors, **carefully understand and resolve each issue**. Read sufficient context to fix them the RIGHT way.

---

## Testing

### Testing Policy

Every module includes inline `#[cfg(test)]` unit tests alongside the implementation. Tests must cover:
- Happy path
- Edge cases (empty input, max values, boundary conditions)
- Error conditions

When adding or changing primitives, add tests that assert the core invariants:
- No task leaks
- No obligation leaks
- Losers are drained after races
- Region close implies quiescence

Prefer deterministic lab-runtime tests for concurrency-sensitive behavior.

### Unit Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run tests for a specific module
cargo test --lib <module_name>

# Run tests for a workspace member
cargo test -p asupersync-macros
cargo test -p asupersync-conformance
cargo test -p franken-kernel
cargo test -p franken-evidence
cargo test -p franken-decision
cargo test -p frankenlab
```

### Test Categories

| Area | Focus |
|------|-------|
| `types/` | Identifiers, outcomes, budgets, policies, serialization round-trips |
| `record/` | Task/region/obligation record creation, state transitions |
| `runtime/` | Scheduler fairness, state management, region lifecycle |
| `cx/` | Capability context, scope API, structured concurrency contracts |
| `channel/` | Two-phase reserve/send, MPSC/oneshot, cancel-correctness |
| `sync/` | Mutex, RwLock, Semaphore, Pool, Barrier, OnceLock — cancel-awareness |
| `combinator/` | Join, race, timeout, bulkhead, retry — loser drain correctness |
| `cancel/` | Cancellation protocol, symbol cancel, drain/finalize lifecycle |
| `obligation/` | Permit/ack/lease commit/abort, no-leak invariant |
| `lab/` | Virtual time, deterministic scheduling, DPOR, oracles |
| `net/` + `io/` | Async I/O adapters, socket integration |
| `http/` | HTTP/1.1, HTTP/2 protocol correctness |
| `codec/` | Framing, encoding/decoding round-trips |
| `conformance/` | Cross-component conformance suite |
| `benches/` | Scheduler, timer wheel, reactor, cancel/drain, RaptorQ throughput |

---

## Audit Index — Avoiding Duplicate Audits

`audit_index.jsonl` in the project root tracks every file that has been audited, by whom, when, and the verdict. **Check it before starting an audit batch** to avoid re-auditing files.

### Querying the index

Some legacy lines in `audit_index.jsonl` are malformed or off-contract, so use
raw-line parsing that ignores bad rows instead of raw `jq -r .file
audit_index.jsonl`.

```bash
# Check if a file has been audited
grep '"src/util/arena.rs"' audit_index.jsonl

# List all files with bugs found
jq -Rr 'fromjson? | objects | select(.verdict? == "FIXED" and .file?) | .file' audit_index.jsonl

# Count valid audit records
jq -Rnr '[inputs | fromjson? | objects | select(.file? and .lines? != null and .batch? != null and .date? and .agent? and (.verdict? == "SOUND" or .verdict? == "FIXED") and .bugs? != null and .notes? != null)] | length' audit_index.jsonl

# Count unique audited files
jq -Rnr '[inputs | fromjson? | objects | .file? // empty] | unique | length' audit_index.jsonl

# Find unaudited .rs files (compare against src/)
comm -23 <(find src -name '*.rs' | sort) <(jq -Rr 'fromjson? | objects | .file? // empty' audit_index.jsonl | sort -u) | head -20
```

### Adding entries

After completing an audit batch, append entries:

```bash
echo '{"file":"src/foo/bar.rs","lines":500,"batch":378,"date":"2026-03-15","agent":"YourName","verdict":"SOUND","bugs":0,"notes":""}' >> audit_index.jsonl
```

**Fields:**
| Field | Description |
|-------|-------------|
| `file` | Path relative to project root (for example `src/...`, `tests/...`, `docs/...`) |
| `lines` | Line count at audit time (0 for diff audits) |
| `batch` | Audit batch identifier (numeric batch, bead id, or other stable string) |
| `date` | ISO date of the audit |
| `agent` | Agent name who performed the audit |
| `verdict` | `SOUND` (no bugs) or `FIXED` (bugs found and fixed) |
| `bugs` | Number of bugs found |
| `notes` | Brief description of bugs, or empty string |

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and current best practices.

---

## Asupersync — This Project

**This is the project you're working on.** Asupersync is a spec-first, cancel-correct, capability-secure async runtime for Rust with structured concurrency, explicit cancellation, and deterministic testing.

### What It Does

Provides a complete async runtime where every task is owned by a region that closes to quiescence. Cancellation is a first-class protocol (request, drain, finalize), not a silent drop. Effects require explicit capabilities flowing through `Cx`.

### Architecture

```
User Future → Scope/Region → Scheduler → Cancellation/Obligations → Trace
     │              │              │               │                    │
     Cx ────────────┘──────────────┘───────────────┘────────────────────┘
```

### Asupersync Non-Negotiable Invariants

- **Structured concurrency:** every task/fiber/actor is owned by exactly one region
- **Region close = quiescence:** no live children + all finalizers done
- **Cancellation is a protocol:** request → drain → finalize (idempotent)
- **Losers are drained:** races must cancel and fully drain losers
- **No obligation leaks:** permits/acks/leases must be committed or aborted
- **No ambient authority:** effects flow through `Cx` and explicit capabilities

### Lock Ordering

When acquiring multiple locks, the strict order is:

```
E(Config) → D(Instrumentation) → B(Regions) → A(Tasks) → C(Obligations)
```

Violating this order causes deadlocks. `ShardedState` with `ContendedMutex` provides independent locking.

### Workspace Structure

```
asupersync/
├── Cargo.toml                         # Workspace root
├── src/                               # Main runtime crate and module tree
│   ├── types/                         # Core types (IDs, outcomes, budgets, policies)
│   ├── record/                        # Internal records for tasks, regions, obligations
│   ├── runtime/                       # Scheduler and runtime state management
│   ├── cx/                            # Capability context and scope API
│   ├── channel/                       # Two-phase channel primitives (MPSC, oneshot, sessions)
│   ├── sync/                          # Sync primitives (mutex, rwlock, semaphore, pool, barrier)
│   ├── combinator/                    # Join, race, timeout, bulkhead, retry
│   ├── cancel/                        # Cancellation protocol and symbol cancellation
│   ├── obligation/                    # Obligation tracking and recovery
│   ├── lab/                           # Deterministic lab runtime with virtual time
│   ├── trace/                         # Tracing infrastructure for deterministic replay
│   ├── time/                          # Sleep and timeout primitives
│   ├── io/                            # Async I/O traits and adapters
│   ├── net/                           # Async networking primitives
│   ├── bytes/                         # Zero-copy buffer types (Bytes, BytesMut, Buf, BufMut)
│   ├── codec/                         # Encoding/decoding primitives and framing
│   ├── http/                          # HTTP/1.1, HTTP/2 implementations
│   ├── tls/                           # TLS support via rustls
│   ├── grpc/                          # gRPC client/server with health checks
│   ├── database/                      # SQLite, PostgreSQL, MySQL async wrappers
│   ├── transport/                     # Low-level transport and routing
│   ├── stream/                        # Stream combinators and operations
│   ├── plan/                          # Plan DAG IR for combinator rewrites
│   ├── observability/                 # Structured logging, metrics, diagnostics
│   ├── security/                      # Symbol authentication and security
│   ├── distributed/                   # Consistent hashing, distribution, snapshots
│   ├── raptorq/                       # RaptorQ encoding pipeline
│   ├── util/                          # Internal utilities (RNG, arenas)
│   ├── actor.rs                       # Actor model primitives
│   ├── supervision.rs                 # Supervision trees
│   ├── gen_server.rs                  # Generic server pattern
│   ├── config.rs                      # Runtime configuration
│   ├── error.rs                       # Error types
│   └── ...                            # Additional single-file modules
├── asupersync-macros/                 # Proc macros (scope!, spawn!, join!, race!)
├── asupersync-browser-core/           # Browser Edition Rust boundary crate
├── asupersync-tokio-compat/           # Tokio-boundary compatibility adapters
├── asupersync-wasm/                   # WASM ABI/package crate (repo-local, excluded from workspace build)
├── conformance/                       # Conformance test suite
├── drop_unwrap_finder/                # Audit/refactor helper CLI
├── franken_kernel/                    # FrankenSuite type substrate
├── franken_evidence/                  # FrankenSuite evidence ledger
├── franken_decision/                  # FrankenSuite decision contracts
├── frankenlab/                        # Deterministic testing harness
├── packages/                          # JS/TS Browser Edition packages
├── artifacts/                         # Validation, governance, and replay artifacts
├── tests/                             # Integration tests
├── benches/                           # Performance benchmarks
├── examples/                          # Usage examples
├── docs/                              # Documentation
├── formal/                            # Formal specifications
├── scripts/                           # Validation, scan, and release tooling
└── .beads/                            # Beads issue tracking
```

### Key Documentation Files

| File | Purpose |
|------|---------|
| `asupersync_plan_v4.md` | Design bible and core invariants |
| `asupersync_v4_formal_semantics.md` | Small-step operational semantics |
| `TESTING.md` | Comprehensive testing guide |
| `README.md` | Project overview |

### Core Types Quick Reference

| Type | Purpose |
|------|---------|
| `Cx` | Capability context — passed to all async operations, no ambient authority |
| `Outcome<T, E>` | Four-valued result: Ok, Err, Cancelled, Panicked |
| `Budget` | Bounded cleanup time — sufficient conditions, not hopes |
| `Region` | Structured concurrency scope — owns tasks, closes to quiescence |
| `Scope` | API for creating child regions and spawning tasks |
| `TaskId` / `RegionId` | Identifiers for tasks and regions |
| `Obligation` | Tracked permit/ack/lease — must be committed or aborted |
| `CancelToken` | Cancellation signal propagation |
| `LabRuntime` | Deterministic runtime with virtual time for testing |

### Performance Requirements

- Zero unnecessary allocations on the hot path (scheduling, cancel checks)
- Deterministic lab runtime: behavior must be schedule-replayable
- Cancellation and drain paths are latency-sensitive; avoid extra work there
- Lock ordering must be respected for deadlock freedom

### Key Design Decisions

- **`#![deny(unsafe_code)]`** with per-module `#[allow(unsafe_code)]` where required (e.g., `pool.rs` for `unsafe impl Send`)
- **Lock ordering enforcement** with `ShardGuard` variants and label system (23 tests)
- **Channel waker dedup** pattern: `Arc<AtomicBool>` on mpsc `SendWaiter`, broadcast, and watch `WatchWaiter`
- **`ShardedState`** with `ContendedMutex` for independent locking across task/region/obligation tables
- **Two-phase effects** (reserve/commit) prevent data loss on cancellation
- **FrankenSuite integration** — evidence ledger, decision contracts, and kernel types for runtime verification
- **Roadmap reality** — README roadmap currently treats Phases 0-5 as complete, with Phase 6 ongoing hardening / policy gates / adapter expansion; some audit and cleanup beads still refer to earlier phase labels for historical context

---

## MCP Agent Mail — Multi-Agent Coordination

A mail-like layer that lets coding agents coordinate asynchronously via MCP tools and resources. Provides identities, inbox/outbox, searchable threads, and advisory file reservations with human-auditable artifacts in Git.

### Why It's Useful

- **Prevents conflicts:** Explicit file reservations (leases) for files/globs
- **Token-efficient:** Messages stored in per-project archive, not in context
- **Quick reads:** `resource://inbox/...`, `resource://thread/...`

### Same Repository Workflow

1. **Register identity:**
   ```
   ensure_project(project_key=<abs-path>)
   register_agent(project_key, program, model)
   ```

2. **Reserve files before editing:**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true)
   ```

3. **Communicate with threads:**
   ```
   send_message(..., thread_id="FEAT-123")
   fetch_inbox(project_key, agent_name)
   acknowledge_message(project_key, agent_name, message_id)
   ```

4. **Quick reads:**
   ```
   resource://inbox/{Agent}?project=<abs-path>&limit=20
   resource://thread/{id}?project=<abs-path>&include_bodies=true
   ```

### Macros vs Granular Tools

- **Prefer macros for speed:** `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`
- **Use granular tools for control:** `register_agent`, `file_reservation_paths`, `send_message`, `fetch_inbox`, `acknowledge_message`

### Common Pitfalls

- `"from_agent not registered"`: Always `register_agent` in the correct `project_key` first
- `"FILE_RESERVATION_CONFLICT"`: Adjust patterns, wait for expiry, or use non-exclusive reservation
- **Auth errors:** If JWT+JWKS enabled, include bearer token with matching `kid`

---

## Beads (br) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`br` - beads_rust) for selecting "ready work," setting priorities, and tracking status. It complements MCP Agent Mail's messaging and file reservations.

**Important:** `br` is non-invasive—it NEVER runs git commands automatically. You must manually commit changes after `br sync --flush-only`.

### Conventions

- **Single source of truth:** Beads for task status/priority/dependencies; Agent Mail for conversation and audit
- **Shared identifiers:** Use Beads issue ID (e.g., `br-123`) as Mail `thread_id` and prefix subjects with `[br-123]`
- **Reservations:** When starting a task, call `file_reservation_paths()` with the issue ID in `reason`

### Typical Agent Flow

1. **Pick ready work (Beads):**
   ```bash
   br ready --json  # Choose highest priority, no blockers
   ```

2. **Reserve edit surface (Mail):**
   ```
   file_reservation_paths(project_key, agent_name, ["src/**"], ttl_seconds=3600, exclusive=true, reason="br-123")
   ```

3. **Announce start (Mail):**
   ```
   send_message(..., thread_id="br-123", subject="[br-123] Start: <title>", ack_required=true)
   ```

4. **Work and update:** Reply in-thread with progress

5. **Complete and release:**
   ```bash
   br close 123 --reason "Completed"
   br sync --flush-only  # Export to JSONL (no git operations)
   ```
   ```
   release_file_reservations(project_key, agent_name, paths=["src/**"])
   ```
   Final Mail reply: `[br-123] Completed` with summary

### Mapping Cheat Sheet

| Concept | Value |
|---------|-------|
| Mail `thread_id` | `br-###` |
| Mail subject | `[br-###] ...` |
| File reservation `reason` | `br-###` |
| Commit messages | Include `br-###` for traceability |

---

## bv — Graph-Aware Triage Engine

bv is a graph-aware triage engine for Beads projects (`.beads/beads.jsonl`). It computes PageRank, betweenness, critical path, cycles, HITS, eigenvector, and k-core metrics deterministically.

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use MCP Agent Mail.

**CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command
```

### Command Reference

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level`, `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles |

**Other:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Interactive HTML visualization |

### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank
bv --robot-triage --robot-triage-by-track    # Group by parallel work streams
bv --robot-triage --robot-triage-by-label    # Group by domain
```

### Understanding Robot Output

**All robot JSON includes:**
- `data_hash` — Fingerprint of source beads.jsonl
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`

**Two-phase analysis:**
- **Phase 1 (instant):** degree, topo sort, density
- **Phase 2 (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles

### jq Quick Reference

```bash
bv --robot-triage | jq '.quick_ref'                        # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]'               # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.status'                         # Check metric readiness
bv --robot-insights | jq '.Cycles'                         # Circular deps (must fix!)
```

---

## UBS — Ultimate Bug Scanner

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

### Commands

```bash
ubs file.rs file2.rs                    # Specific files (< 1s) — USE THIS
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=rust,toml src/               # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs .                                   # Whole project (ignores target/, Cargo.lock)
```

### Output Format

```
⚠️  Category (N errors)
    file.rs:42:5 – Issue description
    💡 Suggested fix
Exit code: 1
```

Parse: `file:line:col` → location | 💡 → how to fix | Exit 0/1 → pass/fail

### Fix Workflow

1. Read finding → category + fix suggestion
2. Navigate `file:line:col` → view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` → exit 0
6. Commit

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

## RCH — Remote Compilation Helper

RCH offloads `cargo build`, `cargo test`, `cargo clippy`, and other compilation commands to a fleet of 8 remote Contabo VPS workers instead of building locally. This prevents compilation storms from overwhelming csd when many agents run simultaneously.

**RCH is installed at `~/.local/bin/rch` and is hooked into Claude Code's PreToolUse automatically.** Most of the time you don't need to do anything if you are Claude Code — builds are intercepted and offloaded transparently.

To manually offload a build:
```bash
rch exec -- cargo build --release
rch exec -- cargo test
rch exec -- cargo clippy
```

Quick commands:
```bash
rch doctor                    # Health check
rch workers probe --all       # Test connectivity to all 8 workers
rch status                    # Overview of current state
rch queue                     # See active/waiting builds
```

If rch or its workers are unavailable, it fails open — builds run locally as normal.

**Note for Codex/GPT-5.2:** Codex does not have the automatic PreToolUse hook, but you can (and should) still manually offload compute-intensive compilation commands using `rch exec -- <command>`. This avoids local resource contention when multiple agents are building simultaneously.

---

## ast-grep vs ripgrep

**Use `ast-grep` when structure matters.** It parses code and matches AST nodes, ignoring comments/strings, and can **safely rewrite** code.

- Refactors/codemods: rename APIs, change import forms
- Policy checks: enforce patterns across a repo
- Editor/automation: LSP mode, `--json` output

**Use `ripgrep` when text is enough.** Fastest way to grep literals/regex.

- Recon: find strings, TODOs, log lines, config values
- Pre-filter: narrow candidate files before ast-grep

### Rule of Thumb

- Need correctness or **applying changes** → `ast-grep`
- Need raw speed or **hunting text** → `rg`
- Often combine: `rg` to shortlist files, then `ast-grep` to match/modify

### Rust Examples

```bash
# Find structured code (ignores comments)
ast-grep run -l Rust -p 'fn $NAME($$ARGS) -> $RET { $$BODY }'

# Find all unwrap() calls
ast-grep run -l Rust -p '$EXPR.unwrap()'

# Quick textual hunt
rg -n 'println!' -t rust

# Combine speed + precision
rg -l -t rust 'unwrap\(' | xargs ast-grep run -l Rust -p '$X.unwrap()' --json
```

---

## Morph Warp Grep — AI-Powered Code Search

**Use `mcp__morph-mcp__warp_grep` for exploratory "how does X work?" questions.** An AI agent expands your query, greps the codebase, reads relevant files, and returns precise line ranges with full context.

**Use `ripgrep` for targeted searches.** When you know exactly what you're looking for.

**Use `ast-grep` for structural patterns.** When you need AST precision for matching/rewriting.

### When to Use What

| Scenario | Tool | Why |
|----------|------|-----|
| "How does the cancellation protocol work?" | `warp_grep` | Exploratory; don't know where to start |
| "Where is the region close logic?" | `warp_grep` | Need to understand architecture |
| "Find all uses of `Cx::trace`" | `ripgrep` | Targeted literal search |
| "Find files with `println!`" | `ripgrep` | Simple pattern |
| "Replace all `unwrap()` with `expect()`" | `ast-grep` | Structural refactor |

### warp_grep Usage

```
mcp__morph-mcp__warp_grep(
  repoPath: "/data/projects/asupersync",
  query: "How does the structured concurrency scope API work?"
)
```

Returns structured results with file paths, line ranges, and extracted code snippets.

### Anti-Patterns

- **Don't** use `warp_grep` to find a specific function name → use `ripgrep`
- **Don't** use `ripgrep` to understand "how does X work" → wastes time with manual reads
- **Don't** use `ripgrep` for codemods → risks collateral edits

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

**Important:** `br` is non-invasive—it NEVER executes git commands. After `br sync --flush-only`, you must manually run `git add .beads/ && git commit`.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
br ready              # Show issues ready to work (no blockers)
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason "Completed"
br close <id1> <id2>  # Close multiple issues at once
br sync --flush-only  # Export to JSONL (NO git operations)
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Run `br sync --flush-only` then manually commit

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads to JSONL
git add .beads/         # Stage beads changes
git commit -m "..."     # Commit everything together
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `br sync --flush-only && git add .beads/` before ending session

<!-- end-bv-agent-instructions -->

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Sync beads** - `br sync --flush-only` to export to JSONL
5. **Hand off** - Provide context for next session

---

## cass — Cross-Agent Session Search

`cass` indexes prior agent conversations (Claude Code, Codex, Cursor, Gemini, ChatGPT, etc.) so we can reuse solved problems.

**Rules:** Never run bare `cass` (TUI). Always use `--robot` or `--json`.

### Examples

```bash
cass health
cass search "async runtime" --robot --limit 5
cass view /path/to/session.jsonl -n 42 --json
cass expand /path/to/session.jsonl -n 42 -C 3 --json
cass capabilities --json
cass robot-docs guide
```

### Tips

- Use `--fields minimal` for lean output
- Filter by agent with `--agent`
- Use `--days N` to limit to recent history

stdout is data-only, stderr is diagnostics; exit code 0 means success.

Treat cass as a way to avoid re-solving problems other agents already handled.

---

Note for Codex/GPT-5.2:

You constantly bother me and stop working with concerned questions that look similar to this:

```
Unexpected changes (need guidance)

- Working tree still shows edits I did not make in Cargo.toml, Cargo.lock, src/runtime.rs, src/scope.rs. Please advise whether to keep/commit/revert these before any further work. I did not touch them.

Next steps (pick one)

1. Decide how to handle the unrelated modified files above so we can resume cleanly.
```

NEVER EVER DO THAT AGAIN. The answer is literally ALWAYS the same: those are changes created by the potentially dozen of other agents working on the project at the same time. This is not only a common occurence, it happens multiple times PER MINUTE. The way to deal with it is simple: you NEVER, under ANY CIRCUMSTANCE, stash, revert, overwrite, or otherwise disturb in ANY way the work of other agents. Just treat those changes identically to changes that you yourself made. Just fool yourself into thinking YOU made the changes and simply don't recall it for some reason.

---

## Note on Built-in TODO Functionality

Also, if I ask you to explicitly use your built-in TODO functionality, don't complain about this and say you need to use beads. You can use built-in TODOs if I tell you specifically to do so. Always comply with such orders.
