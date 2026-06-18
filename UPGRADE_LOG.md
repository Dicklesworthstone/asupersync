# Dependency Upgrade Log

## 2026-06-17 — asupersync — third-party dependency bumps (pass 1)

Scope: third-party deps only. Franken-ecosystem inter-dependency pins were not
touched — asupersync is the ecosystem base and its release is coordinated
separately.

### Important: Cargo.lock is gitignored

`asupersync/.gitignore` ignores `Cargo.lock` (line 6), so this crate resolves
fresh for every consumer. Consequence for this pass:

- **Caret/SemVer-compatible bumps are NOT committable artifacts here.** Running
  `cargo update` (≈144 lock edits available: clap 4.5→4.6, chrono 0.4.44→0.4.45,
  hyper 1.8.1→1.10.1, libc, log, rand, mio, nix, etc.) only refreshes the local
  ignored lock. Those bumps reach consumers automatically through their own
  resolution and need no edit here.
- **Only `Cargo.toml` version-requirement edits are committable** — i.e. the
  major bumps whose requirement string must be raised across a SemVer boundary.

`cargo update` was run locally so that all validation in this pass resolves
against the latest SemVer-compatible dependency set.

### Major bumps applied this pass

| Dependency | From    | To     | Kind                    | Code change |
|------------|---------|--------|-------------------------|-------------|
| `hkdf`     | 0.12    | 0.13   | prod (RustCrypto)       | none        |
| `whoami`   | 1.6     | 2.x    | prod, `optional`        | 1 line      |

**hkdf 0.12 → 0.13.** This was effectively a **dead-dependency realignment**.
The QUIC key schedule (`src/net/atp/handshake/key_schedule.rs`) was previously
migrated off the `hkdf` crate to a hand-rolled HKDF built directly on
`Hmac<Sha256>` (see closed bead `asupersync-3epgv2`, which records the original
hkdf-0.12/sha2-0.11 trait-version conflict and its resolution). A repo-wide grep
finds **zero** `use hkdf` / `hkdf::` call sites in code — only the manifest
declaration at `Cargo.toml:391`. asupersync already pins the new RustCrypto
generation everywhere else (`sha1 = 0.11`, `sha2 = 0.11`, `hmac = 0.13`, all on
`digest 0.11`), so leaving `hkdf` at 0.12 was the lone laggard forcing a stale
`digest 0.10` generation into the dependency graph. Bumping to 0.13 (which is
built on `digest 0.11`) realigns it. No source change required.

**whoami 1.6 → 2.x.** Single call site: `whoami::distro()` in
`src/atp/benchmark/mod.rs:80` (gated behind the `benchmark-adapters` feature).
whoami 2.x kept `distro()` at the crate root but made it **fallible** — it now
returns `Result<String, whoami::Error>` instead of `String`. Since `os_info` is
best-effort benchmark metadata and `BenchmarkEnvironment::collect()` shouldn't
abort just because OS-distro detection failed, the call site degrades gracefully:
`whoami::distro().unwrap_or_else(|_| "unknown".to_string())`.

### Validation

- `cargo check --features benchmark-adapters` (covers the whoami `distro()` call
  site + hkdf 0.13 resolution). See the commit for the result.

### Deferred majors — roadmap for the next pass

These were intentionally left for a follow-up pass; each needs targeted research
+ migration + a feature-specific build. Risk ordering reflects production impact.

| Dependency  | From   | To     | Where / gating                                  | Notes |
|-------------|--------|--------|-------------------------------------------------|-------|
| `sysinfo`   | 0.33   | 0.39   | prod, `Cargo.toml:413` (not optional)           | sysinfo churns its API every minor; audit call sites before bumping. |
| `sqlparser` | 0.52   | 0.62   | prod, `optional`, `sqlite` feature              | AST matching in `src/database/sqlite.rs` (`ast::Statement`, `SQLiteDialect`, `Parser`, `is_pragma_statement`). `Statement` enum variants/fields shift between releases — audit the match arms. |
| `sqlx`      | 0.8.6  | 0.9.0  | **dev-dep**, `Cargo.toml:505` (mysql ref impl)  | MySQL binary-protocol differential conformance test only — cannot affect the runtime. |
| `redis`     | 0.26   | 1.2    | **dev-dep**, `Cargo.toml:507` (RESP3 ref impl)  | RESP3 push-dispatch differential conformance test only. |
| `raptorq`   | 1.7.0  | 2.0    | **dev-dep**, `Cargo.toml:509` (RFC6330 ref)     | RaptorQ byte-level interop test only. |
| `hyper`     | 0.14   | 1.x    | `conformance/Cargo.toml` only                   | The core runtime + `asupersync-tokio-compat` already use hyper 1.x; only the conformance harness lags. |
| `env_logger`| 0.10   | 0.11   | `conformance/Cargo.toml` only                   | Main crate is already on `0.11` (caret covers 0.11.10). |

The "scary" majors flagged in the original ecosystem discovery (hyper, redis,
sqlx, raptorq) are all **dev-dependencies or the conformance sub-crate** — they
are reference implementations for differential/conformance testing and cannot
break the production runtime. Migrating them updates test harness code only.

### Franken inter-dependency pins — untouched (per scope)
