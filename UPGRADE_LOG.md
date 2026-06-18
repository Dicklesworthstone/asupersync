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
| `sysinfo`  | 0.33    | 0.39   | prod                    | none        |

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

**sysinfo 0.33 → 0.39.** Production dep, ~20 call sites across 5 files
(`runtime/resource_monitor.rs`, `atp/daemon_control.rs`,
`atp/logging/failure_bundle.rs`, `bin/atpd.rs`, `atp/benchmark/mod.rs`). Changelog
audit of 0.34→0.39 confirmed **none** of the breaking changes touch the APIs in
use: the 0.34 `ProcessesToUpdate` + `remove_dead` bool is already adopted in the
code; 0.35 `open_files` and 0.38 `Disk::file_system` aren't used; 0.37/0.39 only
raise MSRV (asupersync builds on nightly). Clean zero-code bump.

### Validation

- `cargo check --features benchmark-adapters` (whoami `distro()` + hkdf 0.13) —
  Finished, 0 errors (after the whoami fallible fix).
- `cargo check --lib --bins --features "atpd-daemon,benchmark-adapters"` (all five
  sysinfo call-site files incl. the `atpd` daemon binary) — Finished, 0 errors.

### Deferred majors — roadmap for the next pass

These were intentionally left for a follow-up pass; each needs targeted research
+ migration + a feature-specific build. Risk ordering reflects production impact.
**`sqlparser` was completed in pass 2 (see the 2026-06-18 section below); every
remaining item is a dev-dependency or the conformance sub-crate and cannot affect
the production runtime.**

| Dependency  | From   | To     | Where / gating                                  | Notes |
|-------------|--------|--------|-------------------------------------------------|-------|
| `sqlparser` ✅ | 0.52   | 0.62   | prod, `optional`, `sqlite` feature              | **DONE in pass 2.** `Statement::SetVariable` was unified into `Statement::Set(Set)`; migrated the two match sites in `src/database/sqlite.rs`. See the 2026-06-18 section below. This was the only remaining **production** major. |
| `sqlx`      | 0.8.6  | 0.9.0  | **dev-dep**, `Cargo.toml:505` (mysql ref impl)  | MySQL binary-protocol differential conformance test only — cannot affect the runtime. **`cargo audit` flags a pre-existing RUSTSEC-2023-0071 (Marvin Attack on `rsa`) reaching the tree via `sqlx-mysql 0.8.6`; `rsa` has no fixed release, so bumping sqlx→0.9 (which may drop/gate `rsa`) is the path to clear it.** |
| `redis`     | 0.26   | 1.2    | **dev-dep**, `Cargo.toml:507` (RESP3 ref impl)  | RESP3 push-dispatch differential conformance test only. |
| `raptorq`   | 1.7.0  | 2.0    | **dev-dep**, `Cargo.toml:509` (RFC6330 ref)     | RaptorQ byte-level interop test only. |
| `hyper`     | 0.14   | 1.x    | `conformance/Cargo.toml` only                   | The core runtime + `asupersync-tokio-compat` already use hyper 1.x; only the conformance harness lags. |
| `env_logger`| 0.10   | 0.11   | `conformance/Cargo.toml` only                   | Main crate is already on `0.11` (caret covers 0.11.10). |

The "scary" majors flagged in the original ecosystem discovery (hyper, redis,
sqlx, raptorq) are all **dev-dependencies or the conformance sub-crate** — they
are reference implementations for differential/conformance testing and cannot
break the production runtime. Migrating them updates test harness code only.

### Franken inter-dependency pins — untouched (per scope)

---

## 2026-06-18 — asupersync — third-party dependency bumps (pass 2)

Scope: the deferred **production** major from pass 1. Franken inter-dependency
pins remain untouched (coordinated separately). `Cargo.lock` is still gitignored
(see pass 1), so only the `Cargo.toml` requirement edit is a committable artifact.

### Major bump applied this pass

| Dependency  | From | To   | Kind                        | Code change |
|-------------|------|------|-----------------------------|-------------|
| `sqlparser` | 0.52 | 0.62 | prod, `optional` (`sqlite`) | 2 sites     |

**sqlparser 0.52 → 0.62.** Used only by the secure SQL-surface validator
(`src/database/sqlite.rs`, behind the `sqlite` feature), which parses each
statement with `SQLiteDialect` and rejects PRAGMA / ATTACH·DETACH /
transaction-control / SET-as-PRAGMA forms on the checked surface
(asupersync-dn5hn8). The only break across the ten intervening minor releases:
the various `SET ...` statement forms were unified — `Statement::SetVariable
{ variables, .. }` was removed in favor of a single `Statement::Set(Set)` variant,
where `Set` is an enum whose assignment arms (`SingleAssignment { variable }`,
`ParenthesizedAssignments { variables }`, `MultipleAssignments { assignments }`)
carry the target name(s) as `ObjectName`.

Migration (2 sites):
- `check_parsed_statements`: the defensive `Statement::SetVariable { .. } if
  is_pragma_statement(..)` arm became `Statement::Set(_) if is_pragma_statement(..)`.
- `is_pragma_statement`: rewritten as `let Statement::Set(set) = .. else { false }`
  + a match over the three assignment arms, returning `true` when any target
  `ObjectName` stringifies to a `PRAGMA`-prefixed name. (rustc suggested renaming
  to `ShowVariable`, which is semantically wrong — `SHOW` ≠ `SET` — and was not
  used.)

Real SQLite PRAGMAs still parse as `Statement::Pragma` under `SQLiteDialect`; the
SET branch only matters for parser-drift / non-SQLite-dialect paths, which is
exactly why the guard is kept defensive.

### Validation

- `cargo test --features sqlite --lib database::sqlite::tests::test_sqlparser`
  (cold, 9m56s via rch) — all 4 surface-violation tests pass:
  `test_sqlparser_blocks_pragma`, `test_sqlparser_blocks_attach_detach`,
  `test_sqlparser_blocks_transaction_control`,
  `test_sqlparser_comment_bypass_protection`.

### Remaining after pass 2

Only **dev-dependencies / the conformance sub-crate**: `sqlx` 0.8→0.9 (also clears
the pre-existing RUSTSEC-2023-0071 `rsa`/Marvin advisory in the MySQL conformance
test), `redis` 0.26→1.2, `raptorq` 1→2, conformance `hyper` 0.14→1.x +
`env_logger` 0.10→0.11. None can affect the production runtime.

---

## 2026-06-18 — asupersync — comprehensive dependency/release pass (pass 3)

Scope: complete the remaining dev-dependency and conformance-harness majors,
align workspace crate/package versions for a `0.3.5` release, and verify that
local path/workspace libraries remain the preferred source for user-developed
code in `/dp`.

### Version alignment

All Rust workspace crates now publish as `0.3.5` and all in-workspace path
dependency pins were raised with them:

- `asupersync`
- `asupersync-macros`
- `asupersync-browser-core`
- `asupersync-tokio-compat`
- `asupersync-conformance`
- `franken-kernel`
- `franken-evidence`
- `franken-decision`
- `frankenlab`

The browser/npm workspace packages were also aligned to `0.3.5`.

### Dependency bumps applied this pass

| Dependency | From | To | Kind | Code change |
|------------|------|----|------|-------------|
| `opentelemetry` | 0.31 | 0.32 | prod optional / metrics | proto field drift |
| `opentelemetry_sdk` | 0.31 | 0.32 | prod optional + dev | proto field drift |
| `opentelemetry-proto` | 0.31 | 0.32 | fuzz/test OTLP helpers | proto field drift |
| `rusqlite` | 0.39 | 0.40 | prod optional (`sqlite`) | none observed |
| `sqlx` | 0.8.6 | 0.9 | dev MySQL differential harness | none observed |
| `redis` | 0.26 | 1.2 | dev RESP3 differential harness | clone values at conversion boundary |
| `raptorq` | 1.7.0 | 2.0 | dev RFC6330 differential harness | constructor/payload-id drift |
| `hyper` | 0.14 | 1.x | conformance crate | manifest-only, already compatible |
| `env_logger` | 0.10 | 0.11 | conformance crate | manifest-only |
| `prometheus-client` | 0.23 | 0.25 | conformance crate | manifest-only |
| `syn` | 2.0.117 | 2.0.118 | helper CLI | manifest-only |
| `typescript` | 5.x | 6.0.3 | npm dev tooling | manifest-only |
| `@types/react` | 18.x | 19.2.17 | npm dev tooling | manifest-only |

`opentelemetry-proto` 0.32 adds `key_strindex` to OTLP `KeyValue` and string
value references to the protobuf enum. The runtime exporter and OTLP
wire-format tests now emit `key_strindex: 0` for literal keys and ignore
string-table indexed string values because this crate does not maintain an OTLP
string table.

`redis` 1.2 consumes `Value` in `from_redis_value`, so the differential parser
clones the test fixture value before conversion. The fixture is small and this
keeps the parser comparison deterministic.

`raptorq` 2.0 replaces `SourceBlockEncoder::new2` with `new`. Its payload-id
helper no longer applies the old repair-symbol adjustment, so the local
systematic decoder now creates the external repair payload ID with
`PayloadId::new(0, esi)`.

### `/dp` local-library scan

`/dp` resolves to `/data/projects`. A manifest scan found a stale sibling copy at
`/data/projects/dp/asupersync` (`asupersync` `0.3.2` plus older member/package
versions), while this repository is the newer `0.3.5` source of truth. This pass
keeps all user-developed asupersync-family dependencies as in-repo
`path`/workspace dependencies and found no external `path = "/dp"` or
`/data/projects/...` dependency that needed retargeting.

### Release workflow fix

`Cargo.lock` is intentionally ignored in this repository, but the publish
workflow runs locked packaging/publishing and computes release provenance over
the lockfile. The workflow now generates the release lockfile in CI with
`cargo generate-lockfile` before version verification and provenance capture.
The release-provenance contract was updated to assert that step exists.

### Validation

Validation is still in progress for this pass. The focused
`rust_crate_release_provenance_contract` lane passed after the workflow fix; the
broad workspace check, clippy, full tests, npm checks, audits, and final release
publish gates are tracked in the session closeout.
