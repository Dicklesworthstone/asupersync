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

---

## 2026-07-23 — asupersync — dependency refresh + dead-dep removal (pass 4)

Scope: full lockfile refresh, removal of two dead production dependencies,
four production major bumps, and the dependency **audit** that produced
[`COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md`](./COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md)
(the phased program to replace external crates with home-grown strict-safe
Rust / FrankenSuite projects). Agent: SapphireHill.

Note: `Cargo.lock` **is tracked** in git today (`git check-ignore Cargo.lock` →
not ignored; a later negation overrides the `.gitignore:6` pattern), so unlike
pass 1's assumption, the lockfile refresh in this pass *is* a committable
artifact.

### Lockfile refresh (`cargo update`, semver-compatible)

~120 crate-version bumps, notably: rustls 0.23.40→0.23.42, rustls-pki-types
1.14.1→1.15.1, serde 1.0.228→1.0.229, serde_json 1.0.150→1.0.151, libc
0.2.186→0.2.189, socket2 0.6.4→0.6.5, sysinfo 0.39.3→0.39.6, thiserror
2.0.18→2.0.19, memchr 2.8.2→2.8.3, io-uring 0.7.12→0.7.13, crossbeam-queue
0.3.12→0.3.13, wasm-bindgen family 0.2.125→0.2.126, tokio 1.52.3→1.53.1 +
redis 1.2.4→1.4.1 + trybuild 1.0.116→1.0.118 (dev/satellite lanes), uuid
1.23.3→1.24.0, time 0.3.49→0.3.54.

Side effect: `syn v3.0.3` joins `syn v2.0.119` in the graph because
`serde_derive 1.0.229` moved to syn 3 while the rest of the proc-macro
ecosystem (and our own `asupersync-macros`) remains on syn 2.

### Dead dependencies REMOVED

| Dependency | Evidence |
|---|---|
| `crossbeam-deque` 0.8 | **Zero references** anywhere in the workspace. Work-stealing is fully home-grown (`src/runtime/scheduler/{local_queue,stealing,intrusive,global_injector}.rs`). Remains in the lockfile only via dev-only `criterion → rayon`. |
| `hkdf` 0.13 | **Zero call sites** (pass 1 already documented this and realigned the version; this pass completes the removal). HKDF is hand-rolled on `Hmac<Sha256>` in `src/net/atp/handshake/key_schedule.rs` + `src/security/key.rs` (bead asupersync-3epgv2). A tombstone comment in `Cargo.toml` records why. |

Also fixed: the stale `crc32fast` manifest comment (claimed Kafka KIP-98; real
users are `atp/journal`, `net/atp/sdk/stream`, `atp/adapter/masque`).

### Major bumps applied this pass

| Dependency | From | To | Kind | Code change |
|---|---|---|---|---|
| `base64` | 0.22.1 | 0.23.0 | prod | manifest-only, **default-features off** |
| `lz4_flex` | 0.13.1 | 0.14.0 | prod optional + dev | none (default features keep `alloc`) |
| `aes-gcm` | 0.10.3 | 0.11.0 | prod (native-only) | 2 files, 6 fns |
| `chacha20poly1305` | 0.10.1 | 0.11.0 | prod (native-only) | (same migration) |

**base64 0.23.** No API break for our engine usage. Safety-relevant: 0.23
default-enables the new `simd-unsafe` feature (unsafe SIMD engines). We now
declare `default-features = false, features = ["std"]` to keep the fully safe
scalar engine, consistent with the workspace `deny(unsafe_code)` posture. A
`base64 0.22` copy remains in the dev graph via third-party dev-deps.

**aes-gcm / chacha20poly1305 0.11 (migrated together — shared `aead` stack).**
RustCrypto generation bump (aead 0.5→0.6, cipher 0.4→0.5, Edition 2024):
`AeadInPlace::{en,de}crypt_in_place_detached` → `AeadInOut::{en,de}crypt_inout_detached`
taking `InOutBuf`; `Nonce`/`Tag` moved from GenericArray (`from_slice`, panics
on bad length) to hybrid-array (`From<[u8; N]>` / fallible `TryFrom<&[u8]>`).
Migrated `src/net/atp/crypto/mod.rs` (ChaCha20-Poly1305 + AES-256-GCM
encrypt/decrypt) and `src/atp/mailbox/encryption.rs` (`EncryptedChunk`). Wire
format unchanged (same AEADs, 12-byte nonces, detached 16-byte tags);
slice-length conversion now fails closed with explicit errors instead of
panicking. This harmonizes the graph on the digest-0.11 generation already used
by sha2/hmac (drops `opaque-debug`, dedups part of the digest/crypto-common
chains); the remaining `sha2 0.10` duplicate rides `nkeys → ed25519-dalek`
(replacement plan Phase 5).

### Skipped (intentional)

- **`syn` 2→3 for `asupersync-macros`/`drop_unwrap_finder`:** migrating would
  NOT dedup the graph — thiserror-impl, pin-project-internal, zeroize_derive,
  prost-derive et al. still require syn 2, so both majors remain either way.
  Revisit when the ecosystem majority moves (or when plan Phase 4 makes our own
  macros the only syn consumer we control).
- **`serde_yaml` (deprecated upstream):** no successor to update to; plan
  Phase 3 removes it by migrating frankenlab scenarios to JSON.
- Pinned nightly toolchain, path/workspace pins, opentelemetry 0.32 (already
  latest): untouched.

### Method note

This repo's test gate runs on the rch remote fleet with a long full-suite wall
time and a dozen concurrent agents dirtying the working tree, so verification
used `rch exec --base HEAD --clean-overlay` with only this pass's changed files
overlaid (peer edits cannot confound results), in two batches: (1) lockfile
refresh alone → full `cargo test --features test-internals`; (2) manifest
removals + majors + AEAD migration → `cargo check --all-targets` with
`-D warnings`, then the full suite. Each change was researched individually
(changelogs/release notes) before applying; any batch failure is bisected
per-dependency with rollback per the library-updater protocol.

### Validation

- **Batch 1 (lockfile-only), full `cargo test --features test-internals`:**
  21,363 passed / 3 failed / 22 ignored. The 3 failures
  (`audit::ambient::tests::ambient_authority_does_not_regress`,
  `gen_server::tests::named_start_helper_crash_then_stop_cleans_registry`,
  `runtime::state::tests::task_completion_tracing_panic_is_contained_and_counted`)
  were **exonerated by a control run at clean `HEAD` with the OLD lockfile
  (`--clean-overlay --no-overlay`), which fails the identical 3 tests** —
  pre-existing HEAD redness from code-first peer commits, not caused by this
  pass. Filed as `asupersync-bm3tty` (P1 bug).
- **Batch 2 (removals + majors + AEAD migration):**
  `cargo check --all-targets --features test-internals` with `-D warnings` —
  clean (0 errors, 10m20s remote). Full suite: **21,363 passed / 3 failed —
  the identical pre-existing `asupersync-bm3tty` set, zero new failures.**
  (One fleet SSH timeout, RCH-E104, required a retry on another worker.)
- `cargo audit` not run this session (not installed on this host); plan
  Phase 6 adds a `cargo deny`/`cargo audit` CI lane. No known-advisory crates
  were introduced by this refresh; the sqlx/rsa RUSTSEC-2023-0071 advisory
  noted in pass 1 was already cleared by pass 3's sqlx 0.9 bump.
