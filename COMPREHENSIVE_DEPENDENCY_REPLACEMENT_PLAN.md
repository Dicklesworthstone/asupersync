# Comprehensive Dependency Replacement Plan — Asupersync

> **Goal:** systematically shrink asupersync's external dependency surface to a small, audited core, replacing everything else with home-grown, strict-memory-safe Rust that is ultra-optimized for Apple Silicon (NEON, high single-core IPC) and high-core-count x86 (AVX2/AVX-512, cross-CCX-aware), or with FrankenSuite projects we control.
>
> Audit date: 2026-07-23 (SapphireHill). Graph numbers measured from `Cargo.lock` after the 2026-07-23 `cargo update` refresh, via `cargo metadata`/`cargo tree` (commands in Appendix C).

---

## 1. Philosophy

External library dependencies are an anti-pattern for this project, for four reasons:

1. **Supply chain.** Every one of the ~375 crates in our full workspace graph is a person or CI pipeline that can be compromised. The default *consumer* graph alone is 124 external crates — 124 trust relationships to ship a runtime whose core value proposition is *correctness you can trust*.
2. **Memory safety.** We `deny(unsafe_code)` and ledger every exception — then link in `ring` (C + assembly), bundled SQLite (250k lines of C), and `librdkafka` (C, via cmake). The safety story is only as strong as the weakest native blob.
3. **The generality tax.** One-size-fits-all crates carry code, features, and compile time we never use (`sysinfo` for five call sites; `clap`'s 21-crate closure for two arg modules; `nkeys`' 46-crate closure for one Ed25519 wrapper). Purpose-built code is smaller, faster, and fully understood.
4. **Performance ownership.** Our continuous optimization campaigns (scheduler lock traffic, RaptorQ GF(256) SIMD, timer wheel) stop at crate boundaries. Code we own keeps getting faster; code we import doesn't.

The plan is **not** dogmatic: cryptographic primitives, the TLS stack, serde's derive ecosystem, and platform FFI bedrock stay (Section 6). Dev-dependencies used as *differential-testing references* (httparse, raptorq, sqlx, redis, tokio) are an asset, not a liability — they never ship, and they are exactly how we prove our replacements correct.

---

## 2. Audit Snapshot (2026-07-23)

### 2.1 Graph size

| Graph | External crates |
|---|---|
| Default consumer graph (`cargo tree -p asupersync -e normal`) | **132 crate-versions / 124 unique names** |
| `+tls` | 150 |
| `+tls-native-roots` | 152 |
| `+sqlite` | 134 |
| `+kafka` | 137 |
| `+metrics` | 137 |
| `+cli` | **167** |
| `+atp-cli` | 165 |
| Workspace, all features, incl. dev/build deps | **~376 external / 390 packages** |

### 2.2 Native code (C/C++/asm) in the graph — the worst offenders

| Crate | Native payload | Pulled by | Feature |
|---|---|---|---|
| `ring` | C + hand-written assembly | `rustls/ring` provider | `tls` |
| `libsqlite3-sys` | bundled SQLite C amalgamation (cc + bindgen + pkg-config) | `rusqlite` | `sqlite` |
| `rdkafka-sys` | `librdkafka` C via **cmake** | `rdkafka` | `kafka` |
| `signal-hook` | small `cc` build shim | direct | always (native) |
| `psm`/`stacker` | C stack-probing | `sqlparser` recursion guard | `sqlite` |
| `generator` | C context-switching | `loom` | dev-only (`loom-tests`) |
| `alloca` | C | `criterion` (Windows) | dev-only |

### 2.3 Version-duplication bloat in the *default* graph

Two RustCrypto generations are linked simultaneously: `sha2` 0.10 **and** 0.11, `digest` 0.10+0.11, `block-buffer` ×2, `crypto-common` 0.1+0.2, `const-oid` 0.9+0.10, `cpufeatures` 0.2+0.3, `getrandom` 0.2+0.4 — driven by `nkeys → ed25519-dalek` (old generation) vs our direct `sha2 0.11`/`hmac 0.13` (new generation), and by `aes-gcm`/`chacha20poly1305` 0.10 (old generation; 0.11 migration is queued — see UPGRADE_LOG.md). `syn` 2 + 3 are both present (serde_derive moved to syn 3; the rest of the ecosystem hasn't).

### 2.4 Dead and misplaced dependencies found

| Finding | Status |
|---|---|
| `crossbeam-deque` — **zero references anywhere**; work-stealing is fully home-grown (`runtime/scheduler/local_queue.rs`, `stealing.rs`, `intrusive.rs`) | **removed 2026-07-23** |
| `hkdf` — **zero references**; HKDF is hand-rolled on `hmac` in `net/atp/handshake/key_schedule.rs` + `security/key.rs` (RFC 5869 + RFC 8446 expand-label) | **removed 2026-07-23** |
| `tempfile` is a *normal* dep only because feature-gated e2e modules (`real_*_e2e_tests.rs` under `obligation-cleanup-e2e`, `channel-mpsc-select-e2e`) `use tempfile` outside `cfg(test)` | demote after moving those modules (Phase 1) |
| `env_logger` enabled by all of `cli` but consumed only by `src/bin/offline_tuner.rs` (2 lines) | remove (Phase 1) |
| `time` + `chrono` both in the CLI; `time` has exactly **one** call site (ns→RFC3339 in `bin/asupersync.rs`) | consolidate (Phase 1) |
| `num_cpus` + `whoami`: one call site each in `atp/benchmark/mod.rs`; std (`available_parallelism`) covers it | remove (Phase 1) |
| `src/net/atp/chunk/artifact.rs` contains a local `mod regex` **mock** ("Temporary regex module", simplified matcher) in production code | replace with the real version-scanner in Phase 3 (no-mock policy) |
| `Cargo.toml` comment claims `crc32fast` is for "Kafka RecordBatch v2 (KIP-98)" — stale; actual users are `atp/journal`, `atp/sdk/stream`, `masque` | fix comment; no native Kafka wire code exists at all (§7.3) |

### 2.5 What the code *actually* uses (usage-mapping summary)

Full per-crate detail lives in the audit transcripts; the load-bearing facts:

| Crate | Real surface | Files |
|---|---|---|
| `serde` | `#[derive(Serialize/Deserialize)]` — **~4,570 derives** | ~268 |
| `serde_json` | `json!` ×1419, `Value` ×376, to/from_string — DOM style, no streaming | ~247 |
| `parking_lot` | `Mutex` ×322, `RwLock` ×57 — **no Condvar/Once** — scheduler/channel hot paths | ~173 |
| `thiserror` | derive only (`#[error]`, `#[from]`, `#[source]`) | 111 |
| `tempfile` | `TempDir`/`NamedTempFile`, overwhelmingly test fixtures | 80 |
| `futures-lite` | `block_on` ×728 (mostly tests/bridges), `poll_fn`, `zip`, `race`, `yield_now` | ~150 |
| `smallvec` | inline waker/task batches (`[Waker;8]`, `[TaskId;32]`…) on hot paths | 41 |
| `pin-project` | `#[pin_project]` on stream/service combinator futures | 30 |
| `hex` / `base64` | encode/decode only | 49 / 19 |
| `nkeys` | `KeyPair` seed/sign/verify — canonical Ed25519 identity for ATP peers, capability tokens, agent-swarm control plane, NATS auth | 6 |
| `sha2` | digest + KDF backbone (CAS, transcripts, Merkle, SCRAM) | ~90 |
| `aes-gcm`/`chacha20poly1305` | ATP object/mailbox AEAD (detached, in-place). QUIC packet AEAD is **rustls/ring**, not these | 2 / 1 |
| `x509-parser` | SPKI extraction for cert pinning + SAN matching in native-QUIC verifier | 5 |
| `prost` | `Message` codec for gRPC **+ OTLP export + `codec/length_delimited`** — non-optional, drags `bytes`+`anyhow`+`itertools` into the default graph | 7 |
| `rmp-serde` | binary trace-file format | 6 |
| `bincode-next` | **2** production files (snapshot payload, typed symbols) | 6 |
| `semver` | `Version` parse/compare only | 3 |
| `memchr` | `memmem`/`memchr_iter` in HTTP/1 + Redis parsing | 4 |
| `hashbrown` | 2 call sites (std's HashMap *is* hashbrown) | 2 |
| `slab` | `Slab<T>`; home-grown `TokenSlab` (generation-tagged) already exists | ~8 |
| `crossbeam-queue` | `SegQueue` (global injector, epoch GC), `ArrayQueue` ×2 | 6 |
| `polling` | `Poller`/`Events`/`PollMode` — the epoll/kqueue/IOCP loop | 3 |
| `socket2` | socket builders + options | 8 |
| `nix` | **cmsg/SCM_RIGHTS, sendmmsg/recvmmsg, UDP GSO** (irreplaceable part), statvfs, fcntl | 11 |
| `sysinfo` | daemon process control (`kill_with`), RSS monitor, diag bundles, os-version strings | 5 |
| `signal-hook` | `iterator::Signals` thread + consts | 3 |
| `rusqlite`+`sqlparser` | one 7,258-line module; prepared cache, `progress_handler` budget timeouts, interrupt handles; sqlparser = statement-class allowlist | 1 |
| `rdkafka` | pure librdkafka wrapper — **no native wire protocol exists** | 2 |
| `opentelemetry`/`_sdk` | metrics instruments + span data model, one adapter module (`otel.rs`, 9,427 lines) | 1 |
| `regex` | 4 fixed PII-redaction patterns + user-supplied patterns (otel) | 2 |
| `clap` | derive-only command tree, 2 arg modules + 4 binaries | 6 |
| `unicode-normalization` | one `.nfc()` call for path-homograph safety | 1 |

**Home-grown infrastructure already in-tree** (proof this codebase can do this): work-stealing deques + intrusive queues/heaps, `TokenSlab`/`WaiterSlab`, `DetHashMap`/`DetHasher`, `Arena`, `CachePadded` (`util/cache.rs`), deterministic RNG, hand-rolled HKDF, hand-rolled protobuf varints (`grpc/protobuf.rs`), a `tracing_compat` no-op shim layer, and ledgered unsafe SIMD (RaptorQ GF(256) AVX2/NEON kernels).

---

## 3. Classification: every dependency, one verdict

**Legend:** `REMOVE` = delete, nothing to replace · `STD` = replace with std/existing in-tree code · `OWN` = write it ourselves · `FRANKEN` = replace with a FrankenSuite project · `KEEP` = deliberate, justified external dependency · `DEV-KEEP` = dev-only reference/verification tool, keep.

### Production (normal) dependencies

| Crate | Verdict | Phase | Note |
|---|---|---|---|
| `crossbeam-deque` | REMOVE | 0 ✅ | dead |
| `hkdf` | REMOVE | 0 ✅ | dead (hand-rolled impl already in use) |
| `hashbrown` | STD | 1 | 2 sites → `std::collections`/`DetHashMap` |
| `num_cpus` | STD | 1 | `std::thread::available_parallelism` |
| `whoami` | STD | 1 | fold into `util/host.rs` os-string |
| `env_logger` | REMOVE | 1 | 2 lines in offline_tuner → tracing shim |
| `time` | REMOVE | 1 | 1 call site → own RFC3339 formatter |
| `semver` | OWN | 1 | ~40-line `Version` parse/compare |
| `hex` | OWN | 1 | ~60 lines + optional SIMD path |
| `base64` | OWN | 1 | ~200 lines, RFC 4648 std/url-safe/no-pad |
| `bincode-next` | OWN | 1 | 2 sites → own deterministic binary codec |
| `futures-lite` | OWN | 1 | `block_on`/`poll_fn`/`zip`/`race`/`yield_now` in `util/future.rs` |
| `visibility` | OWN | 1 | 12 uses of one attr → mini-macro in `asupersync-macros` |
| `slab` | STD/OWN | 1 | unify on in-tree `TokenSlab` family |
| `xattr` | OWN | 2 | direct `nix`/libc getxattr/setxattr wrapper |
| `tempfile` | OWN | 2 | `util/tempdir.rs` (getrandom names + O_EXCL + RAII); demote to dev first |
| `polling` | OWN | 2 | direct epoll/kqueue behind existing `Reactor` trait; kills `rustix` from prod graph |
| `socket2` | OWN | 2 | fold into own sockopt layer in `net/sys.rs` |
| `signal-hook` | OWN | 2 | own signal layer on libc + windows-sys (removes a cc build shim) |
| `sysinfo` | OWN | 2 | `util/host.rs`: /proc + sysctl + existing windows-sys calls |
| `prost` | OWN | 3 | `codec/proto.rs` wire codec + hand-written gRPC/OTLP messages; frees `bytes`/`anyhow`/`itertools` |
| `rmp-serde` | OWN | 3 | own MessagePack for trace format (versioned) |
| `toml` | OWN | 3 | config-subset reader/writer |
| `serde_yaml` | REMOVE | 3 | **deprecated upstream**; migrate scenarios to JSON |
| `clap` | OWN | 3 | own derive-less declarative CLI parser |
| `chrono` | OWN | 3 | own UTC timestamp + RFC3339 (serde-compatible) |
| `regex` | OWN | 3 | fixed PII scanners + tiny literal/class matcher |
| `opentelemetry`/`_sdk` | OWN | 3 | native OTLP exporter on own proto codec |
| `parking_lot` | STD→OWN | 4 | **measure first**: nightly `std` futex Mutex; own only if it loses |
| `crossbeam-queue` | OWN | 4 | Vyukov MPMC + segmented injector, loom-verified |
| `smallvec` | OWN | 4 | `util/inline_vec.rs`, ledgered `MaybeUninit` core |
| `memchr` | OWN | 4 | **safe** `std::simd` memchr/memmem (nightly portable SIMD) |
| `crc32fast` | OWN | 4 | slicing-by-16 safe + optional ledgered CLMUL/ARM-CRC |
| `pin-project` | OWN | 4 | own projection derive in `asupersync-macros` |
| `thiserror` | OWN | 4 | own `#[derive(Error)]` in `asupersync-macros`, attr-compatible |
| `rusqlite` + `sqlparser` | FRANKEN | 5 | **FrankenSQLite** (§7.1) — removes bundled C SQLite + psm/stacker |
| `rdkafka` | OWN or REMOVE | 5 | native Kafka wire client or drop the feature; either way librdkafka goes (§7.3) |
| `nkeys` | OWN | 5 | own NKey base32+CRC16 codec directly on `ed25519-dalek` (§7.4) |
| `x509-parser` | OWN | 5 | minimal DER walker for SPKI + SAN only, differential-fuzzed (§7.5) |
| `flate2` | OWN (stretch) | 5 | own DEFLATE; until then it's pure-Rust miniz_oxide (acceptable) |
| `brotli` | REMOVE | 5 | drop from content-encoding menu (it's negotiable) |
| `lz4_flex` | OWN | 5 | LZ4 block format is ~500 lines; natural fit for the SIMD-kernel pattern |
| `unicode-normalization` | OWN | 5 | vendored NFC tables (checked-in, generated offline) |
| `serde` + `serde_json` | KEEP | — | keystone (~4,570 derives, 1,419 `json!`); revisit only after everything else |
| `sha1`, `sha2`, `hmac`, `subtle`, `zeroize`, `getrandom` | KEEP | — | audited, pure-Rust, tiny, security-load-bearing |
| `aes-gcm`, `chacha20poly1305` | KEEP | — | AEAD is not a place for first-party heroics; upgrade to 0.11 generation |
| `ed25519-dalek` (via nkeys today) | KEEP | 5 | becomes a *direct* dep when nkeys goes |
| `rustls` + `rustls-pki-types` + `rustls-pemfile` + roots | KEEP | — | TLS 1.3 + QUIC keys; §6.2 for the ring problem |
| `libc`, `nix`, `windows-sys` | KEEP | — | FFI bedrock (nix uniquely covers cmsg/GSO/mmsg) |
| `io-uring` | KEEP | — | thin raw binding, feature-gated |
| `wasm-bindgen`/`js-sys`/`web-sys`/`wasm-bindgen-futures` | KEEP | — | the browser ABI boundary |
| `tokio`, `async-trait` (benchmark-adapters) | KEEP | — | the competitor lane *is* the point |
| `tower` | KEEP | — | interop adapter, feature-gated, tiny surface |
| `arbitrary`, `opentelemetry-proto` | KEEP | — | fuzz-only, quarantined by design |

### Dev-dependencies — all DEV-KEEP

`proptest`, `criterion`, `insta`, `trybuild`, `loom`, `fastrand`, `rayon`, plus the differential references: `httparse` (HTTP/1), `raptorq` (RFC 6330), `sqlx` (MySQL), `redis` (RESP3), `tokio`/`tokio-util` (semaphore/codec conformance). **Policy:** every crate we replace gets retained (or added) as a dev-dependency reference for differential testing until two release cycles after the replacement ships. Dev deps never reach consumers.

---

## 4. Performance doctrine for replacements

Every `OWN` module follows the doctrine already proven by `raptorq/gf256.rs`:

1. **Safe portable baseline first** — scalar or `std::simd` (we are pinned nightly; portable SIMD costs zero unsafe). This is the always-on fallback and the differential oracle.
2. **Ledgered intrinsics second, only where measured** — `#[allow(unsafe_code)]` at fn scope, row in `artifacts/unsafe_boundary_ledger_v1.json`, evidence in `docs/unsafe_boundary_ledger.md`.
3. **Apple Silicon specifics:** NEON 128-bit lanes via `std::simd` (auto-lowers well); 128-byte cache-line padding (`util/cache.rs::CachePadded` already aligns 128); prefer branchless scalar for short inputs (M-series IPC makes table lookups lose below ~64 B); `TBL`-based nibble tricks for hex/base64; `std::hint::spin_loop` lowers to `ISB`/`WFE`-friendly spins.
4. **High-core-count x86 specifics:** AVX2 baseline, AVX-512 only behind runtime detection (Zen 4/5 double-pumped 512 is a win; pre-Ice-Lake Intel downclocking is not); shard hot atomics per-core and pad to 128 B to avoid cross-CCX cacheline ping-pong; prefer per-worker sharded counters + snapshot merge (the `ContendedMutex` metrics pattern) over shared atomics.
5. **Determinism trumps micro-wins:** no ambient entropy, no wall-clock in kernels, identical results across ISAs (bit-exact outputs are part of every kernel's contract — same rule the GF(256) kernels obey).
6. **Measure before building** (MATRIX-222 lesson): each Phase-4 primitive begins with a criterion A/B of the incumbent vs `std`/naive under the real workload (scheduler bench, h1 parse bench). If std wins or ties, we take the zero-unsafe path and move on.

**Verification stack per replacement:** differential property tests vs the replaced crate (kept as dev-dep) · golden vectors (`insta`) · fuzz target in `fuzz/` · Miri on unsafe modules · loom for lock-free structures · criterion baseline gate (5% ratchet, Phase 6 methodology) · UBS scan before commit.

---

## 5. Phase plan

Effort keys: S < 1 day · M = 1–3 days · L = 1–2 weeks · XL = multi-week campaign. Reductions are measured against the 132-crate default graph (or the named feature graph).

### Phase 0 — Hygiene (DONE 2026-07-23, this session)
`cargo update` lockfile refresh; **remove `crossbeam-deque` + `hkdf` (dead)**; bump `base64`→0.23 (with `default-features = false` — 0.23 default-enables an *unsafe SIMD* feature we do not want), `lz4_flex`→0.14; queue `aes-gcm`/`chacha20poly1305` 0.11 generation harmonization. See `UPGRADE_LOG.md`. **Δ default graph: −2 immediately; −5 more when the AEAD generation dedups digest/crypto-common/block-buffer/cpufeatures/getrandom duplicates.**

### Phase 1 — Trivial tier (S each, ~1 agent-week total, Δ ≈ −14)
1. `hashbrown` → std/`DetHashMap` (2 sites).
2. `num_cpus`, `whoami` → std + `util/host.rs` stub.
3. `env_logger` → tracing shim; drop from `cli`.
4. `time` → own RFC3339-ns formatter (one call site); CLI standardizes on one time type.
5. `semver` → `util/version.rs` (`Version { major, minor, patch, pre }`, parse + `Ord`).
6. `hex` → `util/hex.rs` (encode/decode; SWAR baseline).
7. `base64` → `util/base64.rs` (STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD engines used today; RFC 4648 test vectors + differential vs old crate).
8. `bincode-next` → `codec/binary.rs` two-function deterministic codec for `distributed/snapshot.rs` + `types/typed_symbol.rs` (bump snapshot format version; migration shim for old traces not required — pre-1.0, no users).
9. `futures-lite` → `util/future.rs` (`block_on` with parker, `poll_fn`, `zip`, `race`, `yield_now`, `poll_once`). We ship an executor; importing a second one to test the first is absurd.
10. `slab` → generalize `TokenSlab` into `util/slab.rs`; port ~8 sites.
11. `visibility` → `asupersync_macros::make_pub` attribute (12 uses).
12. Move feature-gated e2e modules' tempfile usage under `cfg(test)`-safe helpers → demote `tempfile` to dev-dependency.
13. Fix the stale `crc32fast` manifest comment; delete the `mod regex` mock in `artifact.rs` (replace with the Phase-3 scanner or a plain split-on-digits parser now).

### Phase 2 — Own the platform layer (M–L each, Δ ≈ −10, removes `rustix`/`linux-raw-sys` and a cc shim)
1. **`polling` → `runtime/reactor/sys/{epoll,kqueue,iocp}.rs`** (L). The `Reactor` trait already isolates it to 3 files. Direct `epoll_ctl`/`epoll_wait` and `kevent` via libc/nix, oneshot+edge modes preserved, generation-tagged tokens unchanged. IOCP via windows-sys (already a dep). The dead reference file `runtime/reactor/macos.rs` (raw kqueue) is prior art in-tree. Unsafe: syscall wrappers only, fn-scoped, ledgered.
2. **`socket2` → `net/sys.rs`** (M). The 9 option-setters used today via `setsockopt` wrappers; kill the current triple-idiom overlap (socket2 vs `nix::fcntl` vs raw libc) — one blessed layer.
3. **`signal-hook` → `signal/sys.rs`** (M). `sigaction` + self-pipe (we already own a signal thread + Win32 event path); consts moved into `signal/kind.rs`.
4. **`sysinfo` → `util/host.rs`** (L). Linux `/proc/{pid}/stat|status|statm`, `/proc/meminfo`, `statvfs` (already via nix); macOS `sysctl`/`proc_pidinfo`; Windows paths already hand-written in `resource_monitor.rs`. Process signalling goes through one blessed `kill` wrapper (collapses today's three idioms: `libc::kill`, `sysinfo::kill_with`, signal-hook).
5. **`tempfile`/`xattr` → `fs/temp.rs` + nix xattr calls** (S–M).

### Phase 3 — Own the codecs and the CLI (L each, Δ ≈ −20 default, −40 for `cli` users)
1. **`prost` → `codec/proto.rs`** (L, highest leverage in this phase — prost is non-optional today). Wire codec: varint/zigzag/length-delimited (varint code already exists in `grpc/protobuf.rs`), field tag/skip, canonical encode. Hand-written message structs for: gRPC health/reflection surfaces we ship, OTLP `Export{Trace,Metrics,Logs}ServiceRequest` subset, `length_delimited` codec. Differential tests vs prost (dev-dep) with proptest round-trips. Frees `bytes`, `anyhow`, `itertools`, `prost-derive` from the default graph.
2. **`rmp-serde` → `trace/msgpack.rs`** (M). MessagePack writer/reader for the trace format; bump trace-format version; `trace/compat.rs` already exists for versioning.
3. **`serde_yaml` → JSON scenarios** (M). serde_yaml is deprecated upstream; frankenlab scenario files migrate to JSON (`serde_json` already ubiquitous) with a `yaml→json` one-shot converter script for the corpus.
4. **`toml` → `config/toml.rs`** (M). Reader for the documented RuntimeBuilder/atp config subset (tables, arrays, strings, ints, bools, datetimes-as-strings) + a pretty writer for the 3 write sites. Spec-subset documented in the module header; differential-fuzzed vs `toml` (dev-dep).
5. **`clap` → `cli/parse.rs`** (L). Declarative table-driven parser (long/short flags, subcommand tree, `--help` generation, value enums, defaults). The command tree is already centralized in `cli/args.rs`/`cli/atp_command_tree.rs`, so this is a re-plumbing, not a redesign. `atp-cli` then needs zero external crates beyond `tls`.
6. **`chrono` → `util/time_fmt.rs`** (M). `UtcTimestamp` (i128 ns) + RFC3339 format/parse + serde impls; ports the CLI/benchmark structs.
7. **`regex` → `observability/redact.rs`** (M). Hand-rolled scanners for the 4 fixed PII patterns (email/SSN/card/phone — each is a simple DFA over bytes); user-supplied patterns get a documented literal/wildcard/char-class subset matcher (~300 lines, no backtracking, linear time — arguably an upgrade: no ReDoS).
8. **`opentelemetry` + `opentelemetry_sdk` → native OTLP** (L). `otel.rs` is already a 9,427-line adapter; re-point it at our own instrument types + OTLP/HTTP export via `codec/proto.rs`. The `metrics` feature then adds **zero** external crates.

### Phase 4 — Hot-path primitives, ledgered unsafe where measured (L–XL, Δ ≈ −8, the perf showcase)
1. **`parking_lot` → nightly `std::sync::nonpoison` Mutex/RwLock** (L, *measure first*). std's futex-based locks + the nightly nonpoison API remove the poisoning objection with zero unsafe of ours. Gate: criterion on `scheduler_benchmark`, `next_task_hotpath`, channel benches; if std regresses >2% p50 on any tracked row, build `sync/rawlock.rs` (futex/WaitOnAddress/os_unfair_lock parking, ~600 lines, ledgered) instead. Either way `parking_lot`+`parking_lot_core`+`lock_api` leave the graph; ~173 files change imports only (`ContendedMutex` already wraps, so most call sites are one alias away).
2. **`crossbeam-queue` → `util/lockfree.rs`** (XL). Vyukov bounded MPMC (`ArrayQueue` replacement) + segmented unbounded MPMC (`SegQueue` replacement for the global injector + epoch GC). Loom models for both (loom is already wired); Miri clean; ABA guarded by pointer tagging on the segment ring. This is the single most correctness-sensitive replacement in the plan — it lands with the largest test budget: loom + fuzz + 48-h stress soak on the 64C box before the old crate is deleted.
3. **`smallvec` → `util/inline_vec.rs`** (L). `InlineVec<T, const N: usize>` — `MaybeUninit<[T; N]>` inline arm + `Vec<T>` spill; the ~10 APIs we use; Miri + proptest; ledger row for the uninit core.
4. **`memchr` → `util/simd_scan.rs`** (M, **zero unsafe**). `std::simd` memchr/memchr_iter/memmem (two-way + SIMD prefilter). Nightly portable SIMD lowers to NEON/AVX2 without intrinsics; bench vs memchr on the h1 parse corpus; keep memchr as dev-dep oracle.
5. **`crc32fast` → `util/crc32.rs`** (M). Safe slicing-by-16 baseline (~6 GB/s); optional ledgered ARMv8 CRC32 + x86 CLMUL kernels behind `simd-intrinsics` (same feature as GF(256)).
6. **`pin-project` → `asupersync_macros::pin_project`** (L). Minimal projection derive covering our 30 usage sites (named projections included); the generated unsafe is ours to ledger — one macro, audited once, replacing a 6-crate proc-macro chain.
7. **`thiserror` → `asupersync_macros::Error`** (M). Derive supporting `#[error("…")]`, `#[from]`, `#[source]` exactly; attribute-compatible so the 111 files change only the derive path.

### Phase 5 — Strategic big-ticket (XL each; the C-code eviction phase)
1. **FrankenSQLite** (§7.1) — `sqlite` feature deprecated in favor of fsqlite's asupersync-native API. Removes `rusqlite`, `libsqlite3-sys` (bundled C), `sqlparser`, `psm`/`stacker`.
2. **Kafka** (§7.3) — native wire client (~6–10k lines: produce/fetch/metadata/offsets, SASL PLAIN/SCRAM via existing sha2/hmac, TLS via existing rustls) **or** feature removal. Decision gate: does anything downstream actually use `kafka` today? If not, remove now, reimplement natively when demanded.
3. **nkeys → `security/nkey.rs`** (§7.4) — base32 + CRC-16/XMODEM + prefix codec (~200 lines) directly on `ed25519-dalek`. Kills the 46-crate nkeys closure down to the dalek core and removes the last old-generation `sha2 0.10` dup when dalek's digest-0.11 generation lands.
4. **x509 SPKI/SAN extractor → `tls/der_min.rs`** (§7.5).
5. **Compression:** drop `brotli` from the negotiation menu; own LZ4 block codec (`trace-compression`); DEFLATE own-implementation as a stretch goal (until then flate2/miniz_oxide is pure Rust and acceptable).
6. **`unicode-normalization` →** checked-in NFC tables (generated offline from UCD, with the generator script committed) powering the one `.nfc()` path-safety call.
7. **rustls crypto provider** (§6.2): evaluate `rustls-graviola` / pure-Rust providers to retire `ring`'s C/asm; adopt when interop + performance clear the bar. Out of scope: writing our own TLS.

### Phase 6 — Continuous enforcement
- **Dependency budget contract:** `artifacts/dependency_budget_contract_v1.json` + `tests/dependency_budget_contract.rs` — asserts the exact allowed direct-dependency set and a ceiling on the default-graph crate count (ratchet-down only, like the coverage ratchet). Any new dependency fails CI until the contract row (with justification) is added — the same fail-closed pattern as the no-tokio proof lanes.
- `cargo deny`/`cargo audit` lanes (advisories, licenses, duplicate-version ratchet); `cargo vet`-style review notes for the KEEP tier.
- The AGENTS.md "Key Dependencies" table becomes generated-from-contract, never hand-maintained.

**Projected end-state default consumer graph: ~40–50 crates** — serde family + RustCrypto keeps + dalek + libc/nix/windows-sys/wasm boundary + io-uring — versus 132 today. `+tls` adds only the rustls core. `+cli`, `+metrics`, `+sqlite` (via fsqlite), `+kafka` add **zero** external crates.

---

## 6. What we deliberately keep (and why that's the right call)

### 6.1 Cryptography is not a place for NIH
`sha1/sha2/hmac/subtle/zeroize/getrandom/aes-gcm/chacha20poly1305/ed25519-dalek` are pure-Rust, RustCrypto-audited, tiny, and security-load-bearing (CAS integrity, Macaroons, SCRAM, ATP AEAD, identity signatures). A home-grown constant-time compare that the compiler quietly un-constant-times, or a GHASH with a timing side channel, is a catastrophic trade for removing ~25 small crates. **Non-negotiable keep.** (We *do* remove crypto-adjacent packaging: nkeys' text codec, x509 parsing for pins — the wrappers, not the primitives.)

### 6.2 rustls and the ring problem
rustls itself is exactly the kind of dependency worth having: the QUIC packet protection, TLS 1.3 state machine, and X.509 chain validation we build on. The blemish is the `ring` provider (C + assembly). Path: (a) short-term, keep ring; (b) medium-term, trial `rustls-graviola` (pure-Rust/formally-verified-asm provider by the rustls author) or the RustCrypto provider on the encrypted ATP matrix — adopt if the 500M/5G encrypted cells hold; (c) long-term, a FrankenTLS is explicitly **out of scope** until the rest of this plan is done and the threat model demands it.

### 6.3 serde / serde_json
~4,570 derives and 1,419 `json!` sites make serde the type-model substrate of the codebase, and every FrankenSuite sibling (franken_kernel/evidence/decision included) speaks it. Replacing it is a program, not a project, and the payoff is small: serde's closure is ~7 tightly-audited crates. **Keep; revisit only after Phases 1–5 land**, at which point a `franken-serde` (derive + JSON DOM, drop-in attr-compatible) could be scoped across the whole suite at once — that decision belongs at suite level, not to asupersync alone.

### 6.4 FFI bedrock
`libc`, `windows-sys`, `wasm-bindgen`/`web-sys`/`js-sys`, `io-uring`: these *are* the platform boundary; "replacing" them means transcribing syscall numbers and ABI structs by hand for zero safety gain. `nix` stays for the cmsg/SCM_RIGHTS/sendmmsg/GSO marshaling that would otherwise be hand-rolled unsafe.

---

## 7. Flagship replacement designs

### 7.1 FrankenSQLite integration (replaces `rusqlite` + `sqlparser`)
**Constraint discovered in audit:** frankensqlite already depends on asupersync (`fsqlite-wal`, `fsqlite-harness`, `linux-asupersync-uring` VFS, optional `async-api`). A naive `asupersync → fsqlite-core` dependency creates a cross-repo cycle the moment a consumer enables fsqlite's asupersync-backed features.
**Design:** integrate in the *other* direction. asupersync's `sqlite` feature is deprecated and removed; **FrankenSQLite's `async-api` feature (which already depends on asupersync) becomes the blessed integration point** — it exposes the cancel-correct, `Cx`-threaded connection API (blocking-pool bridge, budget-derived progress interrupts, prepared-statement cache) that `src/database/sqlite.rs` provides today, implemented against `fsqlite-core` instead of C SQLite. The 7,258-line module's API surface (typed rows, transactions, interrupt handles, budget timeouts) is ported into fsqlite as `fsqlite-asupersync` glue. asupersync keeps a compat re-export doc pointing users at fsqlite.
**Wins:** bundled SQLite C amalgamation gone; `sqlparser` gone (fsqlite has its own real parser — the statement-class allowlist becomes a query against fsqlite's AST, eliminating the parser-divergence risk `sqlparser` was added to fix); MVCC concurrent writers + RaptorQ durability for free.
**Tests:** fsqlite's conformance harness + port of the existing sqlite e2e suite; differential vs rusqlite (dev-dep in fsqlite's harness, already their methodology).

### 7.2 The scheduler-adjacent primitives (parking_lot / crossbeam-queue / smallvec)
Measured-first discipline (§4.6). Bench harnesses already exist (`scheduler_benchmark`, `next_task_hotpath`, `spawn_throughput`, `semaphore_benchmark`). Expected outcomes based on current knowledge: std futex Mutex ties parking_lot on uncontended paths (both are one CAS) and the scheduler's single-lock multi-lane design keeps contention low — so the zero-unsafe std path likely wins Phase 4.1. The Vyukov MPMC (4.2) is where real unsafe concentrates; it gets loom + Miri + the 48-h soak, and its ledger row cites the exact paper + invariants. `InlineVec` (4.3) reuses the RaptorQ ledger pattern. All three keep the incumbent crate as dev-dep oracle for differential stress tests.

### 7.3 Kafka: native or nothing
librdkafka via cmake is the single worst build-graph citizen (C, cmake, pkg-config, network-facing C parser surface). The audit found **zero native wire-protocol code** — the "KIP-98" manifest comment is aspirational. Two honest options: **(a)** delete the `kafka` feature now (it's optional and Early-status; consumers get a clear removal notice), reintroduce later as `messaging/kafka_wire.rs` when a real consumer exists; **(b)** build the native client first (produce/fetch/metadata/offset-commit, RecordBatch v2 with our own crc32c, SASL SCRAM on existing sha2/hmac, TLS via existing rustls) and swap. Recommendation: **(a) then (b)** — remove C now, build native on demand. Either branch removes cmake+C from the graph immediately.

### 7.4 nkeys → `security/nkey.rs`
The NKey format is: prefix byte(s) + Ed25519 key + CRC-16/XMODEM, base32 (RFC 4648, no padding). That is ~200 lines including exhaustive test vectors from the NATS spec repo. Depend on `ed25519-dalek` directly for the actual signatures (KEEP tier). Removes `nkeys`, `signatory`, `data-encoding`, and assorted old-generation RustCrypto duplicates from the *default* graph. Wire-compat proven by differential vectors vs nkeys (dev-dep) covering seed↔public round-trips, all three key-pair types we use (User/Cluster/Operator), sign/verify against NATS-generated fixtures.

### 7.5 x509-parser → `tls/der_min.rs`
Scope is deliberately microscopic: (1) walk Certificate → TBSCertificate → SubjectPublicKeyInfo and return the raw SPKI DER bytes (for SHA-256 pinning); (2) walk extensions → SubjectAlternativeName → DNSName/IPAddress values (for the native-QUIC verifier's hostname check). A strict DER TLV reader (definite lengths only, no BER, depth-capped, length-checked) is ~400 lines. **This is security-sensitive parsing**, so it ships only with: differential fuzzing vs x509-parser (dev-dep) over a corpus of real + mutated certs, the OpenSSL/frankenca test corpus, fail-closed on any parse ambiguity (a pin/SAN we can't extract = verification failure, never a skip). Removes the nom/asn1-rs/der-parser/oid-registry chain (~9 crates) from the `tls` graph.

### 7.6 `codec/proto.rs` (replaces prost)
Varint/zigzag/tag/skip + canonical struct codegen *by hand* for the finite message set we ship (gRPC health/reflection/status-details, OTLP trace/metrics/logs export subset). No derive, no build-time codegen — the structs are written out, which is exactly what makes them auditable and lets us fuse encode-with-length-prefix into the h2 DATA frame writer (a real perf win prost can't give us: no intermediate `BytesMut`, direct into the connection's write buffer). Differential round-trip vs prost under proptest; OTLP goldens vs `opentelemetry-proto` fixtures (both stay dev/fuzz-only).

---

## 8. Risk register

| Risk | Mitigation |
|---|---|
| Home-grown crypto-adjacent code (nkey codec, DER walker) has a subtle bug | differential fuzzing vs incumbent, fail-closed posture, incumbents kept as dev-dep oracles, security-review bead before each ships |
| Lock-free MPMC replacement has a liveness/ABA bug that only shows at scale | loom + Miri + 48-h 64C soak + staged rollout behind a feature flag defaulting to the old crate for one release |
| Trace/snapshot format churn (rmp/bincode replacements) breaks replay tooling | format-version bumps + `trace/compat.rs` readers; pre-1.0 stance means no external migration burden |
| Perf regressions from de-SIMD-ing (memchr, crc32, base64) | criterion 5% ratchet gate is already mandatory; `std::simd` baselines measured before old crate removal |
| Phase 4 primitives add unsafe to a `deny(unsafe_code)` codebase | fn-scoped `#[allow]` + unsafe-boundary ledger rows + proof notes (existing Phase-6 gate covers `src/obligation`/`src/safety` and any changed file containing `unsafe`) |
| serde_yaml removal breaks frankenlab scenario corpus | one-shot converter + goldens for every existing scenario file |
| FrankenSQLite maturity vs bundled SQLite | staged: fsqlite integration lands behind its own feature while `sqlite` is deprecated-but-present for one release; the existing sqlite e2e suite runs against both during the overlap |
| Agent-swarm merge conflicts during 173-file mechanical migrations (parking_lot, thiserror) | file reservations per directory batch + the established parallel-subagent mechanical-change protocol (no scripts, per AGENTS.md) |

---

## 9. Sequencing note for the swarm

Phases 1–3 are embarrassingly parallel (independent crates, disjoint files) — ideal bead-per-crate work for the agent fleet. Phase 4 items are serialized behind their measurement gates and land one at a time with soak windows. Phase 5 items are campaigns with their own epics. Beads: epic **`asupersync-ir2uf0`** with phase children `asupersync-d24mms` (P1), `asupersync-3u3tej` (P2), `asupersync-5z2scg` (P3), `asupersync-0h6myr` (P4), `asupersync-ym2wtv` (P5), `asupersync-mnotoo` (P6). Campaign-scale items inside P4/P5 get their own child beads when picked up.

---

## Appendix A — Default-graph crate list (2026-07-23, post-refresh)

132 crate-versions; see `scripts/`-reproducible command in Appendix C. Notable clusters: serde family (7), RustCrypto new-gen (digest/sha2/hmac/subtle/zeroize + AEAD chains, ~25), nkeys/dalek old-gen chain (~17), prost chain (5 incl. bytes/anyhow/itertools), sysinfo (2–4 per-OS), polling/tempfile/xattr → rustix/linux-raw-sys/fastrand (5), proc-macro chain (syn×2/quote/proc-macro2/unicode-ident, 5).

## Appendix B — Feature-cost table

| Feature | Adds today | Adds at end-state |
|---|---|---|
| (default) | 132 | ~45 |
| `tls` | +26 (rustls, ring, x509-parser chain, webpki) | +~12 (rustls core + provider) |
| `sqlite` | +10 incl. bundled C | 0 (moved to FrankenSQLite) |
| `kafka` | +13 incl. librdkafka/cmake | 0 (native or removed) |
| `metrics` | +13 | 0 (native OTLP) |
| `cli` | +43 | 0 |
| `compression` | +8 | +6 → 0 (stretch) |

## Appendix C — Reproduction commands

```bash
# consumer graph counts (per feature)
cargo tree -p asupersync --locked -e normal --prefix none [--features F] \
  | awk '{print $1}' | sort -u | grep -vcE '^(asupersync$|franken-|asupersync-macros)'

# native-code detection (build.rs / links / cc / cmake / bindgen)
cargo metadata --format-version 1 --all-features   # then filter targets kind=custom-build, .links, build-deps

# no-tokio production proofs — unchanged, see AGENTS.md "Async Runtime: THIS IS IT"
```
