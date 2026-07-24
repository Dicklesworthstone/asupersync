# Comprehensive Dependency Replacement Plan — Asupersync

> **Goal:** systematically shrink asupersync's external dependency surface to a small, audited core, replacing everything else with home-grown, strict-memory-safe Rust that is ultra-optimized for Apple Silicon (NEON, high single-core IPC) and high-core-count x86 (AVX2/AVX-512, cross-CCX-aware), or with FrankenSuite projects we control.
>
> Audit date: 2026-07-23 (SapphireHill). **Rev 2 (2026-07-24):** corrected after an adversarial fresh-eyes verification pass — Phase 0 is now recorded as landed (commit `a86bfb3a6`), graph numbers carry explicit units and pre/post-Phase-0 baselines, and several factual claims were fixed (CachePadded alignment, signal-hook cc, nix-xattr, fsqlite cycle mechanics, nkeys closure size). Measurement commands in Appendix C.

---

## 1. Philosophy

External library dependencies are an anti-pattern for this project, for four reasons:

1. **Supply chain.** Every one of the ~376 crates in our full workspace graph is a person or CI pipeline that can be compromised. The default *consumer* graph alone is 121 external crates (130 counting duplicate versions) — over a hundred trust relationships to ship a runtime whose core value proposition is *correctness you can trust*.
2. **Memory safety.** We `deny(unsafe_code)` and ledger every exception — then link in `ring` (C + assembly), bundled SQLite (250k lines of C), and `librdkafka` (C, via cmake). The safety story is only as strong as the weakest native blob.
3. **The generality tax.** One-size-fits-all crates carry code, features, and compile time we never use (`sysinfo` for five call sites; `clap`'s 21-crate closure for two arg modules; `nkeys`' 36-crate closure for one Ed25519 wrapper). Purpose-built code is smaller, faster, and fully understood.
4. **Performance ownership.** Our continuous optimization campaigns (scheduler lock traffic, RaptorQ GF(256) SIMD, timer wheel) stop at crate boundaries. Code we own keeps getting faster; code we import doesn't.

The plan is **not** dogmatic: cryptographic primitives, the TLS stack, serde's derive ecosystem, and platform FFI bedrock stay (Section 6). Dev-dependencies used as *differential-testing references* (httparse, raptorq, sqlx, redis, tokio) are an asset for proving replacements correct — but note they are only outside the *consumer* threat model, not ours: dev-deps and build scripts execute on the machines and CI lanes that build and publish releases, so Phase 6 extends supply-chain controls to the dev/build graph, GitHub Actions, and the npm packages side rather than pretending "dev-only" means "harmless".

---

## 2. Audit Snapshot (2026-07-23)

### 2.1 Graph size

Unit note: "names" = unique external crate names; "crate-versions" counts duplicate major versions separately. Per-feature rows are **name** counts.

| Graph | Pre-Phase-0 baseline | Post-Phase-0 (landed `a86bfb3a6`) |
|---|---|---|
| Default consumer graph (`cargo tree -p asupersync -e normal`) | **124 names / 132 crate-versions** | **121 names / 130 crate-versions** |
| `+tls` | 150 | 147 |
| `+tls-native-roots` | 152 | 149 |
| `+sqlite` | 134 | 131 |
| `+kafka` | 137 | 134 |
| `+metrics` | 137 | 134 |
| `+cli` | **167** | 164 |
| `+atp-cli` | 165 | 162 |
| Workspace, all features, incl. dev/build deps | ~376 external / 390 packages | ~374 |

Verified (2026-07-24): a synthesized out-of-workspace consumer with default features resolves the **same 130 crate-versions** as the in-workspace `cargo tree -p asupersync -e normal` — today the in-workspace count is not distorted by dev-dep feature unification. That equality is contingent, so the Phase-6 budget contract measures from a synthesized consumer crate, not in-workspace (Appendix C).

Scope note: the `franken-kernel`/`franken-evidence`/`franken-decision` workspace members are excluded from these counts as first-party code, but for an external consumer they are three additional (first-party, registry-published) crates; their externals (serde, serde_json) are already in the graph.

### 2.2 Native code (C/C++/asm) in the graph — the worst offenders

| Crate | Native payload | Pulled by | When |
|---|---|---|---|
| `ring` | C + hand-written assembly | `rustls/ring` provider | `tls` feature |
| `libsqlite3-sys` | bundled SQLite C amalgamation (cc + bindgen + pkg-config) | `rusqlite` | `sqlite` feature |
| `rdkafka-sys` | `librdkafka` C via **cmake** | `rdkafka` | `kafka` feature |
| `psm`/`stacker` | C/asm stack-probing | `sqlparser` (via `recursive`) | `sqlite` feature |
| `generator` | C context-switching | `loom` | `loom-tests` feature — **feature-gated normal dep, not dev-scoped**: enabling the feature puts C in a normal build |
| `alloca` | C | `criterion` (Windows) | dev-only |

Corrected from Rev 1: **`signal-hook` does *not* compile C in our graph.** Its `cc` build-dependency is exercised only under its `extended-siginfo-raw` feature, which we do not enable; the lockfile shows signal-hook's resolved deps are exactly `libc` + `signal-hook-registry`. (Lesson: `cargo metadata` lists declared build-deps regardless of feature activation — attribution must be lockfile-verified.)

### 2.3 Version-duplication bloat in the *default* graph

Two RustCrypto generations remain linked simultaneously **after** the Phase-0 AEAD bump: `sha2` 0.10 + 0.11, `digest` 0.10 + 0.11, `block-buffer` ×2, `crypto-common` 0.1 + 0.2, `const-oid` ×2, `cpufeatures` 0.2 + 0.3, `getrandom` 0.2 + 0.4, and (new with aead 0.6) `rand_core` 0.6 + 0.10. The sole remaining driver is **`nkeys → ed25519-dalek 2.2`**, which pins the old generation. Dedup therefore lands with Phase 5.3 (nkeys replacement) **and requires an upstream `ed25519-dalek` release on the digest-0.11 generation — a dependency outside this plan's control**; until then the dalek chain keeps the old generation alive no matter what we do. `syn` 2 + 3 are both present (serde_derive moved to syn 3; the rest of the ecosystem, including our own macros, has not).

### 2.4 Dead and misplaced dependencies found

| Finding | Status |
|---|---|
| `crossbeam-deque` — **zero references anywhere**; work-stealing is fully home-grown (`runtime/scheduler/{local_queue,stealing,intrusive}.rs`) | **removed in Phase 0** (took transitive `crossbeam-epoch` with it) |
| `hkdf` — **zero references**; HKDF is hand-rolled on `hmac` in `net/atp/handshake/key_schedule.rs` + `security/key.rs` (RFC 5869 + RFC 8446 expand-label, bead asupersync-3epgv2) | **removed in Phase 0** |
| `tempfile` is a *normal* dep because two feature-gated non-test modules use it at module scope: `src/atp/benchmark/suite.rs` (`benchmark-adapters`) and `src/test_logging.rs` (`test-internals`). *(Rev 1 wrongly blamed the `real_*_e2e_tests` e2e modules — they don't reference tempfile.)* Since both users are feature-gated, tempfile can become an **optional dep tied to those features** — cheaper than the Rev-1 demotion story | Phase 1 |
| Three orphaned files (`src/real_fs_dir_fs_vfs_integration_e2e_tests.rs`, `src/real_integration_scenarios_e2e_tests.rs`, `src/real_distributed_e2e_tests.rs`) `use tempfile` at module scope but are **not declared as modules anywhere — they never compile**. Wire-or-remove decision needs owner sign-off (no-deletion rule) | flagged, Phase 1 bead |
| `env_logger` enabled by all of `cli` but consumed only by `src/bin/offline_tuner.rs` (2 lines) | remove (Phase 1) |
| `time` + `chrono` both in the CLI; `time` has exactly **one** call site (ns→RFC3339 in `bin/asupersync.rs`) | consolidate (Phase 1) |
| `num_cpus` + `whoami`: one call site each in `atp/benchmark/mod.rs`; std (`available_parallelism`) covers it | remove (Phase 1) |
| `src/net/atp/chunk/artifact.rs` contains a local `mod regex` **mock** ("Temporary regex module", simplified matcher) in production code | replace with a real scanner (no-mock policy), Phase 1 |
| Stale `crc32fast` manifest comment (claimed Kafka KIP-98; actual users are `atp/journal`, `atp/sdk/stream`, `masque`) | **fixed in Phase 0** |

### 2.5 What the code *actually* uses (usage-mapping summary)

Full per-crate detail lives in the audit transcripts; the load-bearing facts (spot-verified to the line in the Rev-2 pass — `sqlite.rs` is exactly 7,258 lines, `otel.rs` exactly 9,427):

| Crate | Real surface | Files |
|---|---|---|
| `serde` | `#[derive(Serialize/Deserialize)]` — **~4,600 individual trait derives** | ~268 |
| `serde_json` | `json!` ×~1,450, `Value` ×376, to/from_string — DOM style, no streaming | ~247 |
| `parking_lot` | `Mutex` ×322, `RwLock` ×57 — **no Condvar/Once** — scheduler/channel hot paths | ~173 |
| `thiserror` | derive only (`#[error]`, `#[from]`, `#[source]`) | ~112 |
| `tempfile` | `TempDir`/`NamedTempFile`, overwhelmingly test fixtures | 80 |
| `futures-lite` | `futures_lite::future::block_on` ×728 qualified sites (mostly tests/bridges), `poll_fn`, `zip`, `race`, `yield_now` | ~150 |
| `smallvec` | inline waker/task batches (`[Waker;8]`, `[TaskId;32]`…) on hot paths | ~42 |
| `pin-project` | `#[pin_project]` on stream/service combinator futures | 30 |
| `hex` / `base64` | encode/decode only | 49 / 19 |
| `nkeys` | `KeyPair` seed/sign/verify — canonical Ed25519 identity for ATP peers, capability tokens, agent-swarm control plane, NATS auth | 6 |
| `sha2` | digest + KDF backbone (CAS, transcripts, Merkle, SCRAM) | ~90 |
| `aes-gcm`/`chacha20poly1305` | ATP object/mailbox AEAD (detached, in-place). QUIC packet AEAD is **rustls/ring**, not these | 2 / 1 |
| `x509-parser` | SPKI extraction for cert pinning + SAN matching in native-QUIC verifier | 5 |
| `prost` | `Message` codec for gRPC **+ OTLP export + `codec/length_delimited`** — non-optional, drags `bytes`+`anyhow`+`itertools` into the default graph | 7 |
| `rmp-serde` | binary trace-file format | 6 |
| `bincode-next` | **2** production files (snapshot payload, typed symbols); also the sole source of the `pastey` proc-macro dep | 6 |
| `semver` | `Version` parse/compare only | 3 |
| `memchr` | `memmem`/`memchr_iter` in HTTP/1 + Redis parsing | 4 |
| `hashbrown` | 2 call sites (std's HashMap *is* hashbrown) | 2 |
| `slab` | `Slab<T>`; home-grown `TokenSlab` (generation-tagged) already exists | ~7 |
| `crossbeam-queue` | `SegQueue` (global injector, epoch GC), `ArrayQueue` ×2 | 6 |
| `polling` | `Poller`/`Events`/`PollMode` — the epoll/kqueue/IOCP loop | 3 |
| `socket2` | socket builders + options | ~10 |
| `nix` | **cmsg/SCM_RIGHTS, sendmmsg/recvmmsg, UDP GSO** (irreplaceable part), statvfs, fcntl | 11 |
| `sysinfo` | daemon process control (`kill_with`), RSS monitor, diag bundles, os-version strings | 5 |
| `signal-hook` | `iterator::Signals` thread + consts | 3 |
| `rusqlite`+`sqlparser` | one 7,258-line module; prepared cache, `progress_handler` budget timeouts, interrupt handles; sqlparser = statement-class allowlist | 1 |
| `rdkafka` | pure librdkafka wrapper — **no native wire protocol exists** | 2 |
| `opentelemetry`/`_sdk` | metrics instruments + span data model, one adapter module (`otel.rs`, 9,427 lines) | 1 |
| `regex` | 4 fixed PII-redaction patterns + user-supplied patterns (otel) | 2 |
| `clap` | derive-only command tree, 2 arg modules + 4 binaries | 6 |
| `unicode-normalization` | one `.nfc()` call site for path-homograph safety | 1 |

**Home-grown infrastructure already in-tree** (proof this codebase can do this): work-stealing deques + intrusive queues/heaps, `TokenSlab`/`WaiterSlab`, `DetHashMap`/`DetHasher`, `Arena`, `CachePadded` (`util/cache.rs` — **64-byte aligned today**; see Phase 4.8), deterministic RNG, hand-rolled HKDF, a `tracing_compat` no-op shim layer, and ledgered unsafe SIMD (RaptorQ GF(256) AVX2/NEON kernels). *(Rev-1 correction: the varint code in `grpc/protobuf.rs` is `#[cfg(test)]`-only conformance-helper code — the production `ProstCodec` delegates entirely to prost. Useful as a differential oracle, not as reusable production plumbing.)*

---

## 3. Classification: every dependency, one verdict

**Legend:** `REMOVE` = delete, nothing to replace · `STD` = replace with std/existing in-tree code · `OWN` = write it ourselves · `FRANKEN` = replace with a FrankenSuite project · `KEEP` = deliberate, justified external dependency · `DEV-KEEP` = dev-only reference/verification tool, keep.

### Production (normal) dependencies

| Crate | Verdict | Phase | Note |
|---|---|---|---|
| `crossbeam-deque` | REMOVE | 0 ✅ | dead (+ transitive crossbeam-epoch) |
| `hkdf` | REMOVE | 0 ✅ | dead (hand-rolled impl already in use) |
| `hashbrown` | STD | 1 | 2 sites → `std::collections`/`DetHashMap`; sheds foldhash/rapidhash/allocator-api2 |
| `num_cpus` | STD | 1 | `std::thread::available_parallelism` (benchmark-adapters graph) |
| `whoami` | STD | 1 | fold into `util/host.rs` os-string (benchmark-adapters graph) |
| `env_logger` | REMOVE | 1 | 2 lines in offline_tuner → tracing shim (`cli` graph) |
| `time` | REMOVE | 1 | 1 call site → own RFC3339 formatter (`cli` graph) |
| `semver` | OWN | 1 | `Version` parse/compare + serde impls; SemVer pre-release precedence makes this ~150–200 lines, not 40 |
| `hex` | OWN | 1 | ~60 lines scalar; SIMD path optional later |
| `base64` | OWN | 1 | ~200 lines, RFC 4648 std/url-safe/no-pad engines we use |
| `bincode-next` | OWN | 1 | 2 sites → own deterministic binary codec; also removes `pastey`, `bincode_derive`, `virtue`, `unty` |
| `futures-lite` | OWN | 1 | `block_on`/`poll_fn`/`zip`/`race`/`yield_now` in `util/future.rs` |
| `visibility` | OWN | 1 | 12 uses of one attr → mini-macro in `asupersync-macros` |
| `slab` | STD/OWN | 1 | unify on in-tree `TokenSlab` family |
| `tempfile` | OPTIONALIZE → DEV-KEEP | 1 | make optional on `benchmark-adapters`/`test-internals` (its only non-test users), then it's exactly the blessed dev-tier fixture crate. Small own `fs/temp.rs` helper only if a real production need appears — **no dev-tier rewrite** (Rev-1's Phase-2 OWN verdict retracted as zero-benefit) |
| `xattr` | OWN or KEEP | 2 | **nix has no xattr API** (Rev-1 error): replacement means a raw-libc unsafe shim (ledgered) preserving deref/no-deref (`getxattr` vs `lgetxattr`) semantics and macOS's different signature (`options`/`position` args). Only worth it as part of the rustix eviction; otherwise KEEP |
| `polling` | OWN | 2 | direct epoll/kqueue behind existing `Reactor` trait. `rustix` leaves the graph only when polling **and** tempfile (P1) **and** xattr (P2) all land — three parents |
| `socket2` | OWN | 2 | fold into own sockopt layer in `net/sys.rs` |
| `signal-hook` | OWN | 2 | own signal layer on libc + windows-sys. Payoff is one fewer crate + one blessed signal idiom (Rev-1's "removes a cc shim" was wrong — no C compiles in our feature set) |
| `sysinfo` | OWN | 2 | `util/host.rs`: /proc + sysctl + existing windows-sys calls |
| `prost` | OWN | 3 | `codec/proto.rs` wire codec + hand-written gRPC/OTLP messages; frees `bytes`/`anyhow`/`itertools` |
| `rmp-serde` | OWN | 3 | own MessagePack for trace format (versioned) |
| `toml` | OWN | 3 | config-subset reader/writer |
| `serde_yaml` | REMOVE | 3 | **deprecated upstream**; migrate scenarios to JSON |
| `clap` | OWN | 3 | own derive-less declarative CLI parser |
| `chrono` | OWN | 3 | own UTC timestamp + RFC3339 (serde-compatible) |
| `regex` | OWN | 3 | fixed PII scanners + subset matcher that **fails closed** on unsupported syntax (§5 Phase 3.7) |
| `opentelemetry`/`_sdk` | OWN | 3 | native OTLP exporter on own proto codec |
| `parking_lot` | STD→OWN | 4 | **measure first**: nightly `std::sync::nonpoison` (`#![feature(nonpoison_mutex, nonpoison_rwlock)]`, tracking #134645); own futex locks only if std loses |
| `crossbeam-queue` | OWN | 4 | Vyukov bounded MPMC (ArrayQueue) + segmented unbounded MPMC (SegQueue), loom-verified |
| `smallvec` | OWN | 4 | `util/inline_vec.rs`, ledgered `MaybeUninit` core |
| `memchr` | OWN | 4 | `std::simd` memchr/memmem — **zero unsafe on aarch64 (NEON in baseline) and x86 SSE2 baseline; matching memchr's AVX2 needs ledgered `#[target_feature]` dispatch** (§5 Phase 4.4) |
| `crc32fast` | OWN | 4 | slicing-by-16 safe baseline (realistic ~2–4 GB/s/core) + optional ledgered CLMUL/ARM-CRC. Must grow a CRC-32**C** (Castagnoli) variant if the native Kafka client lands — different polynomial |
| `pin-project` | OWN | 4 | own projection derive in `asupersync-macros`; **nets −2 crates** (syn/quote/proc-macro2 stay regardless); must enforce pin-project's negative guarantees (§5 Phase 4.6) |
| `thiserror` | OWN | 4 | own `#[derive(Error)]`, attr-compatible; **nets −2 crates** |
| `rusqlite` + `sqlparser` | FRANKEN | 5 | **FrankenSQLite** (§7.1) — removes bundled C SQLite + psm/stacker |
| `rdkafka` | REMOVE → OWN | 5 | drop the feature now, native wire client on demand (§7.3); either way librdkafka+cmake go |
| `nkeys` | OWN | 5 | own NKey base32+CRC16 codec directly on `ed25519-dalek` (§7.4) |
| `x509-parser` | OWN | 5 | minimal DER walker for SPKI + SAN only, differential-fuzzed (§7.5) |
| `flate2` | OWN (stretch) | 5 | own DEFLATE; until then it's pure-Rust miniz_oxide (acceptable) |
| `brotli` | REMOVE | 5 | drop from the HTTP menu **and** retire the ATP `CompressionAlgorithm::Brotli` manifest variant fail-closed (§5 Phase 5.5) |
| `lz4_flex` | OWN | 5 | LZ4 block codec — realistically ~1–1.5k lines for a safe, competitive encoder+decoder |
| `unicode-normalization` | OWN | 5 | vendored NFC tables (checked-in, generated offline) |
| `tracing` / `tracing-subscriber` | KEEP | — | optional, already isolated behind the `tracing_compat` shim + daemon/test-internals gates; revisit after Phase 3's own-OTLP work if a native structured backend obviates them |
| `backtrace` / `rustc-demangle` | KEEP | — | optional (`lab-stack-traces`), debugging-only surface |
| `loom` | KEEP | — | optional **normal** dep (`loom-tests`), not dev-scoped; its `generator` C enters only that feature build — document as a verification-lane carve-out like `fuzz` |
| `serde` + `serde_json` | KEEP | — | keystone (~4,600 derives, ~1,450 `json!`); revisit only after everything else (§6.3) |
| `sha1`, `sha2`, `hmac`, `subtle`, `zeroize`, `getrandom` | KEEP | — | audited, pure-Rust, tiny, security-load-bearing |
| `aes-gcm`, `chacha20poly1305` | KEEP | — | AEAD is not a place for first-party heroics; 0.11 generation landed in Phase 0 |
| `ed25519-dalek` (via nkeys today) | KEEP | 5 | becomes a *direct* dep when nkeys goes |
| `rustls` + `rustls-pki-types` + `rustls-pemfile` + roots | KEEP | — | TLS 1.3 + QUIC keys; §6.2 for the ring problem |
| `libc`, `nix`, `windows-sys` | KEEP | — | FFI bedrock (nix uniquely covers cmsg/GSO/mmsg) |
| `io-uring` | KEEP | — | thin raw binding, feature-gated |
| `wasm-bindgen`/`js-sys`/`web-sys`/`wasm-bindgen-futures` | KEEP | — | the browser ABI boundary |
| `tokio`, `async-trait` (benchmark-adapters) | KEEP | — | the competitor lane *is* the point |
| `tower` | KEEP | — | interop adapter, feature-gated, tiny surface |
| `arbitrary`, `opentelemetry-proto` | KEEP | — | fuzz-only, quarantined by design |
| `syn`/`quote`/`proc-macro2` (via `asupersync-macros`, serde_derive, etc.) | KEEP | — | **permanent residents**: our own macros need them and serde_derive carries syn 3 regardless. Owning pin-project/thiserror/visibility derives *increases* our use of this chain deliberately — trading many proc-macro crates for one we control |

### Workspace-member and satellite surfaces (explicit scope statement)

The verdicts above cover the root crate. The satellites are scoped as follows: `asupersync-tokio-compat` (hyper/http-body/tower/tokio) is **KEEP-by-design** — its entire purpose is the Tokio boundary; `conformance` (h2, hyper, uuid, tokio, prometheus-client…) and the excluded `fuzz/` crate are **DEV-KEEP verification lanes**; `asupersync-browser-core`'s `serde-wasm-bindgen` is part of the browser ABI boundary (KEEP); `frankenlab`'s `clap`/`serde_yaml` follow the Phase-3 replacements; `drop_unwrap_finder` (syn/walkdir) is an internal tool (DEV-KEEP). The npm `packages/` tree is a separate supply-chain surface handled in Phase 6.

### Dev-dependencies — all DEV-KEEP

`proptest`, `criterion`, `insta`, `trybuild`, `fastrand`, `rayon`, plus the differential references: `httparse` (HTTP/1), `raptorq` (RFC 6330), `sqlx` (MySQL), `redis` (RESP3), `tokio`/`tokio-util` (semaphore/codec conformance). **Policy:** every crate we replace gets retained (or added) as a dev-dependency reference for differential testing until two release cycles after the replacement ships. Dev deps never reach consumers — but they do run on our build/release machines, so they stay inside the Phase-6 audit perimeter.

---

## 4. Performance doctrine for replacements

Every `OWN` module follows the doctrine already proven by `raptorq/gf256.rs`:

1. **Safe portable baseline first** — scalar or `std::simd` (we are pinned nightly; portable SIMD costs zero unsafe). This is the always-on fallback and the differential oracle.
2. **Ledgered intrinsics second, only where measured** — `#[allow(unsafe_code)]` at fn scope, row in `artifacts/unsafe_boundary_ledger_v1.json`, evidence in `docs/unsafe_boundary_ledger.md`.
3. **Know what "portable SIMD" buys per ISA:** on aarch64, NEON is in the baseline target, so safe `std::simd` code vectorizes fully. On x86-64 the default baseline is **SSE2** — reaching AVX2/AVX-512 requires runtime dispatch through `#[target_feature]` functions, which is precisely the small, ledgerable unsafe that crates like memchr contain. Plan accordingly: safe-SIMD replacements are at full strength on Apple Silicon and at SSE2 strength on stock x86 until a ledgered dispatch layer is added.
4. **Apple Silicon specifics:** 128-byte cache-line padding (Phase 4.8 makes `CachePadded` arch-conditional — it is 64-byte today); prefer branchless scalar for short inputs (M-series IPC makes table lookups lose below ~64 B); `TBL`-based nibble tricks for hex/base64; `std::hint::spin_loop` lowers to ISB/WFE-friendly spins.
5. **High-core-count x86 specifics:** AVX2 via dispatch (see 3), AVX-512 only behind runtime detection (Zen 4/5 double-pumped 512 is a win; pre-Ice-Lake Intel downclocking is not); shard hot atomics per-core and pad to 128 B (adjacent-line prefetcher) to avoid cross-CCX cacheline ping-pong; prefer per-worker sharded counters + snapshot merge (the `ContendedMutex` metrics pattern) over shared atomics.
6. **Determinism trumps micro-wins:** no ambient entropy, no wall-clock in kernels, identical results across ISAs (bit-exact outputs are part of every kernel's contract — same rule the GF(256) kernels obey).
7. **Measure before building** (MATRIX-222 lesson): each Phase-4 primitive begins with a criterion A/B of the incumbent vs `std`/naive under the real workload. If std wins or ties, we take the zero-unsafe path and move on.

**Verification stack per replacement:** differential property tests vs the replaced crate (kept as dev-dep) · golden vectors (`insta`) · fuzz target in `fuzz/` · Miri on unsafe modules · loom for lock-free structures · criterion baseline gate (5% ratchet, Phase 6 methodology) · UBS scan before commit.

---

## 5. Phase plan

Effort keys: S < 1 day · M = 1–3 days · L = 1–2 weeks · XL = multi-week campaign. Deltas are unique-name reductions against the graph named in each item (default graph unless stated).

### Phase 0 — Hygiene (LANDED 2026-07-23, commit `a86bfb3a6`)
`cargo update` lockfile refresh; removed dead `crossbeam-deque` + `hkdf`; `base64`→0.23 with `default-features = false` (0.23 default-enables an *unsafe-SIMD* engine we do not want); `lz4_flex`→0.14; **`aes-gcm`/`chacha20poly1305` 0.10→0.11 migration completed** (`AeadInOut`/hybrid-array, wire format unchanged); fixed the stale crc32fast comment. **Measured Δ default graph: net −2 crate-versions / −3 names** (dead-dep removal −3 versions [crossbeam-deque, crossbeam-epoch, hkdf]; AEAD generation swap +1 net [`opaque-debug` out; `cpubits`, `rand_core 0.10` in]). The hoped-for digest-chain dedup did **not** occur and cannot until Phase 5.3 + an upstream dalek release (§2.3). Full validation record: UPGRADE_LOG.md pass 4.

### Phase 1 — Trivial tier (S each, ~1 agent-week total, Δ ≈ −14 to −18 names)
1. `hashbrown` → std/`DetHashMap` (2 sites).
2. `num_cpus`, `whoami` → std + `util/host.rs` stub (benchmark graph).
3. `env_logger` → tracing shim; drop from `cli` (cli graph).
4. `time` → own RFC3339-ns formatter (one call site); CLI standardizes on one time type (cli graph).
5. `semver` → `util/version.rs` (`Version` parse + full SemVer precedence incl. pre-release ordering + serde impls; ~150–200 lines).
6. `hex` → `util/hex.rs`.
7. `base64` → `util/base64.rs` (STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD; RFC 4648 vectors + differential vs old crate).
8. `bincode-next` → `codec/binary.rs` two-function deterministic codec for `distributed/snapshot.rs` + `types/typed_symbol.rs`, with a snapshot-format version bump. (Format-compat note: frankensqlite consumes asupersync 0.3.9 from the registry, but not these serialized formats — verified before claiming the bump is externally invisible.)
9. `futures-lite` → `util/future.rs` (`block_on` with parker, `poll_fn`, `zip`, `race`, `yield_now`, `poll_once`).
10. `slab` → generalize `TokenSlab` into `util/slab.rs`; port ~7 sites.
11. `visibility` → `asupersync_macros::make_pub` attribute (12 uses).
12. `tempfile` → optional dep on `benchmark-adapters` + `test-internals` (its only non-`cfg(test)` users — `atp/benchmark/suite.rs`, `test_logging.rs`); file the wire-or-remove decision bead for the three orphaned `real_*_e2e_tests.rs` files (owner sign-off required for any deletion).
13. Delete the `mod regex` mock in `artifact.rs` (replace with a plain digit-run parser now; real scanner in Phase 3.7).

### Phase 2 — Own the platform layer (M–L each, Δ ≈ −8 to −10 names; `rustix`/`linux-raw-sys` leave once items 1+5 land on top of Phase 1.12)
1. **`polling` → `runtime/reactor/sys/{epoll,kqueue,iocp}.rs`** (L). The `Reactor` trait already isolates it to 3 files. Direct `epoll_ctl`/`epoll_wait` and `kevent` via libc/nix, oneshot+edge modes preserved, generation-tagged tokens unchanged. IOCP via windows-sys. The dead reference file `runtime/reactor/macos.rs` (raw kqueue) is prior art in-tree. Unsafe: syscall wrappers only, fn-scoped, ledgered.
2. **`socket2` → `net/sys.rs`** (M). The option-setters used today via `setsockopt` wrappers; kill the current triple-idiom overlap (socket2 vs `nix::fcntl` vs raw libc) — one blessed layer.
3. **`signal-hook` → `signal/sys.rs`** (M). `sigaction` + self-pipe (we already own a signal thread + Win32 event path); consts move into `signal/kind.rs`. Payoff: one fewer crate, one signal idiom (not a C-removal — see §2.2 correction).
4. **`sysinfo` → `util/host.rs`** (L). Linux `/proc/{pid}/stat|status|statm`, `/proc/meminfo`, `statvfs` (already via nix); macOS `sysctl`/`proc_pidinfo`; Windows paths already hand-written in `resource_monitor.rs`. One blessed `kill` wrapper replaces today's three signal-delivery idioms.
5. **`xattr` →** raw-libc shim (M, ledgered unsafe; deref/no-deref variants + macOS signature differences) — justified only as the final rustix parent; otherwise defer.

### Phase 3 — Own the codecs and the CLI (L each, Δ ≈ −20 default, −40 for `cli` users)
1. **`prost` → `codec/proto.rs`** (L, highest leverage — prost is non-optional today). Varint/zigzag/length-delimited wire codec written fresh (the varint helpers in `grpc/protobuf.rs` are `#[cfg(test)]` conformance code — they become the differential oracle, not the implementation). Hand-written message structs for the gRPC surfaces we ship and the OTLP export subset. Frees `bytes`, `anyhow`, `itertools`, `prost-derive`. Fuse encode-with-length-prefix into the h2 DATA frame writer — a real perf win prost can't give us.
2. **`rmp-serde` → `trace/msgpack.rs`** (M). Trace-format version bump; `trace/compat.rs` already exists.
3. **`serde_yaml` → JSON scenarios** (M). Deprecated upstream; one-shot converter for the scenario corpus + goldens.
4. **`toml` → `config/toml.rs`** (M). Reader for the documented config subset + writer for the 3 write sites; spec-subset documented; differential-fuzzed vs `toml` (dev-dep).
5. **`clap` → `cli/parse.rs`** (L). Table-driven parser (long/short, subcommands, `--help`, value enums, defaults). Command tree already centralized; re-plumbing, not redesign.
6. **`chrono` → `util/time_fmt.rs`** (M). `UtcTimestamp` (i128 ns) + RFC3339 format/parse + serde impls.
7. **`regex` → `observability/redact.rs`** (M). Hand-rolled scanners for the 4 fixed PII patterns. User-supplied redaction patterns get a documented literal/wildcard/char-class subset engine (O(n·m), no backtracking) that **fails closed: any unsupported pattern syntax rejects the configuration at load — a PII-redaction pattern must never silently degrade**. (Honesty note: the `regex` crate is already linear-time/non-backtracking, so "no ReDoS" is parity, not an upgrade; the real trade is losing full syntax, hence fail-closed.) Risk-register row added.
8. **`opentelemetry` + `opentelemetry_sdk` → native OTLP** (L). `otel.rs` is already a 9,427-line adapter; re-point at own instrument types + OTLP/HTTP via `codec/proto.rs`. The `metrics` feature then adds **zero** external crates.

### Phase 4 — Hot-path primitives, ledgered unsafe where measured (L–XL, Δ ≈ −8 names, the perf showcase)
1. **`parking_lot` → nightly `std::sync::nonpoison`** (L, *measure first*; `#![feature(nonpoison_mutex, nonpoison_rwlock)]` on our pinned nightly — verified present, Condvar included). Gate: criterion on `scheduler_benchmark`, `next_task_hotpath`, channel benches; if std regresses >2% p50 on any tracked row, build `sync/rawlock.rs` (futex/WaitOnAddress/os_unfair_lock, ~600 lines, ledgered) instead. Either way `parking_lot`+`parking_lot_core`+`lock_api` leave. Migration is mechanical import/alias swaps across ~173 files (the sharded-state hot core is already behind our own `ContendedMutex` wrapper; the long tail is direct `parking_lot::Mutex` imports).
2. **`crossbeam-queue` → `util/lockfree.rs`** (XL). Vyukov bounded MPMC (`ArrayQueue` replacement) + segmented unbounded MPMC (`SegQueue` replacement — the global injector + epoch GC). Loom models; Miri clean; 48-h stress soak on the 64C box before the old crate is deleted; feature-flagged rollout defaulting to crossbeam for one release.
3. **`smallvec` → `util/inline_vec.rs`** (L). `InlineVec<T, const N: usize>` — `MaybeUninit` inline arm + `Vec<T>` spill; Miri + proptest; ledger row.
4. **`memchr` → `util/simd_scan.rs`** (M). Safe `std::simd` memchr/memmem: full-strength NEON on aarch64, SSE2-strength on stock x86-64. Bench against memchr's runtime-dispatched AVX2 honestly; if the h1-parse corpus shows a real regression on x86, add a ledgered `#[target_feature(enable = "avx2")]` dispatch kernel (same pattern as gf256). memchr stays as dev-dep oracle.
5. **`crc32fast` → `util/crc32.rs`** (M). Safe slicing-by-16 (~2–4 GB/s/core realistic); optional ledgered ARMv8-CRC + x86 CLMUL kernels behind `simd-intrinsics`. Include CRC-32C alongside CRC-32 if/when the Kafka client needs it.
6. **`pin-project` → `asupersync_macros::pin_project`** (L). Projection derive covering our 30 sites **plus pin-project's negative guarantees, which are the actual soundness content**: conditional `Unpin` (any pinned `!Unpin` field ⇒ container `!Unpin`), rejection of user `Drop` impls (PinnedDrop-style), rejection of `#[repr(packed)]` — each enforced and covered by `trybuild` compile-fail tests (trybuild is already a dev-dep). Nets −2 crates; the value is auditability and macro ownership, not graph weight.
7. **`thiserror` → `asupersync_macros::Error`** (M). Attr-compatible (`#[error]`, `#[from]`, `#[source]`); ~112 files change only the derive path. Nets −2 crates.
8. **`CachePadded` arch-conditional alignment** (S). `util/cache.rs` is `#[repr(C, align(64))]` today; make it 128 on `x86_64` (adjacent-cacheline prefetcher) and `aarch64` (Apple 128-B L2 lines), 64 elsewhere — then benchmark the scheduler counters that sit in it.

### Phase 5 — Strategic big-ticket (XL each; the C-code eviction phase)
1. **FrankenSQLite** (§7.1) — `sqlite` feature deprecated in favor of fsqlite's asupersync-native API. Removes `rusqlite`, `libsqlite3-sys` (bundled C), `sqlparser`, `psm`/`stacker`.
2. **Kafka** (§7.3) — remove the `kafka` feature now (librdkafka + cmake gone immediately); build the native wire client when a real consumer exists. The native client trades 13 external crates for ~6–10k lines of first-party network-parser attack surface — a deliberate trade, stated openly.
3. **nkeys → `security/nkey.rs`** (§7.4) — base32 + CRC-16/XMODEM codec (~200 lines) on a direct `ed25519-dalek` dep. Cuts the 36-crate nkeys closure to the dalek core; the digest-generation dedup additionally waits on upstream dalek (§2.3).
4. **x509 SPKI/SAN extractor → `tls/der_min.rs`** (§7.5).
5. **Compression:** drop `brotli` — from HTTP negotiation *and* the ATP surface: retire `CompressionAlgorithm::Brotli` from the manifest enum with fail-closed validation (a manifest declaring Brotli is rejected with a clear error, never a silent decode failure); own LZ4 block codec (~1–1.5k lines); DEFLATE own-implementation as a stretch goal.
6. **`unicode-normalization` →** checked-in NFC tables (generated offline from UCD, generator script committed).
7. **rustls crypto provider** (§6.2): evaluate `rustls-graviola` / pure-Rust providers to retire `ring`'s C/asm. Out of scope: writing our own TLS.

### Phase 6 — Continuous enforcement (expanded in Rev 2)
- **Dependency budget contract:** `artifacts/dependency_budget_contract_v1.json` + `tests/dependency_budget_contract.rs` — asserts the exact allowed direct-dependency set and a ratchet-down ceiling on the consumer graph, **measured from a synthesized out-of-workspace consumer crate** (in-workspace counts are equal today but contingent on dev-dep feature unification staying inert). Fail-closed like the no-tokio lanes.
- `cargo deny`/`cargo audit` lanes (advisories, licenses, duplicate-version ratchet) covering the **full workspace graph including dev/build deps** — the build machines are inside the threat model even when consumers aren't affected.
- **CI supply chain:** pin GitHub Actions by commit SHA across the workflow files; inventory and pin the npm `packages/` toolchain (pnpm lockfile audit); include the excluded `fuzz/` crate's graph in the audit sweep.
- **Consumer guidance:** a library's `Cargo.lock` does not protect downstream users — publish minimal-version-tested requirement bounds and document `cargo vendor` as the recommended posture for consumers who want the same supply-chain stance.
- The AGENTS.md "Key Dependencies" table becomes generated-from-contract, never hand-maintained.

**Projected end-state default consumer graph: ~40–50 names** — serde family + RustCrypto keeps + dalek + libc/nix/windows-sys/wasm boundary + io-uring — versus 121 today. `+tls` adds only the rustls core. `+cli` and `+metrics` add **zero** external crates. Honesty note on the "zero" cells: `+sqlite`-via-FrankenSQLite moves the dependency to a first-party ledger (fsqlite has its own graph) and `+kafka`-native converts external crates into first-party protocol code — these are *ownership* wins consistent with the whole plan's thesis, not claims that the code ceases to exist.

---

## 6. What we deliberately keep (and why that's the right call)

### 6.1 Cryptography is not a place for NIH
`sha1/sha2/hmac/subtle/zeroize/getrandom/aes-gcm/chacha20poly1305/ed25519-dalek` are pure-Rust, RustCrypto-audited, tiny, and security-load-bearing (CAS integrity, Macaroons, SCRAM, ATP AEAD, identity signatures). A home-grown constant-time compare that the compiler quietly un-constant-times, or a GHASH with a timing side channel, is a catastrophic trade for removing ~25 small crates. **Non-negotiable keep.** (We *do* remove crypto-adjacent packaging: nkeys' text codec, x509 parsing for pins — the wrappers, not the primitives.)

### 6.2 rustls and the ring problem
rustls itself is exactly the kind of dependency worth having: QUIC packet protection, the TLS 1.3 state machine, and X.509 chain validation we build on. The blemish is the `ring` provider (C + assembly). Path: (a) short-term, keep ring; (b) medium-term, trial `rustls-graviola` (Rust provider by the rustls author, built on formally verified s2n-bignum assembly — not pure Rust, but verified) or the RustCrypto provider on the encrypted ATP matrix — adopt if the 500M/5G encrypted cells hold; (c) a FrankenTLS is explicitly **out of scope** until the rest of this plan is done and the threat model demands it.

### 6.3 serde / serde_json
~4,600 derives and ~1,450 `json!` sites make serde the type-model substrate of the codebase, and every FrankenSuite sibling speaks it. Replacing it is a program, not a project, and the payoff is small: serde's closure is ~7 tightly-audited crates. **Keep; revisit only after Phases 1–5 land**, at which point a `franken-serde` could be scoped across the whole suite at once — that decision belongs at suite level, not to asupersync alone.

### 6.4 FFI bedrock
`libc`, `windows-sys`, `wasm-bindgen`/`web-sys`/`js-sys`, `io-uring`: these *are* the platform boundary; "replacing" them means transcribing syscall numbers and ABI structs by hand for zero safety gain. `nix` stays for the cmsg/SCM_RIGHTS/sendmmsg/GSO marshaling that would otherwise be hand-rolled unsafe — and that same argument is why the xattr and polling replacements must justify their new ledgered unsafe with concrete graph wins, not ideology.

---

## 7. Flagship replacement designs

### 7.1 FrankenSQLite integration (replaces `rusqlite` + `sqlparser`)
**Constraint (hard, verified):** `fsqlite-core` carries an **unconditional** normal dependency on asupersync for all native targets (as do fsqlite-types/pager/mvcc/vdbe/wal and the e2e/harness crates; `fsqlite`'s `async-api` feature adds more on top). Therefore `asupersync → fsqlite-core` is a package-level dependency cycle rejected by cargo at resolve time — **inverting the integration is the only option, not merely the preferred one.**
**Design:** asupersync's `sqlite` feature is deprecated and removed; FrankenSQLite grows an `fsqlite-asupersync` glue surface (it already depends on asupersync) exposing the cancel-correct, `Cx`-threaded connection API that `src/database/sqlite.rs` provides today — blocking-pool bridge, budget-derived progress interrupts, prepared-statement cache, typed rows, transactions. The 7,258-line module's semantics port into fsqlite; asupersync keeps a doc pointer.
**Wins:** bundled SQLite C gone; `sqlparser` gone (the statement-class allowlist becomes a query against fsqlite's own AST — eliminating the parser/executor-divergence risk `sqlparser` was added to fix); MVCC concurrent writers + RaptorQ durability for free.
**Tests:** fsqlite's conformance harness + port of the existing sqlite e2e suite; differential vs rusqlite (already fsqlite's methodology).

### 7.2 The scheduler-adjacent primitives (parking_lot / crossbeam-queue / smallvec)
Measured-first discipline (§4.7). Bench harnesses already exist (`scheduler_benchmark`, `next_task_hotpath`, `spawn_throughput`, `semaphore_benchmark`). Expectation: std's futex locks tie parking_lot on the uncontended paths that dominate here (both are one CAS), so the zero-unsafe nonpoison path likely wins Phase 4.1. The Vyukov/segmented MPMC (4.2) is where real unsafe concentrates; it gets loom + Miri + the 48-h soak + feature-flagged rollout, and its ledger row cites the exact algorithms and invariants. All three keep the incumbent as dev-dep oracle for differential stress tests.

### 7.3 Kafka: native or nothing
librdkafka via cmake is the single worst build-graph citizen (C, cmake, pkg-config, network-facing C parser surface). The audit found **zero native wire-protocol code** — `messaging/kafka.rs` is a pure wrapper that fails closed without the feature. Plan: **(a)** remove the `kafka` feature now (it's optional and Early-status; C and cmake leave the graph immediately); **(b)** when a real consumer exists, build `messaging/kafka_wire.rs` natively — produce/fetch/metadata/offset-commit, RecordBatch v2 with our own **CRC-32C** (Castagnoli — a different polynomial than the CRC-32 in `atp/journal`; `util/crc32.rs` grows both variants), SASL SCRAM on existing sha2/hmac, TLS via existing rustls. Stated trade: −13 external crates, +~6–10k lines of first-party parser attack surface, fuzzed like every other codec.

### 7.4 nkeys → `security/nkey.rs`
The NKey format is: prefix byte(s) + Ed25519 key + CRC-16/XMODEM, base32 (RFC 4648, no padding) — ~200 lines including exhaustive vectors from the NATS spec repo. Depend on `ed25519-dalek` directly (KEEP tier). Removes `nkeys`, `signatory`, `data-encoding` and most of the **36-crate** closure from the default graph; the old-generation digest dedup additionally requires upstream dalek (§2.3). Wire-compat proven by differential vectors vs nkeys (dev-dep): seed↔public round-trips, all three key-pair types we use, sign/verify against NATS-generated fixtures.

### 7.5 x509-parser → `tls/der_min.rs`
Scope is deliberately microscopic and matches current behavior exactly: (1) walk Certificate → TBSCertificate → SubjectPublicKeyInfo, return raw SPKI DER for SHA-256 pinning; (2) walk extensions → SubjectAlternativeName → DNSName/IPAddress values for the native-QUIC verifier, whose semantics stay **exact, case-insensitive, no wildcards** (today's `san_matches_server_name` behavior). A strict DER TLV reader (definite lengths only, no BER, depth-capped, length-checked) is ~400 lines. Ships only with: differential fuzzing vs x509-parser (dev-dep) over a corpus of real certificates plus mutations — the corpus is **to-be-built**: an `openssl`-CLI-generated fixture set checked into `tests/fixtures/`, extended with BetterTLS/limbo-style malformed variants; fail-closed on any parse ambiguity (a pin/SAN we can't extract = verification failure, never a skip). Explicit residual boundaries: duplicate SAN extensions are a hard parse error (no "first wins"); absent SAN keeps today's no-CN-fallback behavior; `der_min.rs` must never grow toward chain validation — name constraints, wildcards, and path building remain rustls/webpki's job. Removes the nom/asn1-rs/der-parser/oid-registry chain (~9 crates) from the `tls` graph.

### 7.6 `codec/proto.rs` (replaces prost)
Varint/zigzag/tag/skip + canonical struct codegen *by hand* for the finite message set we ship (gRPC health/reflection/status-details, OTLP trace/metrics/logs export subset). No derive, no build-time codegen. The existing `#[cfg(test)]` varint helpers in `grpc/protobuf.rs` become differential oracles. Round-trip vs prost under proptest; OTLP goldens vs `opentelemetry-proto` fixtures (both stay dev/fuzz-only).

---

## 8. Risk register

| Risk | Mitigation |
|---|---|
| Home-grown crypto-adjacent code (nkey codec, DER walker) has a subtle bug | differential fuzzing vs incumbent, fail-closed posture, incumbents kept as dev-dep oracles, security-review bead before each ships |
| Lock-free MPMC replacement has a liveness/ABA bug that only shows at scale | loom + Miri + 48-h 64C soak + feature-flagged rollout defaulting to crossbeam for one release |
| PII-redaction pattern subset silently weakens operator configs | **fail-closed pattern compiler**: unsupported syntax rejects the config at load; migration guide for existing patterns (Phase 3.7) |
| pin-project replacement macro misses a negative guarantee (Drop/packed/Unpin) → latent UB | the three guarantees are explicit acceptance criteria with trybuild compile-fail coverage before any call site migrates |
| Trace/snapshot format churn (rmp/bincode replacements) breaks replay tooling | format-version bumps + `trace/compat.rs` readers; external exposure checked against registry consumers (frankensqlite pins 0.3.9) before calling a bump invisible |
| Perf regressions from de-SIMD-ing (memchr, crc32, base64) on x86 | honest A/B vs runtime-dispatched incumbents (§4.3); ledgered `#[target_feature]` kernels where the bench demands; 5% criterion ratchet is mandatory |
| Phase 4 primitives add unsafe to a `deny(unsafe_code)` codebase | fn-scoped `#[allow]` + unsafe-boundary ledger rows + proof notes (existing Phase-6 gate) |
| serde_yaml removal breaks frankenlab scenario corpus | one-shot converter + goldens for every existing scenario file |
| FrankenSQLite maturity vs bundled SQLite | staged: fsqlite integration lands behind its own feature while `sqlite` is deprecated-but-present for one release; existing sqlite e2e suite runs against both during overlap |
| Brotli retirement breaks peers that declare it in ATP manifests | fail-closed manifest validation with explicit error (Phase 5.5); pre-1.0 wire-compat stance documented |
| Agent-swarm merge conflicts during 173-file mechanical migrations (parking_lot, thiserror) | file reservations per directory batch + the established parallel-subagent mechanical-change protocol (no scripts, per AGENTS.md) |

---

## 9. Sequencing note for the swarm

Phases 1–3 are embarrassingly parallel (independent crates, disjoint files) — ideal bead-per-crate work for the agent fleet. Phase 4 items are serialized behind their measurement gates and land one at a time with soak windows. Phase 5 items are campaigns with their own epics. Beads: epic **`asupersync-ir2uf0`** with phase children `asupersync-d24mms` (P1), `asupersync-3u3tej` (P2), `asupersync-5z2scg` (P3), `asupersync-0h6myr` (P4), `asupersync-ym2wtv` (P5), `asupersync-mnotoo` (P6). Campaign-scale items inside P4/P5 get their own child beads when picked up. Pre-existing HEAD test redness discovered during Phase-0 validation is tracked separately as `asupersync-bm3tty`.

---

## Appendix A — Default-graph snapshots

Pre-Phase-0: 132 crate-versions / 124 names. Post-Phase-0 (`a86bfb3a6`): **130 crate-versions / 121 names**. Notable clusters: serde family (7), RustCrypto new-gen (~25), nkeys/dalek old-gen chain (~17 — the duplicate-version driver), prost chain (5 incl. bytes/anyhow/itertools), sysinfo, polling/tempfile/xattr → rustix/linux-raw-sys/fastrand, proc-macro chain (syn×2/quote/proc-macro2/unicode-ident), bincode chain (5 incl. pastey).

## Appendix B — Feature-cost table (unique names, post-Phase-0 baseline 121)

| Feature | Adds today | Adds at end-state |
|---|---|---|
| (default) | 121 | ~40–50 |
| `tls` | +26 (rustls, ring, x509-parser chain, webpki) | +~12 (rustls core + provider) |
| `sqlite` | +10 incl. bundled C | 0 external (moves to FrankenSQLite's first-party graph) |
| `kafka` | +13 incl. librdkafka/cmake | 0 external (feature removed, later native first-party) |
| `metrics` | +13 | 0 |
| `cli` | +43 | 0 |
| `compression` | +8 | → 0 (stretch; flate2 interim) |

## Appendix C — Reproduction commands

```bash
# consumer graph, BOTH units (run per feature set):
cargo tree -p asupersync --locked -e normal --prefix none [--features F] \
  | awk '{print $1}'      | sort -u | grep -vcE '^(asupersync$|franken-|asupersync-macros)'   # unique names
cargo tree -p asupersync --locked -e normal --prefix none [--features F] \
  | awk '{print $1" "$2}' | sort -u | grep -vcE '^(asupersync |franken-|asupersync-macros)'   # crate-versions

# Phase-6 canonical form: measure from a synthesized consumer, not in-workspace:
#   new empty crate with `asupersync = { path = ..., default-features = ... }`,
#   then the same cargo tree pipeline. (Verified identical today; contract pins it.)

# native-code detection: cargo metadata --all-features → custom-build targets, .links,
# cc/cmake/bindgen build-deps — then VERIFY against Cargo.lock (declared build-deps
# can be feature-gated off; see the signal-hook correction in §2.2).

# no-tokio production proofs — unchanged, see AGENTS.md "Async Runtime: THIS IS IT"
```
