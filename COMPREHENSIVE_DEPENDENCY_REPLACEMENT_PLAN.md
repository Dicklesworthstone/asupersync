# Comprehensive Dependency Replacement Plan — Asupersync

> **Goal:** systematically shrink asupersync's external dependency surface, optimizing for **eliminated trust relationships and eliminated native/unsafe surface — not the raw count of crate names** — replacing dependencies with home-grown strict-memory-safe Rust (per the safety taxonomy in §3), or with FrankenSuite projects we control, with performance tuned for Apple Silicon and high-core-count x86.
>
> Audit date: 2026-07-23 (SapphireHill). **Rev 3 (2026-07-24):** execution-ready revision incorporating Sol Max's external review of Rev 2. Major changes: an explicit safety taxonomy that prohibits algorithmic unsafe in replacements by default (§3); prioritization by *marginal* dependency cost via a generated ledger (§4); a public-API-decision phase inserted before all codec work (§7 Phase 3); the parking_lot replacement redesigned for stable-lane compatibility; the X.509 work re-scoped as a security epic that delegates to rustls/webpki first; Kafka native rewrite descoped to an independent future campaign; and a set of verdicts flipped to KEEP where marginal ROI was poor (semver, thiserror, pin-project, crossbeam-queue, smallvec, memchr, socket2, polling, unicode-normalization). Rev-2 factual errors fixed: rdkafka builds bundled C via configure/make (cmake declared but inactive); `parking_lot::Condvar` *is* used in production; the x509 surface includes validity/EKU/KU/BasicConstraints checks, not just SPKI+SAN.
>
> Phase beads: paused pending this revision per review; re-scoped bead mapping in §7.

---

## 1. Philosophy

External library dependencies are an anti-pattern for this project, for four reasons:

1. **Supply chain.** Every one of the ~376 crates in our full workspace graph is a person or CI pipeline that can be compromised. The default *consumer* graph alone is 121 external crates (130 counting duplicate versions).
2. **Memory safety.** We `deny(unsafe_code)` and ledger every exception — then link in `ring` (C + assembly), bundled SQLite (250k lines of C), and bundled `librdkafka` (C). The safety story is only as strong as the weakest native blob.
3. **The generality tax.** One-size-fits-all crates carry code, features, and compile time we never use. Purpose-built code is smaller, faster, and fully understood.
4. **Performance ownership.** Our continuous optimization campaigns stop at crate boundaries. Code we own keeps getting faster; code we import doesn't.

**The Rev-3 discipline:** a dependency is removed when doing so eliminates *trust* (an upstream maintainer/repo/build script), *native or unsafe surface*, or *real marginal graph weight* — measured by the §4 ledger — at acceptable implementation and soundness cost. Moving unsafe from a mature, widely-fuzzed dependency into fresh first-party code does **not** inherently reduce risk; that trade needs measured evidence and owner sign-off. Dev-dependencies used as differential-testing references are an asset for proving replacements correct, but they run on our build/release machines, so Phase 9 keeps them inside the audit perimeter.

---

## 2. Audit Snapshot (2026-07-23, Rev-3-corrected)

### 2.1 Graph size

Unit note: "names" = unique external crate names; "crate-versions" counts duplicate major versions separately. Per-feature rows are **name** counts.

| Graph | Pre-Phase-0 baseline | Post-Phase-0 (landed `a86bfb3a6`) |
|---|---|---|
| Default consumer graph | 124 names / 132 crate-versions | **121 names / 130 crate-versions** |
| `+tls` | 150 | 147 |
| `+sqlite` | 134 | 131 |
| `+kafka` | 137 | 134 |
| `+metrics` | 137 | 134 |
| `+cli` | 167 | 164 |
| Workspace, all features, incl. dev/build deps | ~376 external / 390 packages | ~374 |

Verified: a synthesized out-of-workspace consumer resolves the same 130 crate-versions as in-workspace measurement — today. The Phase-9 budget contract measures from a synthesized consumer (methodology in Appendix C, now package-ID-based and per-platform).

### 2.2 Native code (C/C++/asm) in the graph

| Crate | Native payload | Pulled by | When |
|---|---|---|---|
| `ring` | C + hand-written assembly | `rustls/ring` provider | `tls` |
| `libsqlite3-sys` | bundled SQLite C amalgamation | `rusqlite` | `sqlite` |
| `rdkafka-sys` | **bundled `librdkafka` C via `./configure` + `make`** (the `cmake-build` feature exists but is not enabled — lockfile-verified, no `cmake` crate resolves) | `rdkafka` | `kafka` |
| `psm`/`stacker` | C/asm stack-probing | `sqlparser` (via `recursive`) | `sqlite` |
| `generator` | C context-switching | `loom` | `loom-tests` (feature-gated **normal** dep) |
| `alloca` | C | `criterion` (Windows) | dev-only |

`signal-hook` compiles no C in our feature set (its `cc` edge is behind `extended-siginfo-raw`). Standing rule: native-code attribution must be **lockfile-verified**, because `cargo metadata` reports declared build-deps regardless of feature activation (this trap produced two Rev-1/2 errors: signal-hook "cc shim" and rdkafka "via cmake").

### 2.3 Version-duplication bloat in the default graph

Two RustCrypto generations remain linked after Phase 0: `sha2`/`digest`/`block-buffer`/`crypto-common`/`const-oid`/`cpufeatures`/`getrandom` ×2 each, plus `rand_core` 0.6+0.10 (new with aead 0.6). Sole driver: `nkeys → ed25519-dalek 2.2` pins the old generation. **Because ed25519-dalek stays (as a direct dep) after the nkeys replacement, this dedup ultimately waits on an upstream dalek release on digest-0.11 — outside our control.** `syn` 2+3 are both present (serde_derive moved; our macros and most of the ecosystem have not).

### 2.4 Dead and misplaced dependencies found

| Finding | Status |
|---|---|
| `crossbeam-deque` — zero references (work-stealing is home-grown) | **removed in Phase 0** (+ transitive crossbeam-epoch) |
| `hkdf` — zero references (HKDF hand-rolled on `hmac`) | **removed in Phase 0** |
| `tempfile` normal-dep forced by two feature-gated non-test modules (`atp/benchmark/suite.rs` under `benchmark-adapters`; `test_logging.rs` under `test-internals`) | optionalize (Phase 2) |
| Three orphaned never-compiled files (`src/real_{fs_dir_fs_vfs_integration,integration_scenarios,distributed}_e2e_tests.rs`) — not declared as modules anywhere | wire-or-remove decision needs owner sign-off (no-deletion rule) |
| `env_logger` enabled by all of `cli`, consumed by 2 lines in `offline_tuner` | remove (Phase 2) |
| `time` + `chrono` both in CLI; `time` has one call site | consolidate (Phase 2) |
| `num_cpus` + `whoami`: one call site each; std covers it | remove (Phase 2) |
| `src/net/atp/chunk/artifact.rs` local `mod regex` **mock** in production | replace (Phase 2, no-mock policy) |
| Stale crc32fast manifest comment | **fixed in Phase 0** |

### 2.5 Usage-map corrections carried into Rev 3

The Rev-1/2 usage tables remain substantially correct (spot-verified to the line) with these corrections:

- **`parking_lot`:** the "no Condvar" claim was **wrong** — `parking_lot::Condvar` is production-load-bearing in `runtime/blocking_pool.rs` and `service/discover.rs`, and parking-lot guard types leak into crate-visible/public method signatures. Any replacement must cover `Mutex`/`RwLock`/`Condvar` and the exposed guard types.
- **`x509-parser`:** the "SPKI + SAN only" scope was **wrong**. Active checks also include certificate validity windows and server EKU (`bin/atp.rs`), validity+EKU+KeyUsage+SAN in the native-QUIC verifier (`net/quic_native/handshake_driver.rs`), per-chain-certificate validity (`tls/acceptor.rs`), and BasicConstraints CA:TRUE (`tls/connector.rs`), plus SPKI extraction (`tls/types.rs`). See §9.4.
- **`memchr`:** replacing it removes **zero** packages — `serde_json` (KEEP) depends on memchr independently.
- **`smallvec`:** remains in the graph through `parking_lot_core` until/unless the parking_lot work lands.
- **CLI scale:** the six clap-consuming files total ~33.8k lines with hundreds of derive/attribute sites — an owned parser is XL, not L.
- **`typed_symbol.rs` / `grpc/protobuf.rs` / `otel.rs` are public generic surfaces** (arbitrary-`Serialize` `SerdeCodec` with public Bincode/MessagePack format variants; public `ProstCodec` over arbitrary `prost::Message`; public consumption of OpenTelemetry's `Meter`). Replacing the backing crates is therefore a **public API redesign**, not an internal swap — hence the new Phase 3.
- Home-grown infrastructure inventory unchanged (`TokenSlab`, `DetHashMap`, `Arena`, `CachePadded` [64-byte today], intrusive queues, hand-rolled HKDF, `tracing_compat` shim, GF(256) SIMD kernels). The `grpc/protobuf.rs` varint helpers are `#[cfg(test)]`-only — differential oracle, not reusable production code.

---

## 3. Safety taxonomy (new in Rev 3 — the policy that resolves "strict memory-safe")

Every replacement is classified before it is approved:

| Class | Definition | Policy |
|---|---|---|
| **SAFE-OWN** | `#![forbid(unsafe_code)]`-clean first-party code | Default. Always eligible. |
| **BOUNDARY-UNSAFE** | Narrow, ledgered unsafe at OS/FFI or CPU-dispatch boundaries: syscall wrappers, `#[target_feature]` dispatch shims, env-var setters — the categories the unsafe-boundary ledger already governs | Eligible with fn-scoped `#[allow]`, ledger row, proof note, and Miri/UBS coverage. This is the same standard the epoll reactor and GF(256) kernels already meet. |
| **ALGORITHMIC-UNSAFE** | Unsafe that *encodes an ownership/liveness/initialization argument*: lock-free queues with pointer tagging, `MaybeUninit` inline storage, futex parking protocols, generated pin-projection | **Prohibited for replacements by default.** Loom does not prove liveness/linearizability, Miri does not model weak memory, and a 48-h soak is not a proof. Moving this class of unsafe from a mature, widely-fuzzed crate into fresh first-party code increases risk. Exceptions require: a measured performance defect in the incumbent, a SAFE alternative benchmarked and rejected, and explicit owner sign-off. |

**Immediate verdict consequences:** `crossbeam-queue`, `smallvec`, and `pin-project` flip to **KEEP** (their entire value *is* well-audited algorithmic unsafe). The parking_lot replacement is redesigned as a SAFE-OWN wrapper over `std::sync` (§9.2). SIMD replacements are honest about which strength class they land in per ISA (§6).

---

## 4. Marginal-cost ledger (new in Rev 3 — the prioritization metric)

Raw closure size overstates wins because shared subtrees don't leave when one parent does. Prioritization now uses **marginal cost**: the packages that actually exit the graph when a root is removed, plus qualitative risk columns.

**Ledger spec** — `artifacts/dependency_marginal_ledger_v1.json`, generated by a script from `cargo metadata` (package IDs, not name text), recomputed after every phase, one row per direct dependency:

`{ crate, marginal_package_versions (per platform: linux/macos/windows/wasm), unique_upstream_repos, build_scripts, proc_macros, native_code, unsafe_exposure_class, runtime_hotness, api_blast_radius, est_impl_cost, security_risk, verdict, phase }`

**Key marginals measured today (default graph, Linux):**

| Root | Closure (Rev-2 framing) | **Marginal (what actually leaves)** |
|---|---|---|
| `nkeys` | 36 packages | **~16** (ed25519-dalek chain stays as a direct dep) |
| `prost` | 13 | **6** (prost, prost-derive, bytes, anyhow, itertools, either) |
| `bincode-next` | 14 | ~5 (bincode, derive, pastey, virtue, unty) |
| `futures-lite` | 6 | ~3–4 |
| `hashbrown` | 4 | ~4 (foldhash/rapidhash/allocator-api2) |
| `semver`, `socket2`, `polling`, `base64`, `hex`, `crc32fast` | — | **~1 each** |
| `memchr` | — | **0** (serde_json keeps it) |
| `smallvec` | — | 0 until parking_lot also lands |
| `rusqlite`+`sqlparser` | — | ~10 + **bundled C + psm/stacker** |
| `rdkafka` | — | ~13 + **bundled C** |
| `x509-parser` | — | ~9 (tls graph) |
| `opentelemetry`+`_sdk` | — | ~13 (metrics graph) |
| `clap` (+time/chrono/env_logger/serde_yaml) | — | ~40+ (cli graph) |

The big wins are therefore: the **C evictions** (sqlite, kafka), **nkeys**, **prost**, the **cli cluster**, and **otel** — not the hot-path primitives, whose marginals are ~0–3 and whose risk class is the worst.

---

## 5. Classification: every dependency, one verdict (Rev 3)

**Legend:** `REMOVE` · `STD` · `OWN` (with safety class) · `FRANKEN` · `KEEP` · `DEV-KEEP`. Phases per §7.

| Crate | Verdict | Phase | Note |
|---|---|---|---|
| `crossbeam-deque`, `hkdf` | REMOVE | 0 ✅ | dead; done |
| `hashbrown` | STD | 2 | 2 sites → std/`DetHashMap`; marginal ~4 |
| `num_cpus`, `whoami` | STD | 2 | one call site each |
| `env_logger` | REMOVE | 2 | 2 lines → tracing shim |
| `time` | REMOVE | 2 | 1 call site → own RFC3339-ns formatter (SAFE-OWN) |
| `tempfile` | OPTIONALIZE→DEV-KEEP | 2 | optional on `benchmark-adapters`/`test-internals`; no rewrite |
| `bincode-next` + `rmp-serde` | OWN (SAFE) | 3→5 | **API decision first** (§7 Phase 3): `SerdeCodec`'s public Bincode/MessagePack variants are replaced by JSON + explicit purpose-built codecs; snapshot and trace schemas hand-coded separately. Marginal ~5 + 2 |
| `futures-lite` | OWN (SAFE) | 2 | `block_on`/`poll_fn`/`zip`/`race`/`yield_now` in `util/future.rs` |
| `visibility` | OWN (SAFE) | 2 | 12 uses → `asupersync-macros` attr |
| `slab` | STD/OWN (SAFE) | 2 | unify on in-tree `TokenSlab` family |
| `hex`, `base64` | OWN (SAFE) | 2 | scalar-safe engines; marginal ~1 each — justified by triviality, not weight |
| `semver` | **KEEP** | — | flipped in Rev 3: one safe marginal package with subtle precedence rules; poor risk-adjusted value to replace |
| `thiserror` | **KEEP** (defer) | — | flipped: nets −2 packages for 112-file churn; revisit only in a suite-wide macro consolidation |
| `pin-project` | **KEEP** (defer) | — | flipped: nets −2; replacement macro is soundness-critical (ALGORITHMIC-UNSAFE class) |
| `smallvec` | **KEEP** | — | flipped: ALGORITHMIC-UNSAFE class; marginal 0 while parking_lot remains |
| `crossbeam-queue` | **KEEP** | — | flipped: ALGORITHMIC-UNSAFE class. A SAFE mutex-backed queue may be *prototyped and benchmarked*; the incumbent leaves only if the safe variant wins or ties (§3 exception process otherwise) |
| `memchr` | **KEEP** | — | flipped: marginal 0 (serde_json). Revisit only if serde_json ever goes |
| `socket2` | **KEEP** | — | flipped: marginal ~1; real scope (socket creation, SockAddr conversion, abstract-Unix, SockRef, keepalive, cross-platform options) was understated. Evidence-gated revisit in Phase 8 |
| `polling` | **KEEP** | — | flipped: marginal ~1; replacement must own EINTR, fd reuse, generation tokens, wakeups, fork behavior, registration races, oneshot/edge, kqueue, IOCP. Evidence-gated revisit in Phase 8 |
| `signal-hook`, `sysinfo`, `xattr` | OWN (BOUNDARY) — deferred | 8 | consolidation candidates with small marginals; each needs a measured or maintenance-driven justification before build |
| `parking_lot` | OWN (SAFE wrapper) | 8 | `sync/oslock.rs`: owned wrapper over `std::sync::{Mutex, RwLock, Condvar}` that recovers poisoned guards internally, exposes our own guard types (fixing the current leak of parking-lot guards into visible signatures), and **compiles on the audited stable lane**. Optional nightly `nonpoison` backend behind a feature. Gate metrics per §6.6. Marginal −3 (parking_lot, parking_lot_core, lock_api) and unblocks smallvec's marginal |
| `prost` | OWN (SAFE) | 5 | after the Phase-3 API decision: owned `ProtoMessage` trait + finite hand-written message types replace the public generic `ProstCodec`. Marginal 6. Prerequisite for native OTLP |
| `toml` | **REMOVE (migrate)** | 3/5 | flipped from OWN: current call sites are generic serde deserialization + pretty serialization — a "subset TOML" is really a serde data-format implementation. Configs migrate to **versioned JSON** (serde_json is permanent). Owner-visible behavior change; documented in the Phase-3 API decisions |
| `serde_yaml` | REMOVE (migrate) | 5 | deprecated upstream. JSON migration with **data-preservation rules**: comments/anchors/scalar-distinction loss is enumerated per file, semantic goldens for every scenario, manual review of the converted corpus, and old YAML files are deleted only with explicit owner permission |
| `clap` | OWN (SAFE) — **XL** | 5 | re-scoped: ~33.8k CLI lines, hundreds of attr sites; owned parser must cover OsString/invalid-UTF-8, `--`, short clusters, negative values, global/flattened args, counts, custom parsers, defaults, value delimiters/enums, help text, exit codes, error goldens. Part of the Phase-3 API decision for the CLI surface |
| `chrono` | OWN (SAFE) | 5 | `UtcTimestamp` + RFC3339 + serde impls |
| `regex` | OWN (SAFE) | 5 | fixed PII scanners + subset matcher that **fails closed** on unsupported syntax (PII must never silently degrade) |
| `opentelemetry`/`_sdk` | OWN (SAFE) — **XL** | 5 | re-scoped: this is an implementation replacement **and** a public interoperability removal (external `Meter`/SDK consumers). The Phase-3 decision must explicitly approve dropping external-SDK interop, redesigning around our owned exporter traits. Depends on the prost replacement |
| `rusqlite` + `sqlparser` | FRANKEN | 6 | FrankenSQLite under combined-graph + parity gates (§9.1) |
| `rdkafka` | REMOVE | 7 | remove the feature after a downstream-inventory check confirms no consumer. Native client = **independent future campaign** (§9.3), not sized here |
| `nkeys` | OWN (SAFE) | 4 | security-contract replacement (§9.5); marginal ~16 |
| `x509-parser` | OWN (BOUNDARY) — **security epic** | 8 | re-scoped (§9.4): delegate maximally to rustls/webpki; own only extraction that cannot be delegated; full checklist (canonicality, full-input consumption, ASN.1 time, KU/EKU/BasicConstraints, SAN, SPKI, duplicate/critical-extension policy, error-mapping parity) |
| `flate2` | OWN (stretch) | 8 | pure-Rust miniz_oxide meanwhile |
| `brotli` | **DECISION REQUIRED** | 3 | flipped from REMOVE: it is a real public HTTP compressor/decompressor and an ATP manifest capability — removal reduces interoperability. Owner must either keep the pure-Rust dep or explicitly approve capability removal with the HTTP + ATP impact documented. Until then: KEEP |
| `lz4_flex` | OWN (SAFE) | 8 | ~1–1.5k lines realistic |
| `unicode-normalization` | **KEEP** | — | flipped: hand-maintaining Unicode tables/versioning/security semantics is a poor target. The dependency-free alternative — rejecting non-ASCII paths — is an owner-level product decision, offered but not assumed |
| `serde` + `serde_json` | KEEP | — | keystone; suite-level decision later |
| `sha1/sha2/hmac/subtle/zeroize/getrandom`, `aes-gcm`, `chacha20poly1305`, `ed25519-dalek` | KEEP | — | audited crypto; not a place for NIH |
| `rustls` + pki-types + pemfile + roots | KEEP | — | §8.2 for ring/Graviola |
| `libc`, `nix`, `windows-sys`, `io-uring`, wasm-bindgen family | KEEP | — | FFI/ABI bedrock |
| `tracing`/`tracing-subscriber`, `backtrace`/`rustc-demangle`, `loom` (feature-gated normal), `tower`, `tokio`+`async-trait` (benchmark lane), `arbitrary`, `opentelemetry-proto` (fuzz) | KEEP | — | isolated, feature-gated, or verification lanes. Note: `cli` currently enables `tracing-integration`, so retained tracing crates remain a marginal cost of `cli` unless that feature edge is dropped — recorded in Appendix B |
| `syn`/`quote`/`proc-macro2` | KEEP | — | permanent residents (our macros + serde_derive) |

Satellites: `asupersync-tokio-compat` = KEEP-by-design (it *is* the Tokio boundary); `conformance` + `fuzz/` = DEV-KEEP verification lanes; `asupersync-browser-core`'s `serde-wasm-bindgen` = browser ABI KEEP; `frankenlab` follows the CLI/YAML decisions; `drop_unwrap_finder` = internal tool. npm `packages/` handled in Phase 9. Dev-dependencies: all DEV-KEEP; replaced crates stay as differential oracles for two release cycles.

---

## 6. Performance doctrine (Rev-3-corrected)

1. **Safe portable baseline first; ledgered dispatch second, only where measured** (the GF(256) pattern).
2. **`std::simd` honesty:** it is a nightly experimental API; codegen may split wide ops into multiple instructions or scalarize — it is *not* guaranteed "full-strength NEON/AVX2". Treat portable-SIMD results as an empirical question per kernel: benchmark, inspect codegen where it matters, and fall back to ledgered `#[target_feature]` intrinsics (BOUNDARY-UNSAFE) when the numbers demand.
3. **x86-64 baseline is SSE2** without target-feature dispatch; AVX2/AVX-512 need runtime dispatch through ledgered shims. AVX-512 notes: Zen 4 executes 512-bit ops over two 256-bit paths; **Zen 5 has a native 512-bit datapath** — do not group them; Intel pre-Ice-Lake downclocking still argues for runtime gating.
4. **Apple Silicon:** prefer branchless scalar below ~64 B; `std::hint::spin_loop` lowers to `isb` on aarch64 (a pipeline-flush hint — *not* a WFE wait protocol; do not design spin loops assuming event-wait semantics).
5. **Cache-line padding is measured, not global:** aarch64 ≠ Apple Silicon. Do not blanket-change `CachePadded` to 128 B; scope 128-byte padding to *specific measured structures* on target families where the benchmark shows contention wins (Apple M-series 128-B lines; x86 adjacent-line prefetcher), keeping 64 B elsewhere to avoid wasting cache.
6. **Lock/primitive gate metrics (replaces the Rev-2 "2% p50" gate):** throughput, p50/p95/p99/p999, fairness (max starvation), cancellation latency, allocations + RSS, compile time, binary size, and 1/8/32/64-core scaling curves on the tracked bench set. A replacement ships only if it is within threshold on *all* tracked axes or the regression is explicitly accepted by the owner.
7. **Determinism trumps micro-wins:** bit-exact outputs across ISAs remain part of every kernel's contract.

**Verification stack per replacement:** differential property tests vs the replaced crate (dev-dep oracle) · golden vectors · fuzz target · Miri on unsafe modules (with the §3 caveat that Miri does not prove concurrent liveness or weak-memory correctness) · criterion ratchet · UBS.

---

## 7. Execution plan (Rev 3 — DAG, not "embarrassingly parallel")

Rev 2's "Phases 1–3 are embarrassingly parallel" was false: bincode and MessagePack both touch `typed_symbol.rs`; prost is a prerequisite for native OTLP; TOML/YAML/chrono/clap overlap heavily in the CLI files and manifests; parking_lot gates smallvec's marginal. The plan is now an ordered DAG; within each phase, listed items are independent **only if their file sets are disjoint — every bead carries exact file reservations**.

**Phase 0 — Hygiene. LANDED** (`a86bfb3a6`; net −2 crate-versions / −3 names; UPGRADE_LOG.md pass 4).

**Phase 1 — Foundations (blocks everything).**
1.1 Safety-taxonomy artifact (§3) as `artifacts/dependency_safety_taxonomy_v1.json` + contract test.
1.2 Marginal-ledger generator (§4) from `cargo metadata` package IDs, per-platform, synthesized-consumer root excluded; committed artifact + contract test.

**Phase 2 — Low-risk leaf removals (SAFE-OWN/STD only; genuinely parallel, disjoint files).**
hashbrown→std/DetHashMap · num_cpus/whoami→std · env_logger removal · `time` consolidation · tempfile optionalization · futures-lite→`util/future.rs` · visibility→own attr · slab→TokenSlab · hex/base64 own engines · delete the `mod regex` mock (plain digit-run parser stopgap) · file the orphaned-e2e-files wire-or-remove bead (owner sign-off).

**Phase 3 — Public API decisions (blocks all codec/CLI/otel work; produces ADRs + api_surface_map updates, no implementation).**
3.1 `SerdeCodec` (`typed_symbol.rs`): replace public Bincode/MessagePack format variants with JSON + explicit purpose-built codecs; decide the snapshot and trace schema ownership split.
3.2 `ProstCodec` (`grpc/protobuf.rs`): owned `ProtoMessage` trait over a finite message set; drop the public arbitrary-`prost::Message` surface.
3.3 OTLP/metrics: redesign around owned exporter traits; **explicit decision to remove external OpenTelemetry `Meter`/SDK interoperability** (or abandon the replacement).
3.4 Config formats: TOML→versioned-JSON migration decision; YAML scenario migration rules (data preservation, goldens, manual review, owner permission for deletions).
3.5 CLI surface: owned-parser contract (XL scope per §5) and help/error-golden strategy.
3.6 Brotli: keep vs. approved capability removal (HTTP + ATP manifest impact documented).
Each ADR updates `artifacts/api_surface_map_v1.json` and docs in the same commit.

**Phase 4 — nkeys replacement under a security contract (independent of Phase 3).**
`security/nkey.rs` (SAFE-OWN): base32/RFC 4648 no-pad + CRC-16/XMODEM + prefix codec on a direct `ed25519-dalek` dep; NATS-fixture differential vectors vs nkeys (dev-dep); security-review bead before merge. Marginal ~16.

**Phase 5 — Codec/CLI implementation in dependency order (after Phase 3).**
5.1 Owned protobuf types + wire codec (SAFE-OWN; test-only varint helpers as oracle) → 5.2 native OTLP exporter (XL) → in parallel with 5.1/5.2 where files are disjoint: typed-symbol/snapshot/trace format redesign (bincode+rmp exit together — same files, one bead), TOML→JSON migration, YAML→JSON migration, chrono replacement, clap replacement (XL), regex→fail-closed scanners.

**Phase 6 — FrankenSQLite integration (independent campaign; §9.1 gates).**

**Phase 7 — Kafka feature removal** after downstream-inventory confirmation; native client explicitly out of scope (§9.3).

**Phase 8 — Evidence-gated deferrals (each needs a measured/maintenance justification + owner sign-off before build).**
parking_lot→SAFE `sync/oslock.rs` wrapper (stable-lane-compatible; §9.2) · signal-hook/sysinfo/xattr consolidation (BOUNDARY) · x509 security epic (§9.4) · polling/socket2 revisit (only with measured defect or a suite-wide platform-boundary project) · flate2/lz4/DEFLATE work · crossbeam-queue SAFE prototype benchmark.

**Phase 9 — Continuous enforcement.**
Dependency budget contract from the marginal ledger (synthesized consumer, per-platform, ratchet-down) · `cargo deny`/`cargo audit` over the full workspace incl. dev/build graphs · GitHub Actions pinned by commit SHA · npm `packages/` + pnpm lockfile audit · `fuzz/` graph in the sweep · consumer guidance (library lockfiles don't protect consumers; minimal-versions lane; `cargo vendor` posture) · AGENTS.md dep table generated from the contract.

**Bead re-mapping (beads paused per review, resume against this list):** `d24mms` = Phases 1–2 · `5z2scg` = Phases 3+5 · `ym2wtv` = Phases 4, 6, 7 · `3u3tej` + `0h6myr` = Phase 8 (evidence-gated; do not start without gate evidence) · `mnotoo` = Phase 9. Epic `ir2uf0` unchanged; `bm3tty` tracks the pre-existing HEAD test redness.

**End-state projection:** replaced by generated forecasts. The ledger (Phase 1.2) emits per-phase projected graphs with confidence ranges; the static "~40–50 names" figure from Rev 2 is retired. Direction, not destination, is the commitment: every phase must reduce trusted upstreams, native/unsafe surface, or marginal weight — and prove it with the recomputed ledger.

---

## 8. What we deliberately keep

### 8.1 Cryptography is not a place for NIH
`sha1/sha2/hmac/subtle/zeroize/getrandom/aes-gcm/chacha20poly1305/ed25519-dalek`: audited, pure-Rust, security-load-bearing. Non-negotiable keep. We remove crypto-adjacent *packaging* (nkeys' text codec; x509 extraction where webpki can't help), never the primitives.

### 8.2 rustls and the ring problem
Keep rustls. For the ring provider: **Graviola is a provider *experiment*, not a default switch** — it is very new, incorporates (formally verified) assembly, supports only x86_64/aarch64, and requires substantial CPU features; it does not satisfy a literal no-unsafe/no-assembly rule and needs runtime/fleet eligibility handling. Trial it on the encrypted ATP matrix; adopt only with owner sign-off on the assembly trade. FrankenTLS remains out of scope.

### 8.3 serde / serde_json
Keystone (~4,600 derives, ~1,450 `json!`). Keep; any `franken-serde` is a suite-level decision after this plan completes. serde_json's permanence is also why JSON is the migration target for TOML/YAML and why memchr's marginal is zero.

### 8.4 FFI bedrock and the mature-unsafe principle
`libc`/`nix`/`windows-sys`/`io-uring`/wasm-bindgen family: the platform boundary. The same reasoning now explicitly protects `crossbeam-queue`/`smallvec`/`pin-project` (§3): mature, widely-fuzzed algorithmic unsafe beats fresh first-party algorithmic unsafe until measurement says otherwise.

### 8.5 FrankenSuite non-candidates (for the record)
**FrankenFS** is not a host-xattr substitute (its xattr work is filesystem/on-disk semantics, not portable syscalls). **FrankenLibC** is Linux/interposer-oriented prior art with intentional unsafe ABI boundaries — its syscall/signal//proc logic can inform Phase-8 implementations but cannot replace the cross-platform layer.

---

## 9. Flagship designs (Rev-3-scoped)

### 9.1 FrankenSQLite (replaces `rusqlite` + `sqlparser`)
Direction confirmed: fsqlite-core's asupersync dependency is unconditional, so integration **must** be inverted — asupersync's `sqlite` feature is deprecated/removed; fsqlite's existing `async-api` grows the `Cx`-threaded glue. This is **capability relocation, not zero dependency cost**: fsqlite's async graph carries its own external crates and currently resolves the published asupersync 0.3.9 graph. Gates before the swap: (a) a **combined fsqlite + asupersync consumer budget** measured with the §4 ledger; (b) a **semantic parity matrix** — transactions, prepared statements + cache, interruption, budget-derived timeouts, typed rows, cancellation behavior — proven against the existing sqlite e2e suite running on both engines during overlap; (c) honest maturity framing: fsqlite's native mode is partial per its own README — the claim is *owned, safe, concurrent-writer SQLite on our runtime*, not "MVCC and RaptorQ durability for free."

### 9.2 parking_lot → `sync/oslock.rs` (SAFE-OWN, stable-compatible)
An owned wrapper over `std::sync::{Mutex, RwLock, Condvar}` that (a) recovers poisoned guards internally (`PoisonError::into_inner`) so call sites keep non-poisoning ergonomics, (b) exposes **our own guard types** — fixing the current leak of parking-lot guards into visible signatures, (c) compiles identically on the audited stable lane (`--no-default-features --features proc-macros`), with an optional nightly `nonpoison` backend behind a feature for contributor lanes, and (d) covers `Condvar` (production-load-bearing in `blocking_pool`/`discover`). Ships only through the §6.6 multi-axis gate on 1/8/32/64 cores. Marginal: −3 packages + unblocks smallvec's.

### 9.3 Kafka: remove now, campaign later
Remove the `kafka` feature once downstream inventory confirms no consumer (bundled librdkafka C leaves immediately). Any native client is an **independent protocol campaign** with its own epic: API-version negotiation matrix, flexible/tagged fields, coordinator protocols (groups/heartbeats/rebalance), idempotence epochs/sequences, transactions, isolation levels, offset management, compression codecs, TLS/SASL, metadata refresh + retry semantics, fuzzing, and real-broker conformance. The current surface it would have to match is ~7k lines of wrapper API including transactional producers and consumer groups — no line estimate is retained here by design.

### 9.4 X.509: a security epic, not a parser swap
Current x509-parser usage is **active validation**, not just extraction (§2.5): validity windows, server EKU, KeyUsage, BasicConstraints CA:TRUE, per-chain validity, SAN matching, SPKI pinning, plus error-mapping consumers. Strategy, in order: (1) **delegate every check rustls/webpki can perform to rustls/webpki** — chain validity, EKU, name checking on the standard path; (2) inventory what genuinely cannot be delegated (SPKI-bytes extraction for pinning; SAN access inside the custom native-QUIC verifier); (3) only then scope `tls/der_min.rs` for that residue, with the full checklist: DER canonicality, full-input consumption, ASN.1 time parsing, duplicate/critical-extension policy (hard error), depth caps, fail-closed ambiguity handling, and byte-for-byte error-mapping parity with today's diagnostics. Differential fuzzing vs x509-parser over an openssl-generated + BetterTLS/limbo-style mutated corpus (to-be-built). Own epic + security-review bead; not schedulable from this plan alone.

### 9.5 nkeys → `security/nkey.rs`
Unchanged from Rev 2 except honest accounting: ~200 lines SAFE-OWN codec (base32 no-pad + CRC-16/XMODEM + prefixes) on a direct ed25519-dalek dep; **marginal ~16 packages**; NATS-fixture differential vectors; the digest-generation dedup additionally waits on upstream dalek (§2.3).

### 9.6 `codec/proto.rs` (replaces prost, after ADR 3.2)
Owned `ProtoMessage` trait + hand-written finite message set (gRPC health/reflection/status-details; OTLP export subset). Varint/zigzag/tag/skip codec, SAFE-OWN; `#[cfg(test)]` helpers in `grpc/protobuf.rs` as oracle; round-trip vs prost under proptest; OTLP goldens vs `opentelemetry-proto` fixtures (dev/fuzz-only). Marginal 6; prerequisite for 5.2.

---

## 10. Risk register (Rev 3)

| Risk | Mitigation |
|---|---|
| Fresh algorithmic unsafe introduces liveness/UB bugs mature crates don't have | §3 prohibits the class by default; exceptions need measured defect + safe-alternative benchmark + owner sign-off |
| Public API redesigns (SerdeCodec/ProstCodec/Meter/CLI/config) ship half-decided | Phase 3 ADR gate blocks implementation; api_surface_map + docs updated per ADR |
| X.509 replacement drops an active security check | §9.4 delegate-first strategy; residue checklist; differential fuzz; security-review bead; error-mapping parity requirement |
| Stable lane breaks (parking_lot replacement, nightly-only APIs) | §9.2 stable-first design; `run_stable_lane_e2e.sh` added to the gate set for every Phase-8 primitive |
| PII-redaction subset silently weakens operator configs | fail-closed pattern compiler; migration guide |
| YAML/TOML→JSON migration loses semantic content | per-file preservation notes, semantic goldens, manual corpus review, owner permission before any YAML deletion |
| Brotli removal degrades HTTP/ATP interop | Phase-3 decision item with documented impact; default KEEP until decided |
| Kafka removal strands an unknown consumer | downstream inventory check gates the removal |
| FrankenSQLite swap regresses semantics or inflates the combined graph | §9.1 parity matrix + combined-graph budget + overlap period |
| Trace/snapshot format churn breaks replay tooling | format-version bumps + `trace/compat.rs`; registry-consumer exposure checked (frankensqlite pins 0.3.9) |
| Marginal-ledger drift makes priorities stale | ledger regenerated and committed after every phase; budget contract fails closed on drift |
| Agent-swarm conflicts on shared files (typed_symbol, CLI cluster) | DAG ordering + exact per-bead file reservations (§7) |

---

## Appendix A — Graph snapshots
Pre-Phase-0: 132 crate-versions / 124 names. Post-Phase-0 (`a86bfb3a6`): 130 / 121. Duplicate-version driver: nkeys→dalek old-gen chain. Full lists regenerate via Appendix C.

## Appendix B — Feature-cost table (names, post-Phase-0)
| Feature | Adds today | End-state |
|---|---|---|
| (default) | 121 | generated forecast (Phase 1.2 ledger) |
| `tls` | +26 | the measured rustls/provider/webpki closure (~12–15; forecast-generated) |
| `sqlite` | +10 + bundled C | 0 external here; capability relocates to FrankenSQLite's own measured graph (§9.1 combined budget) |
| `kafka` | +13 + bundled C | 0 (feature removed; future native client is first-party code, tracked separately) |
| `metrics` | +13 | 0 external **if** ADR 3.3 approves dropping external-SDK interop |
| `cli` | +43 | approaches 0 external **minus** the retained tracing crates while `cli` keeps its `tracing-integration` edge (dropping that edge is part of ADR 3.5) |
| `compression` | +8 | per Brotli decision (ADR 3.6); flate2 interim |

## Appendix C — Measurement methodology (Rev 3)
```bash
# Canonical counting: cargo metadata PACKAGE IDS, not crate-name text parsing.
# 1. Synthesize a consumer crate depending on asupersync (path dep, chosen features).
# 2. cargo metadata --format-version 1 --filter-platform <triple> on that consumer.
# 3. Count resolve-graph package IDs reachable via normal+build edges from the
#    consumer root, EXCLUDING the synthetic root itself and workspace-path members.
# 4. Report Linux, macOS, Windows, and wasm32 graphs separately; report both
#    unique-name and crate-version counts.
# 5. Marginal cost of root R = |graph| - |graph with R's edge removed|.
# The ledger generator (Phase 1.2) implements this; ad-hoc `cargo tree | awk`
# pipelines are for exploration only.
# Native-code attribution must be lockfile-verified (declared build-deps can be
# feature-gated off — see rdkafka/signal-hook corrections in §2.2).
```
