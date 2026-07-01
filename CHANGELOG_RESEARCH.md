# Changelog Research Notes

## 2026-07-01 Unreleased ATP / Skill-Refresh Pass

Scope: summarize material changes since the prior `asupersync-mega-skill`
creation point, with enough evidence to update both `CHANGELOG.md` and the
canonical skill in `/data/projects/je_private_skills_repo`.

Sources used:

- `AGENTS.md` and `README.md` in `/data/projects/asupersync`
- `CHANGELOG.md`
- `git log --since=2026-06-01 --oneline --decorate`
- `gh release list --limit 100`
- `br list --json`
- `br list --status closed --json`
- `cass status`
- focused `cass search ... --robot --limit ...` / `cass view ... --json`
- read-only subagent passes over current APIs, git/beads history,
  runtime semantics, and cass-mined session rules

High-confidence findings:

- The latest visible GitHub release is `v0.3.4` on 2026-06-07. The changelog
  also records a `v0.3.5` release-train entry dated 2026-06-18, but no matching
  local tag was visible during this pass.
- The current public runtime example is no longer the older
  `Cx::for_request()` bootstrap. The README shows `RuntimeBuilder`, `Runtime`,
  `RuntimeHandle::spawn`, ambient `Cx::current()`, and `Cx::spawn`.
  `Cx::for_request()` / `Cx::for_testing()` are test-internals gated.
- `tokio::spawn` should map to `Cx::spawn` or `Cx::spawn_in`.
  `Scope::spawn_registered` remains a lower-level boot/test path for callers
  that already hold `&mut RuntimeState`.
- The workspace now includes the root crate, `asupersync-macros`,
  `asupersync-browser-core`, `asupersync-tokio-compat`, `conformance`,
  `franken_kernel`, `franken_evidence`, `franken_decision`, `frankenlab`, and
  `drop_unwrap_finder`; `fuzz` and `asupersync-wasm` are excluded scaffolds.
- ATP evidence is matrix-governed. Claims must use the benchmark harnesses,
  tuned rsync baseline, release `atp`, crypto-symmetric cells, SHA/tamper
  checks, rate caps, and whole-matrix accounting.
- Late-June ATP work landed authenticated control-source stream paths,
  reliable encrypted clean-source stream handling, ack-clocked QUIC datagram
  pacing, repair-spray pacing, incremental hash-on-receive, protocol-v3
  `ObjectComplete` hash trailers, and commit-time same-filesystem renames.
- `br-asupersync-2eb4k2` records 500M clean wins against tuned rsync, and
  `br-asupersync-sze9ym` records 5G clean wins plus a commit-write reduction.
  Harder encrypted/QUIC and delta-resync blockers remain explicitly active.
- RaptorQ should be described as proof-carrying and fail-closed, with decode
  verification guards, symbol-auth posture, tamper witnesses, rank-profile
  evidence, and data-loss regression fixes.
- Proof-lane artifacts are first-class. `artifacts/proof_lane_manifest_v1.json`,
  `artifacts/proof_status_snapshot_v1.json`, validation-frontier artifacts,
  scripts, and contract tests must move together.
- Browser Edition has package/readiness/integrity gates and
  `asupersync-browser-core` is the canonical browser core; Rust browser runtime
  APIs remain explicit browser-lane surfaces, not a blanket server/edge story.
- Service surfaces have expanded materially across H2 listener/drain behavior,
  middleware layering, HTTP request builders, database transaction obligations,
  and gRPC call-scoped backpressure/cancel coupling.
- Runtime CPU work introduced `runtime-metrics`, scheduler churn evidence,
  shared process-global no-driver sleep fallback, a warn-once fallback path, and
  `RuntimeBuilder::enable_time()`.

No-claim boundaries to preserve:

- Do not claim ATP wins from compile-only evidence, stale matrix artifacts, or
  `sha_ok` without timing/bytes evidence.
- Do not present native QUIC/H3 as generic release-ready interoperability.
  Treat it as requirement-driven and verify exact protocol needs.
- Do not present Browser Edition as direct runtime support for SSR, edge, or
  Node-only contexts.
- Do not call Asupersync DPOR "optimal"; current source describes
  DPOR-style guided coverage with race/backtrack extraction.
- Do not use `Cx::for_request()` as a production teaching path.
