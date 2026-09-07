# QUIC receive-run regression evidence

Bead: `asupersync-gwmn38`. Measured on 2026-09-07 through strict RCH on
`ovh-a`. Replacing per-frame receive nodes with contiguous runs fixes the
8 MiB receive-window failure: all three baseline bad-profile transfers failed
the fragment guard; all three repaired transfers delivered the full object.

| Revision | Profile | Verified transfers | Median wall to exit (s) | Wall CV | Sender peak RSS median (KB) | Receiver peak RSS median (KB) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Before | good | 3/3 | 71.095 | 7.19% | 57756 | 27588 |
| After | good | 3/3 | 70.195 | 8.02% | 64692 | 25508 |
| Before | bad | 0/3 | 363.337, error exit | N/A for completed transfers | 60164, failed transfers | 20220, failed transfers |
| After | bad | 3/3 | 92.517 | 0.87% | 40000 | 28148 |

The good-profile timing samples are noisy under the existing scorer's 5% CV
rule. Sender peak RSS increased in that sample while receiver peak RSS
decreased. These results do not establish a speed improvement, memory
improvement, or absence of regression. Failed baseline durations and RSS are
not successful-transfer measurements and must not become speedup ratios.

Every successful row has matching source/destination SHA-256, receiver
`committed=true sha_ok=true merkle_ok=true metadata_ok=true`, exactly
524288000 received bytes, and both sender and receiver exit status 0. Every
baseline bad receiver reports `stream receive reassembly fragment limit
exceeded`; its sender exits 2. The baseline matrix exits 3 and the repaired
matrix exits 0. All 12 planned phase/case pairs are present exactly once.

## Inputs and identity

- Payload: the same 500 MiB file in every transfer, SHA-256
  `53cc7cdee6c62f5ad254377f8671ae3b2f1bd948362051f2bc7bcc9d41a787e1`.
- Method: `atp-quic-tls13`, encrypted tier, one source stream, four workers,
  8 MiB initial and maximum receive windows, three repetitions per profile.
- Good: 200 Mbit/s, 25 ms delay, 0.1% loss. Bad: 50 Mbit/s, 80 ms delay
  with 20 ms jitter, 2% loss. Netem applies at both ends of the namespace link.
- Unchanged matrix timeout: 1800 seconds. Baseline failures follow ATP's
  ordinary error path; they are not harness timeouts.
- Both binaries use pinned `nightly-2026-08-31`, `--locked --release`,
  `--features atp-cli --bin atp -j2`, the unchanged Cargo release profile,
  `CARGO_INCREMENTAL=0`, and `RUSTFLAGS='-D warnings -C debuginfo=0'`.
- Before source: `382bc5823989e8376995c7567a8d332b85294b11`;
  binary SHA-256 `c986e952c656ec3e46c92f8427f8950e79ed6afb626885cf264b763f4949a1be`.
- After source: `97335c1cd5167972262e30a6d902edc6d44dfca9`;
  binary SHA-256 `89d74be1353d4cb233f54a2e911b111b2b9b5ff18422b43c67fb7d159e31717a`.

The production source difference between those revisions is confined to
`src/net/quic_native/streams.rs`; the remaining differences are regression
tests and tracker evidence. Both release builds used RCH clean-overlay mode
with their fixed base revision and no overlay. The unchanged harness scripts
were copied outside Git and hash-checked before each phase, allowing their
documented `ATP_MATRIX_GIT_HEAD` fallback to identify the compiled revision
without relying on the worker mirror's stale `.git` metadata.

The exact build and matrix commands, terminal RCH results, script hashes,
and binary checks are retained in [proof/](proof/). The phases ran serially
and each matrix reserved both configured RCH slots on `ovh-a`. The job
invocation unsets inherited `CARGO_BUILD_JOBS` because it is not a Cargo job;
it uses the supported two-slot RCH setting without changing worker policy.

## Behavioral and compiler checks

- The original linked-runtime 8 MiB regression fails at frame 4097 on the
  baseline. Its hostile-fragment companion passes on that same baseline.
- The repaired focused endpoint target passes all 94 tests, with no failed,
  ignored, or filtered tests. It includes retained-byte pointer checks,
  forward/reverse run coalescing, one-hole bridging, hostile-fragment
  refusal, partial-read RESET prefix preservation, and an independent
  byte-coverage oracle for admission.
- Default all-target `cargo check`, all-target Clippy with `-D warnings`,
  and `cargo fmt --check` pass through RCH. The native stream module is
  compiled in the default runtime surface.
- The isolated source test module has one documented `expect(dead_code)`
  for helpers whose production callers are outside that module. Production
  lint rules and all behavioral assertions remain intact. UBS's deliberate
  test-panic finding was reviewed; it is not claimed as a clean UBS run.

The test/check/Clippy/fmt evidence binds base `382bc5823` and owned overlay
fingerprint `9ff215e955b40e94412344f1e479dbc314492ae950987a9f26e8d1bf957633e6`.
Those source bytes are present in the repaired release revision. The
tests-only baseline regression uses the endpoint test overlay without the
production repair. Earlier canceled or compilation-failed attempts ran no
test bodies and are not counted as behavioral evidence.

## Receipts and limits

[Before results](before/results.jsonl), [before plan](before/plan.jsonl),
[before context](before/run_context.json), and
[before scorecard](before/scorecard.md) retain the expected failures.
[After results](after/results.jsonl), [after plan](after/plan.jsonl),
[after context](after/run_context.json), and
[after scorecard](after/scorecard.md) retain all six successful transfers.
Each phase also contains `terminal_status.json` and per-cell receiver logs.

This proves the scoped reassembly repair on a real TLS/UDP namespace link
on one Linux worker. It is not cross-machine WAN evidence, an rsync
comparison, broad workspace health, release readiness, or a fleet guarantee.
The fragment cap and window-growth policy are unchanged. Nonfatal handling
of the genuine fragment cap remains the separate dependent bead
`asupersync-9d0ypz`.

Review was a fresh solo pass over the original acceptance criteria and
terminal remote executions; no independent human or agent review is claimed.
These receipts are retained for SapphireHill's original benchmark acceptance
and future replay. They may be retired after equivalent superseding evidence
is accepted and the owner explicitly authorizes removal; no deletion is
authorized or performed by this packet.
