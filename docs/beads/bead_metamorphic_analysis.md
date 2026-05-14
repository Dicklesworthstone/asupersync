Channel metamorphic suite triage (CopperPeak, 2026-05-08)

The three channel metamorphic suites are salvageable. The working tree had
already moved them from `.disabled` files into `.rs` files and re-enabled them
from `src/channel/mod.rs`, but the copied files needed repair before they could
stay online:

- `src/channel/mpsc_message_preservation_metamorphic.rs` is wired in
  `src/channel/mod.rs`, but has duplicated trailing text after the final module
  close. `rustfmt --edition 2024 --check` reports an unexpected `)` at line 576.
- `src/channel/broadcast_no_message_loss_metamorphic.rs` is wired in
  `src/channel/mod.rs`, but has duplicated trailing braces after the final
  module close. `rustfmt --edition 2024 --check` reports an unexpected `}` at
  line 610.
- `src/channel/oneshot_exactly_once_metamorphic.rs` is wired in
  `src/channel/mod.rs`, but has duplicated trailing text after the final module
  close. `rustfmt --edition 2024 --check` reports an unexpected `)` at line 660.

The checked-in `.disabled` versions in `HEAD` do not contain those trailing
fragments, so the first repair was to remove the copy/append corruption from the
new `.rs` files. The suites also needed current-API cleanup before they should
stay online:

| MR candidate | Fault sensitivity | Independence | Cost | Score |
|---|---:|---:|---:|---:|
| MPSC permutation preserves the received multiset for commutative consumers | 5 | 5 | 3 | 8.3 |
| MPSC deterministic trace replay preserves received sequence/count | 4 | 4 | 2 | 8.0 |
| MPSC decomposition into N partitions preserves total message count | 5 | 4 | 3 | 6.7 |
| Broadcast fast receivers receive the same post-subscription sequence | 4 | 4 | 2 | 8.0 |
| Oneshot successful send implies exactly one receive and exhausted state | 5 | 4 | 2 | 10.0 |

Repair status:

- The corrupt trailing fragments were removed from all three revived suites.
- The MPSC suite now includes the three requested explicit MRs: reservation-slot
  permutation for commutative consumers, deterministic trace replay, and
  decomposition into N partitions preserving total count and aggregate set.
- The MPSC suite was updated to current `RecvError` variants, `DetRng::shuffle`,
  and capacity-safe single-threaded bounded-channel harnesses.
- The broadcast and oneshot suites were updated for current receive-error
  variants and no longer write to stdout.
- Local `rustfmt --edition 2024 --check` and `git diff --check` pass for the
  channel/doc slice. Remote `rch` compile probes now stop on unrelated
  shared-main errors before completing the lib-test target.
- Required `rch` gates were attempted for bead `asupersync-z0wq1e`:
  - `cargo check --all-targets` stops in unrelated
    `tests/metamorphic_region_table.rs` API drift for
    `RegionCreateError::ParentClosed { .. }`.
  - `cargo clippy --all-targets -- -D warnings` stops in unrelated bin and
    conformance warning debt, including `src/bin/raptorq_profile_manual.rs:64`
    and `conformance/src/otlp_wire_format.rs`.
  - `cargo fmt --check` stops on unrelated formatting debt in
    `src/sync/rwlock.rs`.

Coordination notes:

- The channel files are reserved by CopperPeak for the repair.
- Concrete tracker bead: `asupersync-z0wq1e`.
