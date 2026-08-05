# DEP-ADR-005: Capability-complete, accessible CLI contract and tracing/config edges

- Status: accepted
- Date: 2026-07-24
- Owner: SapphireHill
- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Bead: `asupersync-dep-p3-api-adrs-h3jspm.5`
- Capabilities: `CAP-CLI-ASUPERSYNC`, `CAP-CLI-ATP`, `CAP-CLI-ATPD`,
  `CAP-CLI-OFFLINE-TUNER`
- Decision: `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT` for all four
- Machine row: `artifacts/dependency_api_adr_registry_v1.json`
- Supersedes: `COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md` §5 `clap` disposition
  row and §7 Phase-3 item 3.5

## Context

The Rev-3 plan already did the honest thing here. It re-scoped an owned parser
from L to **XL** after measuring roughly 33.8k lines across six clap-consuming
sources with hundreds of derive sites, and it enumerated what a replacement would
have to cover: `OsString` and invalid UTF-8, the bare `--` terminator, short
clusters, negative values, global and flattened args, counts, custom parsers,
defaults, value delimiters and enums, help text, exit codes, error goldens.

This ADR does not overturn that estimate. It adds the reason a replacement cannot
be *evaluated* yet.

**The CLI contract is pinned by source hashes, not behavior.** The registry pins
seven parser sources by SHA-256 and line count — all seven verified matching at
the time of writing — and says so plainly in its own rule: *a hash match is
inventory evidence, not behavioral parity*. Hashes detect that a file changed.
They cannot tell you whether usage text, option spelling, wrapping, ordering,
error wording or an exit path changed meaning. And they cannot survive the
replacement they exist to gate, since an owned parser rewrites those files
entirely.

**There is no help golden anywhere.** No test in the repository captures
`--help`, `-h` or `--version` output for any of the four binaries. The claimed
"help/OsString/accessibility contract" is a prose sentence in the artifact,
enforced by exactly one assertion: that the sentence contains the substring
`shell/OsString`. The only frozen help text that exists is the hand-written
`COMMON_ARGS_HELP` constant.

So an owned parser could pass every test in the tree while silently changing
everything a user sees.

**Two clap feature choices are load-bearing.** Only `derive` is enabled.
`wrap_help` is **off**, so help wraps at clap's fixed default width and never
consults `COLUMNS` or the terminal — a reimplementation that wrapped to terminal
width would be a visible behavior change. The `env` feature is **off**, and there
are zero clap `env =` attributes in the tree, so no argument is populated from
the environment by the parser and every environment read is hand-rolled. That
second fact is good news: the environment contract is already parser-independent.

**The exit contract is not what it looks like.** A shared semantic registry
exists in `src/cli/exit.rs` with ten codes and a valid range, and the capability
registry contract parses that file and asserts equality with the artifact — the
strongest CLI contract in the repo. But only **one of four binaries uses it**.
`atp` returns `std::process::ExitCode::SUCCESS`/`FAILURE`, i.e. 0 or 1. `atpd`
returns a `Result`, so a failure exits 1 through Rust's default `Termination`.
`offline_tuner` calls `process::exit(1)` directly. No test asserts a nonzero
semantic code from a real binary run at all.

**One command tree is unreachable.** `src/cli/atp_command_tree.rs` is dense clap
code defining 22 commands — `config`, `ci`, `dataset`, `fuzz`, `release`,
`archive` and more — and **no binary imports it**. Its only consumers are
`atp_config.rs`, `atp_workflows.rs` and the module re-export. None of those
commands can be typed by any user today.

## Decision

`clap` stays for all four binaries at `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`.

1. Every currently typable command, alias, option, short form, positional,
   default, value parser and constraint **MUST** be preserved, across all four
   binaries.
2. The two hidden `atp` commands **MUST** keep both their exact
   double-underscore spelling and their hidden status. `serve` **MUST** remain
   accepted as an alias for `recv`.
3. The `wrap_help`-off width policy and the absence of parser-populated
   environment variables **MUST** be preserved, or declared as reviewed changes.
4. The color precedence — `NO_COLOR` over `CLICOLOR_FORCE` over TTY detection —
   and the format precedence — `CI`, then non-TTY stdout, then
   `ASUPERSYNC_OUTPUT_FORMAT`, then Human — **MUST** be preserved. Both are
   hand-rolled and therefore portable across any parser.
5. Stream routing **MUST** be preserved: data on stdout, progress on stderr, each
   consulting its own stream's terminal state.
6. Existing exit-code *values* **MUST NOT** be reassigned. Codes may be added.
7. The current per-binary exit asymmetry is **frozen as observed behavior**.
   Unifying it is desirable but is a user-visible change requiring its own
   review and evidence, because scripts and CI depend on the codes as they are.
8. `src/cli/atp_command_tree.rs` **MUST NOT** be treated as user-facing
   vocabulary while it remains unreachable.
9. A parser replacement **MUST NOT** be attempted before byte-level argv, help,
   usage, version and error goldens exist for all four binaries, plus non-UTF-8
   argv coverage and real-binary nonzero exit assertions.
10. The `tracing-integration` edge on `cli` **MUST NOT** be dropped until
    subscriber initialization and verbose behavior are specified, so removing
    `env_logger` or `clap` cannot silence diagnostics.

## Allowed tradeoffs

- Adding commands, options and output formats is permitted and encouraged.
- An owned parser may improve determinism, diagnostics, startup time, binary size
  and discoverability — once measured against goldens.
- The exit asymmetry may be unified, as a deliberate reviewed change.

## Forbidden compromises

- Removing or renaming any command, alias, option or short form.
- Changing a default, value parser or constraint without review.
- Reassigning an existing exit code value.
- Swapping the parser before goldens exist.
- Promoting the unreachable command tree into the user-facing surface silently.
- Citing source-hash matches as behavioral parity.
- Citing the doctor TUI visual-language accessibility constraints as evidence for
  CLI help accessibility — they govern rendered screens, not help output.

## Known gaps

| ID | Gap | Owner |
|---|---|---|
| CLI-GAP-01 | **Four of the eight `source_owners` entries across the CAP-CLI rows do not own the code they are credited with**: `src/cli/mod.rs` (zero clap, pure facade), `src/cli/signal.rs` (zero clap, and `atpd` doesn't use it — it has its own `install_signal_listener` via `signal_hook`), `Cargo.toml` (manifest, not source), `src/cli/atp_command_tree.rs` (clap-dense but unreachable). Every CAP-CLI row names at least one wrong file, while `src/cli/args.rs` and `src/cli/output.rs` — which hold the only frozen help text and the entire color/format contract — are named by none. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| CLI-GAP-02 | The hash-pinned snapshot list and the `source_owners` lists disagree: `args.rs` is pinned but owns nothing; `mod.rs` and `signal.rs` own but aren't pinned. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| CLI-GAP-03 | The shared exit registry is consumed by **one of four** binaries. The semantic exit set is aspirational for the other three. | `asupersync-5z2scg.7.8` |
| CLI-GAP-04 | The registry records the two hidden `atp` commands **without** their `__` prefix, so the recorded names aren't what users type. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| CLI-GAP-05 | The registry pins 10 environment variables; the CLI reads at least 9 more. The count assertion passes only because it checks names against the 7 hash-pinned sources, which exclude `output.rs`, `first_run.rs` and `completion.rs` where several of those reads live. | `asupersync-5z2scg.7.1` |
| CLI-GAP-06 | **No help golden exists** for any binary. The help/OsString/accessibility contract is prose guarded by a substring assertion. This is the central blocker. | `asupersync-5z2scg.7.1` |
| CLI-GAP-07 | No explicit handling or test for non-UTF-8 argv on any platform. | `asupersync-5z2scg.7.6` |
| CLI-GAP-08 | No test asserts a nonzero semantic exit code from a real binary run. | `asupersync-5z2scg.7.11` |
| CLI-GAP-09 | Feature claims are wrong: the tuner row claims `benchmark-adapters` (not in its `required-features`); the atp row claims `tls-native-roots` (atp-cli pulls `tls` + `rustls-native-certs` directly). Registry docs say 14 binaries; the artifact and its test say 15. | `asupersync-dep-p1-foundations-upksjk.5.1` |
| CLI-GAP-10 | The accessibility constraints in code belong to the doctor TUI visual-language contract, not to CLI help. | `asupersync-5z2scg.7.6` |

CLI-GAP-01, -02, -04, -05 and -09 belong to the capability registry and are filed
under `asupersync-dvgpji`. Their discovery is significant: the CAP-CLI rows were
the *hand-curated, deliberately fail-closed* ones. Finding the same class of
error there means the defect is not confined to the rows generated by the
`encoding::`/`decoding::` prefix selector.

## Invariant impact checklist

- [x] Every typable command, alias, option and short form preserved.
- [x] Hidden-command spelling and visibility preserved.
- [x] `wrap_help`-off width policy preserved.
- [x] Zero parser-populated environment variables preserved.
- [x] Color and format precedence preserved.
- [x] Stream routing preserved.
- [x] Existing exit-code values unchanged.
- [x] Per-binary exit asymmetry frozen as observed, not papered over.
- [x] Unreachable command tree recorded as unreachable.
- [x] No compatibility shim or deprecated alias introduced.
- [x] No root export changes, so `artifacts/api_surface_map_v1.json` is untouched.

## Evidence

Evidence state is `BASELINE_PLANNED`. Thirteen scenario IDs across the four
binaries, owned by `asupersync-5z2scg.7.1` (baseline), `.7.6`/`.7.7`/`.7.8`
(unit) and `.7.11` (installed E2E).

The ordering matters and is part of the decision: **goldens first**. Byte-exact
`--help`, subcommand help, `--version`, and error/usage text for all four
binaries; then non-UTF-8 argv coverage; then real-binary nonzero exit assertions.
Only after those exist can an owned parser be measured at all.

Existing coverage is narrower than it looks: the CLI output goldens cover
`Output`/`OutputFormat` formatting, not help; the largest real-argv body is the
`atp` QUIC loopback suite; and `atpd` and `offline_tuner` have no
`try_parse_from` tests at all.

### CLI A1 static inventory slice

The source-fingerprinted declaration inventory now lives at
`artifacts/cli_clap_surface_inventory_v1.json`, with operator notes in
`docs/cli_clap_surface_inventory.md`. Its disposition is
`STATIC_SURFACE_FROZEN_BYTE_GOLDENS_MISSING`: it indexes the four binary roots,
the two shared files, all command variants, argument-group and value-enum types,
feature cells, and adjacent width/environment/config/exit boundaries.

This does not resolve CLI-GAP-06. The artifact deliberately records
`MISSING_EXECUTION_RECEIPTS` and an empty captured-case array because source
inspection cannot establish stdout bytes, stderr bytes, or process exit status.
The A1 bead remains open until the admitted incumbent binaries populate the
required byte-capture matrix.

The field-normalization state is
`COMPLETE_6_OF_6_PRIMARY_SOURCES`. The bounded static cohort expands all 490
`#[arg]` declarations across the six pinned sources, plus 37 implicit
positionals, into 527 source-anchored rows. `asupersync` contributes 174
annotated and 25 implicit fields; its eleven flatten/subcommand plumbing fields
are intentionally not counted as arguments. The inventory records four root
fields copied but not dispatched and the parsed-but-unused doctor recipe-list
JSON flag. Standalone `atp` contributes 99 annotated and ten implicit fields;
its rows preserve distinct `recv`/`serve` variants, repeated explicit
`parse_max_block_size_arg` parsers, and hidden parser fields. The detached ATP
tree contributes 164 annotated fields and no implicit positionals; its five
subcommand-plumbing fields are excluded. Sixty detached rows describe public
command models and 104 describe library workflow models, with both cohorts
explicitly marked `NO_BINARY_PARSER_ROOT`. The consumer classifications
establish only source-level model handoff, not independent per-field dataflow,
binary reachability, or behavior. The cohort also records that
`atpd --foreground` is parsed but unused, tuner weight range prose has no
matching parser or runtime range validation, and shared ATP verify/replay
ratios do have post-parse range validation. None of these rows is byte-golden
evidence.

## Rollback

Triggered by any removed or renamed command, alias, option or short form; any
changed default, value parser or constraint; any altered help, usage or version
text; any changed exit code for an existing condition; any lost environment
interaction; any color, format or stream-routing change; or any newly required
argument. Because the decision is KEEP, rollback means abandoning the replacement
attempt rather than restoring a deleted capability.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

## No-claim boundary

This ADR is a frozen decision and public-surface inventory only. It does not
prove that the planned evidence has run, that the recorded command vocabulary is
equivalent to rendered parser bytes, that the detached ATP model has a binary
parser root, that help or error text is stable, that non-UTF-8 argv is handled
correctly, that exit codes behave as documented on any binary other than
`asupersync`, that an owned parser could reach parity, or that `clap` may be
removed. It also does not certify the capability registry's CAP-CLI source-owner
rows, environment-variable list, hidden-command names or feature claims, which
CLI-GAP-01, -02, -04, -05 and -09 record as incorrect or incomplete.
