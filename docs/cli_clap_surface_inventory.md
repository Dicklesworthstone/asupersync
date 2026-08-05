# CLI clap surface inventory

<!-- BEGIN CLI CLAP SURFACE INVENTORY -->

This document explains the static inventory in
`artifacts/cli_clap_surface_inventory_v1.json` (`cli-clap-surface-inventory-v1`)
for `asupersync-5z2scg.7.1`. It freezes the source shape that future byte-level
goldens must exercise. It does not replace those goldens.

The current disposition is
`STATIC_SURFACE_FROZEN_BYTE_GOLDENS_MISSING`. The dependency decision remains
`KEEP_UNTIL_PARITY`: no parser replacement, command removal, option removal, or
dependency exit is authorized.

## What is frozen

The primary boundary is exactly four binaries and two shared CLI files:

| Source | Reachability | Required features | Parser / subcommand / args / value-enum derives | Clap arg / command / value attributes | Command variants |
|---|---|---|---:|---:|---:|
| `src/bin/asupersync.rs` | binary root | `cli` | 1 / 10 / 52 / 4 | 174 / 12 / 3 | 83 |
| `src/bin/atp.rs` | binary root | `atp-cli` | 7 / 1 / 0 / 4 | 99 / 8 / 0 | 9 |
| `src/bin/atpd.rs` | binary root | `atpd-daemon` | 1 / 2 / 3 / 0 | 18 / 5 / 0 | 11 |
| `src/bin/offline_tuner.rs` | binary root | `cli,simd-intrinsics` | 1 / 1 / 0 / 1 | 15 / 4 / 3 | 5 |
| `src/cli/args.rs` | shared by the library and `asupersync` | `cli` | 0 / 0 / 4 / 0 | 20 / 0 / 0 | 0 |
| `src/cli/atp_command_tree.rs` | library-exported, no binary parser root | `cli` | 0 / 6 / 47 / 2 | 164 / 5 / 0 | 51 |

The artifact indexes every parser-derived type, argument-group type,
subcommand enum, command variant, and value enum. Exact source hashes make all
fields, doc comments, positional declarations, defaults, short forms, value
parsers, delimiters, actions, and other clap attributes part of the frozen
snapshot.

The field-level state is `COMPLETE_6_OF_6_PRIMARY_SOURCES`. The normalization
cohort covers all 490 `#[arg]` attributes across the six primary sources plus
37 implicit positionals: 25 in `asupersync`, ten in standalone `atp`, and two
identity paths in `atpd`. Eleven `asupersync` fields and five detached-tree
fields marked only with `#[command(flatten/subcommand)]` are parser plumbing,
not arguments, and are therefore excluded from the 527 field rows. Complete
here means complete static field normalization for the six pinned sources; it
does not mean complete byte captures, parser execution, or binary reachability.

There are 159 indexed command variants across the six files. Only 108 belong
to binary-root command trees. The remaining 51 are the detached shared ATP
tree.

Adjacent fingerprints cover `Cargo.toml`, `src/lib.rs`, `src/cli/output.rs`,
`src/cli/exit.rs`, `src/cli/atp_config.rs`, `src/cli/mod.rs`, and
`src/cli/atp_workflows.rs`, because feature admission, format/color policy,
exit behavior, configuration precedence, exports, and detached-tree consumers
cannot be interpreted from the six parser files alone.

## Reachable binary trees

### `asupersync`

The root has five families: `atp`, `trace`, `conformance`, `lab`, and `doctor`.
Their nested command enums contain 83 variants in total. The largest families
are ATP (including pairing, inbox, directory, and ATP-trace children) and
Doctor. All are declared in the binary rather than in the exported shared ATP
tree.

Four argument groups—ATP doctor, verify, replay, and proof—come from
`src/cli/args.rs`. `CommonArgs` itself is not a clap-derived type; the binary
uses its own `CommonArgsCli` wrapper and converts it after parsing.

### `atp`

The standalone transfer binary has nine root spellings: `send`, `recv`,
`serve`, `bond-donate`, `bond-recv`, `bond-pull`, `__bond-descriptor`,
`rq-keygen`, and `__delta-state-export`. The two double-underscore commands are
hidden. `serve` is a separate command variant sharing `RecvArgs`; it is not a
clap alias declaration.

`SendArgs`, `RecvArgs`, and the four bonded-transfer argument types derive
`Parser` rather than `Args`. That distinction is source-observed and preserved
in the artifact. Together they declare 99 annotated fields and nine implicit
positionals; the hidden inline `__delta-state-export` command contributes the
tenth implicit positional, for 109 normalized standalone-ATP rows. Their
consumer classifications freeze only the parser-struct handoff to the command
dispatcher, except for the directly dispatched delta-export destination. They
do not claim independent per-field dataflow or behavior.

### `atpd`

The daemon root has `start`, `stop`, `status`, `reload`, `init`, `diagnostics`,
and `identity`; identity adds `show`, `generate`, `import`, and `export`.
Platform-specific functions provide the root config, data, pid, and log-path
defaults. The parser surface exists under `atpd-daemon`; the optional `tls`
feature changes later behavior, not the presence of its QUIC-related flags.

### `offline_tuner`

The tuner has `optimize`, `candidates`, `emit-profile`, `validate`, and
`scheduler-recommend`. Its two global options are `--verbose` and
`--output-dir`. The admitted binary requires both `cli` and
`simd-intrinsics`, while architecture-specific implementation selection occurs
after parsing.

## Field-normalization cohort

The machine artifact records 527 field rows under
`COMPLETE_6_OF_6_PRIMARY_SOURCES`:

| Source | Annotated fields | Implicit positionals | Normalized rows |
|---|---:|---:|---:|
| `src/bin/asupersync.rs` | 174 | 25 | 199 |
| `src/bin/atp.rs` | 99 | 10 | 109 |
| `src/bin/atpd.rs` | 18 | 2 | 20 |
| `src/bin/offline_tuner.rs` | 15 | 0 | 15 |
| `src/cli/args.rs` | 20 | 0 | 20 |
| `src/cli/atp_command_tree.rs` | 164 | 0 | 164 |
| **Cohort total** | **490** | **37** | **527** |

Each row records a stable field ID, owner type, Rust field declaration, option
or positional shape, source attribute, explicit default, cardinality, scope,
consumer classification, and source anchors. Names copied from explicit
`long =`, `value_name =`, or short-character attributes are labeled
explicit. Names expected from a bare `long` or `short`, and implicit
positional value names, are labeled derived. Derived names are static review
expectations only; they are not accepted as rendered help, usage, or parser
byte evidence.

The cohort makes these previously compressed distinctions visible:

- `asupersync` contributes 174 annotated fields and 25 implicit positionals.
  Its eleven flatten/subcommand plumbing fields are intentionally outside the
  argument-row count.
- Root `asupersync` verbosity, quiet, debug, and config values are copied into
  `CommonArgs`, but only format, color, and the command are used by main
  dispatch; those four values are classified as
  `COPIED_TO_COMMON_ARGS_NOT_DISPATCHED`.
- `asupersync doctor recipe-list --json` is `PARSED_UNUSED_GAP`: the command
  dispatcher ignores the argument payload.
- Other `asupersync` rows classified as struct-dispatched establish only the
  source-level command handoff. They are not per-field consumer proofs.
- `atpd --foreground` is `PARSED_UNUSED_GAP`: parsing populates the field,
  but the post-parse code has no consumer.
- `atpd identity import` and `identity export` each take one required
  implicit `PathBuf` positional even though neither field has an `#[arg]`
  attribute.
- The tuner describes its three weights as `0.0-1.0`, but those fields and
  the minimum-improvement threshold have no clap range parser and no runtime
  range validation before `OptimizationCriteria` is built.
- The shared ATP verify `--min-coverage` and replay
  `--reduction-target` fields also use plain `f64` parsing, but their
  handlers do perform inclusive runtime range checks.
- Standalone `atp recv` and `atp serve` are distinct command variants that
  share `RecvArgs` and dispatch to the same handler with different persistence
  booleans; `serve` is not a clap alias.
- All six standalone ATP parser structs use the same explicit
  `parse_max_block_size_arg` parser and `MaxBlockSizeArg::Auto` default for
  `--max-block-size`.
- The standalone tree retains hidden parser surface: two legacy
  delta-sidecar flags, three auth-key-stdin flags, two double-underscore
  commands, and the delta-state-export destination positional.
- Standalone ATP rows classified as struct-dispatched establish only the
  source-level command handoff. They are not per-field consumer proofs.
- The detached tree contributes 164 annotated fields and no implicit
  positionals. Its five subcommand-plumbing fields are intentionally outside
  the argument-row count.
- Of those detached rows, 60 belong to public root command models with no
  downstream library dispatcher, while 104 belong to CI, dataset, corpus,
  release, and archive models handed to `AtpWorkflowCoordinator`.
- Both detached consumer classifications retain the
  `NO_BINARY_PARSER_ROOT` boundary. Library export or workflow dispatch is not
  evidence that a binary can parse or expose the corresponding spelling.

These observations freeze gaps; they do not authorize silently fixing them in
the inventory bead.

## Detached shared ATP tree

`src/cli/atp_command_tree.rs` is classified exactly as
`LIBRARY_EXPORTED_NO_BINARY_PARSER_ROOT`. It defines 51 variants spanning its
root plus CI, dataset, fuzz, release, and archive children, but it derives no
`Parser` root and no binary imports the module. `src/cli/atp_config.rs` and
`src/cli/atp_workflows.rs` consume its types as library models.

All 164 annotated fields are normalized in the artifact. Sixty are classified
as `DETACHED_PUBLIC_COMMAND_MODEL_NO_BINARY_PARSER_ROOT`; the other 104 are
classified as `DETACHED_LIBRARY_WORKFLOW_MODEL_NO_BINARY_PARSER_ROOT` and
anchored to their source-level workflow dispatch. These classifications freeze
model ownership only. They do not turn the detached tree into a reachable CLI.

This matters in both directions:

- A future refactor must not silently present these 51 variants as existing
  user-reachable commands.
- A library consumer may still rely on the exported types, so “unreachable from
  a binary” is not permission to delete or rename them.

## Width, environment, configuration, and exit boundaries

The static source establishes these boundaries:

- `clap` enables only `derive`; `wrap_help` is absent. A replacement must not
  invent terminal-width-sensitive behavior before byte captures establish the
  incumbent output. The future matrix includes `COLUMNS` unset, 40, and 120 so
  this assumption is checked rather than merely repeated.
- The clap `env` feature is absent and all six files contain zero
  `#[arg(env = ...)]` bindings. Environment behavior is hand-written.
- For `asupersync`, explicit format/color flags bypass auto detection. Auto
  format consults `CI` and then `ASUPERSYNC_OUTPUT_FORMAT`; auto color consults
  `NO_COLOR`, then `CLICOLOR_FORCE`, then terminal state.
- Root-level `asupersync` verbosity, quiet, debug, and config values are parsed
  and copied into `CommonArgs`, but the current main path consumes only the
  effective format and color before dispatch. None of those four root values
  reaches `run`. This is a frozen gap, not an invitation to assign new
  semantics in the inventory bead.
- Standalone `atp` reads `ATP_RQ_AUTH_KEY_HEX`, `SSL_CERT_FILE`,
  `SSL_CERT_DIR`, and `HOME` outside clap. It does not consume the detached
  ATP configuration manager.
- `atpd --config` selects a TOML path. Its optional or true `start` flags
  overlay loaded configuration; missing or unreadable configuration currently
  falls back to defaults with a warning. `PROGRAMDATA` affects Windows default
  paths, while diagnostics consults `HOSTNAME` and then `COMPUTERNAME`; none is
  a clap-populated value.
- `offline_tuner` initializes `env_logger` from its default environment after
  parsing, choosing a default filter from `--verbose`.
- Only `asupersync` consumes the ten-code shared semantic exit registry.
  Standalone `atp` reduces command errors to `std::process::ExitCode::FAILURE`,
  `atpd` returns `Result`, and `offline_tuner` uses exit 1 on reported errors.

These are source observations. Exact stream bytes and process statuses remain
uncaptured.

## Required byte-capture matrix

The artifact records `MISSING_EXECUTION_RECEIPTS` and zero captured byte
goldens. Source text, derive expansion knowledge, and library documentation are
not accepted as substitutes for bytes from the admitted incumbent binaries.

Each future record must carry:

- the case ID, binary, exact OS-level argv representation, feature set, target,
  terminal context, and environment allowlist;
- exact stdout and stderr bytes represented as hex;
- the process exit code and source revision.

The required classes include root `--help`, `-h`, and `--version`; help for
every reachable subcommand; minimally valid leaves; unknown root and nested
commands; unknown options; missing arguments and option values; invalid enum
and numeric values; runtime validation errors; and non-UTF-8 argv.

Each class must be checked with terminal and pipe combinations, color-control
environment cells, the three width cells, admitted feature combinations, and
the platform cells listed in the artifact. A missing or unsupported cell stays
explicitly missing; it is not green and is not silently skipped.

## Offline Tuner `env_logger` static audit

The dependent Phase-2 leaf `asupersync-d24mms.3` now has a bounded static
receipt, `CLI-OFFLINE-TUNER-ENV-LOGGER-AUDIT-V1`, inside the same artifact.
Its state is `STATIC_SOURCE_PINNED_NOT_EXECUTED`; the required black-box state
is `NO_BLACK_BOX_BASELINE_CAPTURED`. The receipt advances source and evidence
planning without treating source inspection as observable logging behavior.

A 2026-08-05 static correction reconciles the wrapper-script source pin with
the companion contract's Rust `str::lines()` semantics.
`scripts/run_offline_tuning.sh` has no final LF, so its final nonempty record is
line 248 even though newline-byte counting reports 247. Its SHA-256 and bytes
are unchanged. This measurement correction does not change `KEEP_INCUMBENT`,
provide black-box evidence, or complete the bead.

The pinned binary parses first, initializes `env_logger` from
`Env::default()`, selects only the fallback filter from `--verbose`, creates
the output directory, and then dispatches exactly one of `optimize`,
`candidates`, `emit-profile`, `validate`, or `scheduler-recommend`. Static
counts record two logger builder sites, two environment lookups, 39 stdout
print sites, two stderr print sites, two explicit exit-1 sites, five file-write
sites, two file-read sites, and two wall-clock artifact fields. The binary and
its directly invoked tuner module contain zero direct `log` or `tracing` call
tokens. That zero is deliberately not promoted to a behavior claim: a built
command may reach dependency logging that source-local scanning cannot see.

The nominal future baseline has 30 cells: five commands multiplied by default
versus `--verbose` and by `RUST_LOG` unset, `off`, or `trace`. It must also
cover successful execution, argument or validation failures, input/output
failures, the invoked optimization benchmark path, and either a safe panic
capture or an owner-approved receipt that no safe user-reachable panic cell
exists. Every case must retain exact stdout and stderr bytes, exit code,
environment allowlist, feature/host/source identity, generated artifact paths
and hashes, structured harness NDJSON, a redaction result, and a deterministic
replay command. Missing, skipped, unsupported, unredacted, or non-replayable
cells are not parity evidence.

All seven cutover rows are therefore `MISSING`: all-command baseline, filter
parity, stream/exit parity, artifact/replay parity, redaction parity, focused
replacement unit evidence, and serialized dependency-ledger cutover. The
result is `KEEP_INCUMBENT` with `dependency_exit_allowed=false`. No manifest,
lockfile, dependency, logger, source behavior, or tracker state changed, and
this partial receipt does not claim completion of `asupersync-d24mms.3`.

## Static contract

`tests/cli_clap_surface_inventory_contract.rs` is authored to verify source
fingerprints, line counts, declaration and attribute counts, indexed command
variants, the 527-row complete static field-normalization cohort,
feature/environment/config/exit boundary markers, documentation markers, and
the empty fail-closed golden state.

In this safety lane the contract was not executed. Validation was limited to
JSON parsing, hashes, textual counts, and Git whitespace checks. Consequently,
the contract's presence is not a passing test receipt.

## No-claim boundary

This inventory contains zero captured byte goldens. No binary or parser was
executed. No compiler, test, formatter, benchmark, or remote proof lane was
run. The artifact does not prove rendered help or error stability, stdout and
stderr routing, process exit behavior, non-UTF-8 handling, platform parity,
compilation, runtime correctness, performance, release readiness, or broad
workspace health.

Field normalization covers all six primary sources, but even the 527 normalized
rows do not substitute for captured parser bytes. The detached tree still has
no binary parser root, and its 60 public-model plus 104 workflow-model rows do
not establish user reachability. The `asupersync` and standalone ATP dispatch
classifications are not independent per-field dataflow proof. The bead
therefore remains open, `clap` remains `KEEP_UNTIL_PARITY`, and no dependency
exit or parser replacement is authorized.

<!-- END CLI CLAP SURFACE INVENTORY -->
