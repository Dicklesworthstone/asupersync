# ATP CLI Command Architecture (ATP-I1)

This document defines the complete ATP CLI command architecture for asupersync-swezeg (ATP-I1), providing comprehensive data movement tools that are easy by default and deeply explainable when asked.

## Command Tree

The ATP CLI provides a comprehensive set of commands for all ATP operations:

```
asupersync atp <command> [args]
  send        Send files/directories with automatic chunking and repair
  get         Receive and restore files from ATP transfers  
  sync        Bidirectional sync with conflict resolution
  local-sync  Preview/apply persistent sync between two local directories (Linux/glibc)
  mirror      One-way mirror with automatic cleanup
  local-mirror Preview/apply an authoritative local mirror with retained originals (Linux/glibc)
  local-recover Review/restore retained originals from saved local application receipts (Linux/glibc)
  share       Create shareable links with access control
  watch       Watch directories for changes and auto-sync
  serve       Start ATP daemon/server mode
  inbox       Manage transfer inbox and notifications
  resume      Resume interrupted transfers
  cancel      Cancel active transfers
  status      Show transfer status and progress
  bench       Benchmark ATP performance
  doctor      ATP diagnostics and health checks
  verify      Verify ATP proof bundles offline
  proof       Display ATP proof bundle information
  config      Configure ATP profiles and settings
```

## Configuration Profiles

ATP provides 10 optimized profiles for different use cases:

| Profile | Description | Use Case |
|---------|-------------|----------|
| `bulk-file` | Large fixed chunks for maximum throughput | Bulk transfers of large files |
| `sync-tree` | Content-defined chunking optimized for dedupe | Source tree synchronization |
| `media` | Prefix-friendly chunking for streaming | Media files and progressive delivery |
| `sparse-image` | Hole-aware chunking | VM images and sparse files |
| `artifact` | Reproducible chunking for proof strength | Build artifacts and reproducible transfers |
| `stream` | Rolling manifest chunking | Real-time streaming scenarios |
| `clean-lan` | LAN-optimized with clean connections | High-speed local network |
| `lossy-wifi` | WiFi-optimized tolerating packet loss | Wireless and mobile networks |
| `relay-only` | NAT traversal via relay servers | Restricted network environments |
| `auto` | Automatic selection based on conditions | Default adaptive behavior |

## Configuration Precedence

Configuration follows a strict precedence hierarchy:

1. **CLI flags** (highest precedence) - `--profile`, `--chunk-size`, etc.
2. **Local config** - `.atp.toml` in current directory
3. **User config** - `~/.config/asupersync/atp.toml` (Unix) or `%APPDATA%\Asupersync\atp.toml` (Windows)
4. **Daemon policy** - System-wide policy configuration
5. **Defaults** (lowest precedence) - Built-in sensible defaults

### Configuration File Format

```toml
# Example .atp.toml
profile = "sync-tree"
chunk_size = 1048576  # 1MB chunks
max_concurrent = 8
timeout = 600
compression = true
encryption = true
repair_overhead = 0.15
interface = "eth0"
relay_server = "relay.example.com"
tailscale = "auto" # "auto", "prefer", or "disabled"
verbose = false
```

### Configuration Management

```bash
# Show current configuration
asupersync atp config --show

# Set configuration values
asupersync atp config --set profile=artifact --set chunk_size=2097152

# Unset configuration values  
asupersync atp config --unset relay_server

# List available profiles
asupersync atp config --list-profiles

# Set user-level configuration
asupersync atp config --set profile=bulk-file --scope=user

# Set local project configuration
asupersync atp config --set profile=sync-tree --scope=local
```

## JSON Output Contracts

All ATP commands support JSON output for machine parsing. Output format is automatically detected:

- **Human format**: Interactive terminals
- **JSON format**: CI environments, pipes, `--format=json`

### Key JSON Schemas

1. **Status Output** (`schemas/atp_status_output.json`)
   - Transfer summaries and individual status
   - System resource usage
   - Performance metrics

2. **Progress Output** (`schemas/atp_progress_output.json`)
   - Real-time transfer progress
   - Current file and phase information
   - Network and repair metrics

3. **Benchmark Output** (`schemas/atp_bench_output.json`)
   - Performance test results
   - System information
   - Statistical summaries

4. **Proof Output** (`schemas/atp_proof_output.json`)
   - Proof bundle information
   - Manifest and repair details
   - Verification status

5. **Path Doctor Output** (`schemas/atp_path_doctor_output.json`)
   - Network interface diagnostics
   - Connectivity test results
   - NAT traversal and bandwidth tests

## Example Usage

### Persistent local synchronization

`asupersync atp local-sync` exposes the maintained native directory reconciliation
engine through the `cli` feature. Both arguments are local filesystem directories;
the existing peer-address `atp sync` and `atp mirror` execution paths still return
their compatibility refusal. This command does not contact a daemon or remote peer.

Use existing, absolute UTF-8 paths without symlink components. The private state
directory must be empty for initialization, have mode `0700`, and belong to the
effective user and group. State and staging must be outside both trees and each
other. Staging must share the trees' filesystem, belong to the effective user,
and not be writable by group or others. The caller must exclusively own both trees
during a command. No directories are created implicitly for these arguments.

```bash
# Create history explicitly and inspect the initial three-way plan.
# /work/left, /work/right, /work/sync-state and /work/sync-staging already exist.
asupersync --format json atp local-sync /work/left /work/right \
  --state-dir /work/sync-state --initialize

# Reopen the saved history and preview the current changes without applying them.
asupersync --format json atp local-sync /work/left /work/right \
  --state-dir /work/sync-state

# Apply non-destructive additions in both directions and persist convergence.
asupersync --format json atp local-sync /work/left /work/right \
  --state-dir /work/sync-state --apply --staging-dir /work/sync-staging

# After reviewing the changes, explicitly authorize replacements and deletions.
asupersync --format json atp local-sync /work/left /work/right \
  --state-dir /work/sync-state --apply --staging-dir /work/sync-staging \
  --allow-overwrite --allow-permission-change --allow-delete
```

Initialization records no prior common history. Different existing versions of
the same file conflict; timestamps never pick a winner. Successful application
verifies both resulting inventories and publishes the next durable baseline,
which later invocations use to distinguish one-sided changes from concurrent
edits. A conflict blocks the entire application. Failed reopen never falls back
to initialization. Preview may confirm the durability of existing state files
while holding their writer lease; it does not apply changes to the two trees.

Each `--apply` prepares current inventories and revalidates them before effects.
The `plan_id` identifies that invocation and its retained recovery job; it is not
a reusable approval token from an earlier preview. Overwrite requires both
`--allow-overwrite` and `--allow-permission-change`; deletion requires its separate
`--allow-delete` grant. Originals are moved into quarantine, never unlinked by
this command. There is no whole-tree transaction or automatic recovery cleanup.

The content-only profile copies ordinary file contents and directory structure.
It does not preserve source permissions, timestamps, symlinks, hard-link topology,
sparse layout or platform metadata. Unsupported inputs are refused. New files
use `0600` and new directories `0700`. Inventory bounds are configurable with
`--max-entries`, `--max-depth`, `--max-file-bytes`, `--max-total-bytes` and
`--max-state-bytes`.

JSON output uses `schema_version: 1` and `command: "atp.local-sync"`. `decisions`
contains each actual path/action and its baseline/local/remote observations.
Application output preserves `result.actions`, including each action's last
state, bytes written, durability, `staged_path` and `quarantine_path`.
`result.complete` describes tree convergence; `result.publication` and
`result.persistence_failure` separately describe durable history. Partial or
non-durable application emits its receipt before a nonzero exit. An outer failure
without an observed application receipt leaves `result` null and fills
`application_error`; reopen history and inspect staging before another attempt.

### Reviewed local mirroring

`asupersync atp local-mirror SOURCE DESTINATION` exposes the native one-way
directory mirror through the `cli` feature on Linux/glibc. The source is
authoritative: additions and changed files are proposed for the destination,
and destination-only entries are proposed for removal into quarantine. No
destination-only content is copied back to the source. This command operates on
two local directories and does not use persistent synchronization history or a
daemon. The existing peer-address `atp mirror` execution path remains unavailable.

The default invocation scans both actual trees and prints a plan without changing
their contents. Inspect every `decisions` entry and the printed `review_id`.
Applying requires that exact ID in `--apply REVIEW_ID`, plus an existing external
`--staging-dir`. The command scans again and refuses a different content/root
identity before application, returning the newly observed plan for review.
Native object guards are revalidated again before filesystem effects.

```bash
# Both trees and /work/mirror-staging already exist.
# Preview the complete plan and inspect its review_id and proposed actions.
asupersync --format json atp local-mirror /work/source /work/destination

# Replace REVIEW_ID with the exact 64-character lowercase hexadecimal review_id.
# Include only the grants required by the changes you reviewed.
# Keep the receipt outside both trees so saving it does not change the plan.
asupersync --format json atp local-mirror /work/source /work/destination \
  --apply REVIEW_ID --staging-dir /work/mirror-staging \
  --allow-overwrite --allow-permission-change --allow-delete \
  > /work/mirror-receipt.json
```

Authorization is checked for the entire plan before the first effect. New files
and directories require no destructive grants. Existing regular-file replacement
requires **both** `--allow-overwrite` and `--allow-permission-change`.
Destination-only files and directories require `--allow-delete`. Supplying one
grant never implies another, and these grants require `--apply`. Without all
required grants, even unrelated additions in the same plan remain unstarted.

Use existing absolute UTF-8 paths without symlink components, and exclusively own
both trees during each command. The roots must not overlap. Staging must be outside
both roots, on the same filesystem as both, owned by the effective user, and not
writable by group or others. Staging must have no visible extended attributes.
A private mode-`0700` staging directory is suitable; the command
does not create this supplied directory automatically.

The content profile copies ordinary file bytes and directory structure. New files
use `0600`, and new directories use `0700`. Ordinary destination mode and ownership
are preserved during supported overwrites; source permissions and timestamps are
not copied. Replacements with special mode bits, different ownership, or visible
extended attributes are refused; replacement targets must belong to the effective
user and group. The permission-change grant acknowledges that
hidden platform metadata cannot be guaranteed; it does not waive these refusals.
Symlinks, multiply linked files, unsupported object kinds, and file/directory kind
replacement are refused. Source hard-link topology, sparse layout, and platform
metadata are not preserved. Inventory bounds use `--max-entries`, `--max-depth`,
`--max-file-bytes`, and `--max-total-bytes`.

`review_id` identifies the deterministic content/root plan. `plan_id` identifies
this particular execution attempt and its retained staging job; different
invocations receive different attempt IDs. An explicitly restored destination can
therefore be mirrored again without reusing or removing an earlier recovery job.
The mirror never unlinks originals or automatically cleans staging. Overwritten
files and removed entries are retained at their reported `quarantine_path`;
removed subtrees have separate retained entries for their directories and files.
There is no whole-tree transaction or automatic rollback. A failed operation may
have completed earlier actions, and those effects remain in its receipt.

JSON output has `schema_version: 1` and `command: "atp.local-mirror"`. A preview
has `result: null`. Application reports `result.complete`, `result.dry_run`,
`result.failure`, `result.staging_directory`, and every action's state, byte count,
durability, `staged_path`, and `quarantine_path`. `result.recovery_source` preserves
the original action indices and canonical quarantine associations for fresh native
recovery preparation; it is diagnostic input, not authenticated content or a grant
of restoration authority. Retain the complete application receipt and staging data.

A rejected review leaves `result` null and explains the mismatch in
`application_error`. An application that returns partial or failed effects emits
its receipt before a nonzero exit. `runtime_quiescent` and `runtime_stopped` report
cleanup, and unconfirmed cleanup prevents success. If writing or flushing stdout
fails after application, the structured stderr error retains the full observed
report in `context.receipt`. That output error does not roll back filesystem
effects; inspect the receipt and retained originals before another attempt.

### Restoring retained originals

`asupersync atp local-recover RECEIPT LOCAL REMOTE` previews or applies restoration
from an earlier `local-sync` or `local-mirror` application on Linux/glibc. Supply
the original roots explicitly and in their original order: for a mirror, `LOCAL`
is its source and `REMOTE` is its destination. Keep the receipt, the retained
staging job, and both roots available. No new staging directory is created.

The default command reads the saved associations and scans the actual retained
originals and current destinations without changing their contents. Inspect every
`entries` item, including its `quarantined` and `current` content identities, and
the new recovery `review_id`. A saved receipt supplies neither authenticated
historical contents nor overwrite authority. Applying requires the recovery
review ID, not the earlier mirror's review ID or the operation's `plan_id`.
Fresh preparation binds the selected associations, root identities, retained
contents, and current trees; changes require another review before application.
The native engine revalidates its captured objects before filesystem effects.

```bash
# Review actual retained originals and current destinations.
asupersync --format json atp local-recover \
  /work/mirror-receipt.json /work/source /work/destination

# Replace RECOVERY_REVIEW_ID with the exact review_id from that recovery preview.
# Both grants below are needed if any existing regular file will be exchanged.
asupersync --format json atp local-recover \
  /work/mirror-receipt.json /work/source /work/destination \
  --apply RECOVERY_REVIEW_ID --allow-overwrite --allow-permission-change \
  > /work/recovery-receipt.json
```

Keep both receipts and any preview output outside both roots and the recovery job;
writing output into a scanned tree changes the next review. The receipt must be a
regular file; symlinks at its final path entry, FIFOs, devices, and directories are
refused before reading. Its parent directories remain caller-trusted. Use absolute
UTF-8 paths and exclusively own both roots and the recovery job throughout each command.
The roots and job must be disjoint and on one filesystem. The recovery job must
retain private `0700` permissions and effective-user/group ownership. Native
path, object-kind, ownership, mode, and visible-metadata refusals still apply.
Inventory bounds use the same `--max-entries`, `--max-depth`, `--max-file-bytes`,
and `--max-total-bytes` flags as local mirroring.

Accepted JSON inputs are:

- A complete saved `local-sync` or `local-mirror` application report, with
  `schema_version: 1`, its exact command name, `mode: "apply"`, and
  `content_profile: "linux-gnu-content-only-v1"`. Partial application reports
  are accepted; they need not claim successful completion or durable publication.
- A standalone `NativeDirectoryRecoverySource` object, such as the entire
  `result.recovery_source` extracted from a mirror report. Preserve every action
  and its original index, including actions without a quarantine path.
- A structured `output_error` whose `context.receipt` is one of those complete
  local application reports, as emitted when the original stdout write fails.

Preview reports, recovery-command reports, nested error envelopes, and isolated
`result` objects are not recovery inputs. If a full application report contains
`result.recovery_source`, it must agree exactly with the report's plan ID,
dry-run status, staging directory, and actions. The reader bounds actual input
bytes before decoding: `--max-receipt-bytes` defaults to 16 MiB and accepts
1 through 64 MiB. Ambiguous or malformed associations are refused before effects.

An absent destination is restored by renaming its retained original into place.
An existing regular file requires **both** `--allow-overwrite` and
`--allow-permission-change`; the engine atomically exchanges it with the retained
original. The displaced current bytes remain at the action's `quarantine_path`.
All required grants are checked before the first restoration, and grants require
`--apply`. There is no delete grant for this command: recovery does not unlink
files. Existing-directory and file/directory kind replacements are refused.
Recovered directories precede their recovered descendants.

Only retained originals are restored. Files newly added by the earlier operation
remain in place, persistent local-sync history is not rewound, and staging is not
automatically cleaned. Review a new synchronization plan before later syncing a
restored tree. Recovery is not a whole-tree rollback or an unattended crash-replay
operation; a later failure can leave earlier restorations completed.

JSON output uses `command: "atp.local-recover"` and records `source_plan_id`,
the fresh `review_id`, scanned `entries`, and the retained `recovery_directory`.
Application reports every action as `not_started`, `restored`, or `exchanged`,
with its destination, quarantine path, and durability. A stale review returns
the newly observed preview with `result: null` and `application_error`, then
exits nonzero. Partial application emits its observed receipt before a nonzero
exit. Check `result.complete`, `result.failure`, `runtime_quiescent`, and
`runtime_stopped`; unconfirmed cleanup prevents success. If writing or flushing
stdout fails after effects, the structured stderr error preserves the full
recovery report in `context.receipt`. Retain this report alongside the original
application receipt and the remaining recovery data.

### Basic Transfer Commands

```bash
# Send a directory with automatic profile selection
asupersync atp send /home/user/documents/ peer123

# Send with rsync-like SSH bootstrap syntax. SSH authenticates, starts the
# remote receiver, and passes a generated RQ symbol-auth key; ATP still moves
# bulk bytes over the selected ATP transport.
atp send /home/user/documents/ user@host:/srv/inbox --transport rq

# Prefer a Tailscale data endpoint when the remote host reports one, while
# falling back to the SSH host/public address if Tailscale is unavailable.
atp send /home/user/documents/ user@host:/srv/inbox --transport rq --prefer tailscale

# Direct host:port RQ requires an explicit shared symbol-auth key.
KEY=$(atp rq-keygen)
atp recv /srv/inbox --listen 0.0.0.0:8472 --transport rq --rq-auth-key-hex "$KEY"
atp send /home/user/documents/ host:8472 --transport rq --rq-auth-key-hex "$KEY"

# Send with specific profile and progress
asupersync atp send /project/ peer456 --profile=sync-tree --progress

# Receive with verification
asupersync atp get transfer789 /destination/ --verify --progress

# Bidirectional sync with conflict resolution
asupersync atp sync /local/repo/ peer123:/remote/repo/ --conflict=latest

# Mirror with cleanup
asupersync atp mirror /source/ peer123:/backup/ --delete --dry-run
```

### Status and Monitoring

```bash
# Show all transfer status
asupersync atp status

# Show detailed status in JSON
asupersync atp status --detailed --format=json

# Monitor active transfers
asupersync atp status --active --watch --interval=2

# Filter by transfer pattern
asupersync atp status --filter="backup*"
```

### Benchmarking and Diagnostics

```bash
# Benchmark different profiles
asupersync atp bench --profile=bulk-file --size=1G --iterations=5

# Network benchmark with peer
asupersync atp bench --peer=peer123 --detailed

# Path diagnostics
asupersync atp doctor --platform

# Network path analysis
asupersync atp doctor --path --target=peer123

# Prefer a Tailscale candidate when the optional provider yields one
asupersync atp doctor --path --target=peer123 --prefer tailscale

# Disable Tailscale candidate use without disabling direct, NAT, relay, or mailbox paths
asupersync atp doctor --path --target=peer123 --no-tailscale
```

### Tailscale Candidate Policy

Tailscale is an optional ATP path-candidate source, not an ATP dependency. The
`tailscale-path-provider` Cargo feature reserves the integration surface without
pulling in a Tailscale crate or requiring `tailscaled` at build time. Runtime
provider output is converted into ordinary path candidates by
`src/net/atp/path/mod.rs`; ATP still runs native ATP/QUIC over the selected
Tailscale IP or MagicDNS address.

`--prefer tailscale` maps to the provider preference that ranks Tailscale ahead
of other non-relay candidates when provider output is available. `--no-tailscale`
maps to the disabled policy and ignores provider output while leaving direct
UDP, public IPv6, NAT traversal, relay, and mailbox candidates in the normal
path race. Provider failures are non-fatal path caveats and must not block other
candidate sources.

### SSH Bootstrap Policy

SSH is a bootstrap and identity channel, not the normal ATP bulk-data plane.
The rsync-like target syntax `user@host:/path` means:

1. open an SSH control connection to `user@host`;
2. start the remote `atp recv /path --once` command with the selected ATP
   transport, generating and passing a per-transfer RQ symbol-auth key when
   `--transport rq` is used and no explicit key was supplied;
3. discover the best reachable ATP data endpoint, preferring an explicit
   `--data-host` first, then a Tailscale address when `--prefer tailscale` is
   set, then the SSH host address;
4. move bytes over the selected ATP transport, with SHA-256 and Merkle receipt
   verification exactly as direct `host:port` transfers do.

This keeps rsync ergonomics without forcing ATP into a single SSH stream. A
future `--data-plane ssh` fallback may be useful for hostile networks, but it is
a fallback mode and must be reported separately in benchmark results. Today
`--transport rq` means RaptorQ over UDP with a TCP control plane; the native
QUIC lane should replace the data/control split without changing the SSH
bootstrap contract.

Direct `host:port` RQ transfers do not have an SSH bootstrap channel, so they
fail closed unless both sides receive the same 32-byte key via
`--rq-auth-key-hex` or `ATP_RQ_AUTH_KEY_HEX`. `--rq-allow-unauthenticated-lab`
is reserved for loopback/lab-only runs and must not be used for open-internet
benchmarks.

### Configuration Examples

```bash
# Set up sync-tree profile for development
asupersync atp config --set profile=sync-tree --set repair_overhead=0.1

# Configure for low-bandwidth environment
asupersync atp config --set profile=lossy-wifi --set compression=true

# Set up dedicated interface
asupersync atp config --set interface=eth1 --set max_concurrent=2
```

## UX Design Principles

### Easy by Default

- **Auto-detection**: Profile, output format, network interface
- **Sensible defaults**: Compression enabled, repair symbols at 20%
- **Progress indication**: Automatic in interactive terminals
- **Error recovery**: Automatic resume for interrupted transfers

### Deeply Explainable

- **Verbose mode**: `--verbose` shows detailed operation logs
- **JSON output**: Machine-readable for scripting and monitoring
- **Proof bundles**: Cryptographic verification of all transfers
- **Doctor commands**: Comprehensive network and system diagnostics

### Machine-Friendly

- **Exit codes**: Standard codes for automation (0=success, 1=user error, 2=system error)
- **JSON schemas**: Structured output with versioning
- **CI detection**: Automatic JSON mode in CI environments
- **No TTY assumptions**: Works in scripts and automation

## Implementation Status

✅ **Complete (ATP-I1)**:
- Command tree architecture defined
- Configuration precedence system
- JSON output schemas  
- Profile system with 10 profiles
- Documentation and examples

🚧 **Future (ATP-I2)**:
- Command implementations
- Network protocol integration
- Proof bundle generation
- Real-time progress reporting

## File Structure

```
src/cli/
├── atp_command_tree.rs      # Command definitions and argument parsing
├── atp_config.rs            # Configuration management with precedence
├── mod.rs                   # CLI module exports
└── ...

schemas/
├── atp_status_output.json   # Status command JSON schema
├── atp_progress_output.json # Progress reporting JSON schema  
├── atp_bench_output.json    # Benchmark results JSON schema
├── atp_proof_output.json    # Proof bundle JSON schema
└── atp_path_doctor_output.json # Path diagnostics JSON schema

docs/
└── atp_cli_architecture.md  # This document
```

## Dependencies

ATP-I1 provides the architecture for ATP-I2 implementation, which depends on:

- Protocol and object model (ATP-B4)
- Manifest and chunking systems (ATP-C6, ATP-G2)  
- Path establishment and repair (ATP-G series)
- Proof and verification systems

The CLI architecture is designed to be implementation-agnostic, allowing the core ATP functionality to be developed independently while maintaining a consistent user experience.
