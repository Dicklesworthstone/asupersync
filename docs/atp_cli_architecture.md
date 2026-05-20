# ATP CLI Command Architecture (ATP-I1)

This document defines the complete ATP CLI command architecture for asupersync-swezeg (ATP-I1), providing comprehensive data movement tools that are easy by default and deeply explainable when asked.

## Command Tree

The ATP CLI provides a comprehensive set of commands for all ATP operations:

```
asupersync atp <command> [args]
  send        Send files/directories with automatic chunking and repair
  get         Receive and restore files from ATP transfers  
  sync        Bidirectional sync with conflict resolution
  mirror      One-way mirror with automatic cleanup
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

### Basic Transfer Commands

```bash
# Send a directory with automatic profile selection
asupersync atp send /home/user/documents/ peer123

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
