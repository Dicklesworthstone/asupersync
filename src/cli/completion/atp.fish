# ATP Fish Completion

# Global options
complete -c atp -s h -l help -d "Show help information"
complete -c atp -s V -l version -d "Show version information"
complete -c atp -l config -d "Configuration file" -F
complete -c atp -l json -d "Output in JSON format"
complete -c atp -s v -l verbose -d "Verbose output"
complete -c atp -s q -l quiet -d "Quiet output"

# Main commands
complete -c atp -f -n "__fish_use_subcommand" -a "atp" -d "ATP protocol tooling"
complete -c atp -f -n "__fish_use_subcommand" -a "trace" -d "Trace file inspection utilities"
complete -c atp -f -n "__fish_use_subcommand" -a "conformance" -d "Conformance tooling"
complete -c atp -f -n "__fish_use_subcommand" -a "lab" -d "FrankenLab scenario testing"
complete -c atp -f -n "__fish_use_subcommand" -a "doctor" -d "Workspace diagnostics"
complete -c atp -f -n "__fish_use_subcommand" -a "help" -d "Show help for commands"

# ATP subcommands
complete -c atp -f -n "__fish_seen_subcommand_from atp" -a "doctor" -d "ATP diagnostics"
complete -c atp -f -n "__fish_seen_subcommand_from atp" -a "directory" -d "Peer directory operations"
complete -c atp -f -n "__fish_seen_subcommand_from atp" -a "verify" -d "Verify ATP proof bundle offline"
complete -c atp -f -n "__fish_seen_subcommand_from atp" -a "proof" -d "Display ATP proof bundle information"

# Directory subcommands
complete -c atp -f -n "__fish_seen_subcommand_from directory" -a "list" -d "List active peers and groups"
complete -c atp -f -n "__fish_seen_subcommand_from directory" -a "inspect" -d "Inspect one peer, device, or group"
complete -c atp -f -n "__fish_seen_subcommand_from directory" -a "rename-peer" -d "Rename a peer display name"
complete -c atp -f -n "__fish_seen_subcommand_from directory" -a "rename-device" -d "Rename a device under a peer"

# Trace subcommands
complete -c atp -f -n "__fish_seen_subcommand_from trace" -a "info" -d "Show summary information about a trace file"
complete -c atp -f -n "__fish_seen_subcommand_from trace" -a "events" -d "List trace events with optional filtering"
complete -c atp -f -n "__fish_seen_subcommand_from trace" -a "verify" -d "Verify trace file integrity"
complete -c atp -f -n "__fish_seen_subcommand_from trace" -a "diff" -d "Diff two trace files"
complete -c atp -f -n "__fish_seen_subcommand_from trace" -a "compress" -d "Rewrite a trace file with LZ4 compression"
complete -c atp -f -n "__fish_seen_subcommand_from trace" -a "export" -d "Export trace events to JSON"

# Conformance subcommands
complete -c atp -f -n "__fish_seen_subcommand_from conformance" -a "matrix" -d "Generate spec-to-test traceability matrix"

# Lab subcommands
complete -c atp -f -n "__fish_seen_subcommand_from lab" -a "run" -d "Run a FrankenLab scenario from a YAML file"
complete -c atp -f -n "__fish_seen_subcommand_from lab" -a "validate" -d "Validate a scenario YAML file without executing it"
complete -c atp -f -n "__fish_seen_subcommand_from lab" -a "replay" -d "Replay a scenario and verify determinism"
complete -c atp -f -n "__fish_seen_subcommand_from lab" -a "explore" -d "Explore multiple seeds to find violations"
complete -c atp -f -n "__fish_seen_subcommand_from lab" -a "differential" -d "Run built-in lab-vs-live differential scenario packs"

# Doctor subcommands
complete -c atp -f -n "__fish_seen_subcommand_from doctor" -a "scan-workspace" -d "Scan workspace topology"
complete -c atp -f -n "__fish_seen_subcommand_from doctor" -a "analyze-invariants" -d "Analyze runtime invariants"
complete -c atp -f -n "__fish_seen_subcommand_from doctor" -a "analyze-lock-contention" -d "Analyze lock-order and contention risk"
complete -c atp -f -n "__fish_seen_subcommand_from doctor" -a "operator-model" -d "Emit operator personas and decision loops"
complete -c atp -f -n "__fish_seen_subcommand_from doctor" -a "screen-contracts" -d "Emit screen-to-engine contract"
complete -c atp -f -n "__fish_seen_subcommand_from doctor" -a "logging-contract" -d "Emit structured logging contract"
complete -c atp -f -n "__fish_seen_subcommand_from doctor" -a "remediation-contract" -d "Emit remediation recipe DSL contract"
complete -c atp -f -n "__fish_seen_subcommand_from doctor" -a "report-contract" -d "Emit core diagnostics report contract"

# File completions for certain commands
complete -c atp -n "__fish_seen_subcommand_from verify proof" -F
complete -c atp -n "__fish_seen_subcommand_from trace" -F
complete -c atp -n "__fish_seen_subcommand_from lab; and __fish_seen_subcommand_from run validate replay explore" -F