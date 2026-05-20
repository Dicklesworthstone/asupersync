#compdef atp

# ATP Zsh Completion
# Place this file in a directory in your fpath with the name _atp

_atp() {
    local context state line
    typeset -A opt_args

    _arguments -C \
        '(-h --help)'{-h,--help}'[Show help information]' \
        '(-V --version)'{-V,--version}'[Show version information]' \
        '--config[Configuration file]:file:_files' \
        '--json[Output in JSON format]' \
        '(-v --verbose)'{-v,--verbose}'[Verbose output]' \
        '(-q --quiet)'{-q,--quiet}'[Quiet output]' \
        '1: :_atp_commands' \
        '*: :_atp_subcommand_args' && return 0
}

_atp_commands() {
    local commands; commands=(
        'atp:ATP protocol tooling'
        'trace:Trace file inspection utilities'
        'conformance:Conformance tooling'
        'lab:FrankenLab scenario testing'
        'doctor:Workspace diagnostics'
        'help:Show help for commands'
    )
    _describe 'command' commands
}

_atp_subcommand_args() {
    case $words[2] in
        atp)
            local atp_commands; atp_commands=(
                'doctor:ATP diagnostics'
                'directory:Peer directory operations'
                'verify:Verify ATP proof bundle offline'
                'proof:Display ATP proof bundle information'
            )
            _describe 'atp command' atp_commands
            ;;
        trace)
            local trace_commands; trace_commands=(
                'info:Show summary information about a trace file'
                'events:List trace events with optional filtering'
                'verify:Verify trace file integrity'
                'diff:Diff two trace files'
                'compress:Rewrite a trace file with LZ4 compression'
                'export:Export trace events to JSON'
            )
            _describe 'trace command' trace_commands
            ;;
        conformance)
            local conformance_commands; conformance_commands=(
                'matrix:Generate spec-to-test traceability matrix'
            )
            _describe 'conformance command' conformance_commands
            ;;
        lab)
            local lab_commands; lab_commands=(
                'run:Run a FrankenLab scenario from a YAML file'
                'validate:Validate a scenario YAML file without executing it'
                'replay:Replay a scenario and verify determinism'
                'explore:Explore multiple seeds to find violations'
                'differential:Run built-in lab-vs-live differential scenario packs'
            )
            _describe 'lab command' lab_commands
            ;;
        doctor)
            local doctor_commands; doctor_commands=(
                'scan-workspace:Scan workspace topology'
                'analyze-invariants:Analyze runtime invariants'
                'analyze-lock-contention:Analyze lock-order and contention risk'
                'operator-model:Emit operator personas and decision loops'
                'screen-contracts:Emit screen-to-engine contract'
                'logging-contract:Emit structured logging contract'
                'remediation-contract:Emit remediation recipe DSL contract'
                'report-contract:Emit core diagnostics report contract'
            )
            _describe 'doctor command' doctor_commands
            ;;
    esac
}

_atp "$@"