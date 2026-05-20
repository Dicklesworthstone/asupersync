#!/bin/bash
# Generate Deterministic Replay Artifacts for ATP Test Failures
# Creates comprehensive replay artifacts for nontrivial test failures

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

usage() {
    echo "Usage: $0 [OPTIONS] FAILURE_TYPE TEST_COMMAND"
    echo ""
    echo "Generate deterministic replay artifacts for test failures."
    echo ""
    echo "FAILURE_TYPE:"
    echo "  proof-lane    Proof lane execution failure"
    echo "  integration   Integration test failure"
    echo "  lab-scenario  Lab scenario execution failure"
    echo "  benchmark     Performance benchmark failure"
    echo ""
    echo "Options:"
    echo "  -o OUTPUT_DIR Directory to store replay artifacts (default: artifacts/replays/)"
    echo "  -t TAG        Tag for this replay session (default: auto-generated)"
    echo "  -e ENV_VARS   Additional environment variables to capture"
    echo "  -h            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 proof-lane 'cargo test --test quic_conformance'"
    echo "  $0 integration 'cargo test test_transfer_resume'"
    echo "  $0 lab-scenario './lab_runner scenario_crash_recovery.yaml'"
}

# Default values
OUTPUT_DIR="${PROJECT_ROOT}/artifacts/replays"
TAG=""
EXTRA_ENV_VARS=""
FAILURE_TYPE=""
TEST_COMMAND=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -e|--env-vars)
            EXTRA_ENV_VARS="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "Unknown option $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            if [[ -z "$FAILURE_TYPE" ]]; then
                FAILURE_TYPE="$1"
            elif [[ -z "$TEST_COMMAND" ]]; then
                TEST_COMMAND="$1"
            else
                echo "Too many arguments" >&2
                usage >&2
                exit 1
            fi
            shift
            ;;
    esac
done

# Validate required arguments
if [[ -z "$FAILURE_TYPE" ]] || [[ -z "$TEST_COMMAND" ]]; then
    echo "Error: FAILURE_TYPE and TEST_COMMAND are required" >&2
    usage >&2
    exit 1
fi

# Generate session tag if not provided
if [[ -z "$TAG" ]]; then
    TAG="${FAILURE_TYPE}_$(date +%Y%m%d_%H%M%S)_$$"
fi

# Create output directory
REPLAY_DIR="${OUTPUT_DIR}/${TAG}"
mkdir -p "$REPLAY_DIR"

echo -e "${BLUE}Generating replay artifacts for failure: $FAILURE_TYPE${NC}"
echo -e "${BLUE}Test command: $TEST_COMMAND${NC}"
echo -e "${BLUE}Output directory: $REPLAY_DIR${NC}"

# Function to log steps
log_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

# Capture system environment
capture_system_environment() {
    log_step "Capturing system environment..."

    cat > "$REPLAY_DIR/system_environment.json" << EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "hostname": "$(hostname)",
    "platform": {
        "os": "$(uname -s)",
        "release": "$(uname -r)",
        "architecture": "$(uname -m)",
        "platform_details": "$(uname -a)"
    },
    "hardware": {
        "cpu_info": "$(cat /proc/cpuinfo 2>/dev/null | head -20 || sysctl -n machdep.cpu.brand_string 2>/dev/null || echo 'N/A')",
        "memory_info": "$(free -h 2>/dev/null || vm_stat 2>/dev/null || echo 'N/A')",
        "disk_info": "$(df -h 2>/dev/null || echo 'N/A')"
    },
    "software": {
        "rustc_version": "$(rustc --version 2>/dev/null || echo 'N/A')",
        "cargo_version": "$(cargo --version 2>/dev/null || echo 'N/A')",
        "git_version": "$(git --version 2>/dev/null || echo 'N/A')",
        "shell": "$SHELL"
    }
}
EOF
}

# Capture environment variables
capture_environment_variables() {
    log_step "Capturing environment variables..."

    # Core environment variables
    local core_vars=(
        "PATH" "CARGO_TARGET_DIR" "RUSTFLAGS" "RUST_BACKTRACE"
        "CARGO_HOME" "RUSTUP_HOME" "PWD" "USER" "HOME"
    )

    # Add extra environment variables if specified
    if [[ -n "$EXTRA_ENV_VARS" ]]; then
        IFS=',' read -ra extra_array <<< "$EXTRA_ENV_VARS"
        core_vars+=("${extra_array[@]}")
    fi

    {
        echo "{"
        echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
        echo "  \"environment_variables\": {"

        local first=true
        for var in "${core_vars[@]}"; do
            if [[ -n "${!var:-}" ]]; then
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo ","
                fi
                echo -n "    \"$var\": \"${!var}\""
            fi
        done
        echo ""
        echo "  }"
        echo "}"
    } > "$REPLAY_DIR/environment_variables.json"
}

# Capture git state
capture_git_state() {
    log_step "Capturing git repository state..."

    cd "$PROJECT_ROOT"

    cat > "$REPLAY_DIR/git_state.json" << EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "repository": {
        "commit_hash": "$(git rev-parse HEAD)",
        "branch": "$(git branch --show-current)",
        "remote_url": "$(git remote get-url origin 2>/dev/null || echo 'N/A')",
        "status": "$(git status --porcelain)",
        "last_commit": {
            "hash": "$(git log -1 --format='%H')",
            "author": "$(git log -1 --format='%an <%ae>')",
            "date": "$(git log -1 --format='%ai')",
            "message": "$(git log -1 --format='%s')"
        }
    }
}
EOF

    # Capture diff if there are uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        git diff > "$REPLAY_DIR/uncommitted_changes.diff"
        git diff --cached > "$REPLAY_DIR/staged_changes.diff"
    fi
}

# Capture Cargo configuration
capture_cargo_config() {
    log_step "Capturing Cargo configuration..."

    cd "$PROJECT_ROOT"

    # Capture Cargo.toml and Cargo.lock
    cp Cargo.toml "$REPLAY_DIR/"
    if [[ -f Cargo.lock ]]; then
        cp Cargo.lock "$REPLAY_DIR/"
    fi

    # Capture Cargo configuration
    if [[ -f .cargo/config.toml ]]; then
        mkdir -p "$REPLAY_DIR/.cargo"
        cp .cargo/config.toml "$REPLAY_DIR/.cargo/"
    fi

    # Generate dependency tree
    cargo tree --format "{p} {f}" > "$REPLAY_DIR/dependency_tree.txt" 2>/dev/null || echo "Failed to generate dependency tree" > "$REPLAY_DIR/dependency_tree.txt"
}

# Execute test with tracing
execute_with_tracing() {
    log_step "Executing test command with tracing..."

    cd "$PROJECT_ROOT"

    # Set up environment for detailed logging
    export RUST_BACKTRACE=full
    export RUST_LOG=debug

    # Additional tracing for different failure types
    case "$FAILURE_TYPE" in
        lab-scenario)
            export ATP_LAB_TRACE=1
            export ATP_LAB_EVIDENCE_PATH="$REPLAY_DIR/lab_evidence"
            mkdir -p "$REPLAY_DIR/lab_evidence"
            ;;
        proof-lane)
            export ATP_PROOF_TRACE=1
            export ATP_PROOF_ARTIFACTS="$REPLAY_DIR/proof_artifacts"
            mkdir -p "$REPLAY_DIR/proof_artifacts"
            ;;
        integration)
            export ATP_INTEGRATION_TRACE=1
            ;;
    esac

    # Execute test command and capture output
    local exit_code=0
    {
        echo "=== Test Execution Started at $(date) ==="
        echo "Command: $TEST_COMMAND"
        echo "Working Directory: $(pwd)"
        echo "Environment Variables:"
        env | grep -E "(RUST|CARGO|ATP)_" | sort
        echo "=== Test Output ==="

        # Execute the command
        if timeout 3600 bash -c "$TEST_COMMAND"; then
            echo "=== Test Execution Completed Successfully at $(date) ==="
        else
            exit_code=$?
            echo "=== Test Execution Failed with exit code $exit_code at $(date) ==="
        fi
    } > "$REPLAY_DIR/test_execution.log" 2>&1 || exit_code=$?

    echo "$exit_code" > "$REPLAY_DIR/exit_code"

    return $exit_code
}

# Capture post-execution state
capture_post_execution_state() {
    log_step "Capturing post-execution state..."

    # Capture any generated artifacts
    if [[ -d target ]]; then
        find target -name "*.log" -o -name "*.trace" -o -name "*.evidence" 2>/dev/null | \
        while read -r file; do
            local dest="$REPLAY_DIR/target_artifacts/$(basename "$file")"
            mkdir -p "$(dirname "$dest")"
            cp "$file" "$dest" 2>/dev/null || true
        done
    fi

    # Capture core dumps if any
    find . -name "core*" -o -name "*.core" 2>/dev/null | \
    while read -r core_file; do
        if [[ -f "$core_file" ]] && [[ -r "$core_file" ]]; then
            cp "$core_file" "$REPLAY_DIR/" 2>/dev/null || true
        fi
    done
}

# Generate replay instructions
generate_replay_instructions() {
    log_step "Generating replay instructions..."

    cat > "$REPLAY_DIR/REPLAY_INSTRUCTIONS.md" << EOF
# Deterministic Replay Instructions

Generated for failure: \`$FAILURE_TYPE\`
Test command: \`$TEST_COMMAND\`
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Quick Start

To reproduce this failure:

1. Restore the exact git state:
   \`\`\`bash
   git checkout $(cat "$REPLAY_DIR/git_state.json" | grep '"commit_hash"' | cut -d'"' -f4)

   # Apply any uncommitted changes if they exist
   if [[ -f "$REPLAY_DIR/uncommitted_changes.diff" ]]; then
       git apply "$REPLAY_DIR/uncommitted_changes.diff"
   fi
   \`\`\`

2. Set up environment variables:
   \`\`\`bash
   $(grep -E "(RUST|CARGO|ATP)_" "$REPLAY_DIR/environment_variables.json" | sed 's/.*"\([^"]*\)": *"\([^"]*\)".*/export \1="\2"/')
   \`\`\`

3. Restore Cargo configuration:
   \`\`\`bash
   cp "$REPLAY_DIR/Cargo.toml" .
   cp "$REPLAY_DIR/Cargo.lock" .
   \`\`\`

4. Execute the failing test:
   \`\`\`bash
   $TEST_COMMAND
   \`\`\`

## Detailed Environment Information

- **System**: $(uname -s) $(uname -r) $(uname -m)
- **Rust Version**: $(rustc --version 2>/dev/null || echo 'N/A')
- **Git Commit**: $(git rev-parse HEAD)
- **Exit Code**: $(cat "$REPLAY_DIR/exit_code")

## Artifacts Included

- \`system_environment.json\` - Complete system environment
- \`environment_variables.json\` - Environment variables at execution
- \`git_state.json\` - Git repository state
- \`Cargo.toml\` / \`Cargo.lock\` - Rust dependencies
- \`test_execution.log\` - Complete test output
- \`exit_code\` - Test command exit code

$(if [[ -f "$REPLAY_DIR/uncommitted_changes.diff" ]]; then
    echo "- \`uncommitted_changes.diff\` - Uncommitted changes in working tree"
fi)

$(if [[ -d "$REPLAY_DIR/target_artifacts" ]]; then
    echo "- \`target_artifacts/\` - Build artifacts and logs"
fi)

$(if [[ -d "$REPLAY_DIR/lab_evidence" ]]; then
    echo "- \`lab_evidence/\` - Lab scenario evidence artifacts"
fi)

$(if [[ -d "$REPLAY_DIR/proof_artifacts" ]]; then
    echo "- \`proof_artifacts/\` - Proof lane execution artifacts"
fi)

## Next Steps

1. **Reproduce Locally**: Use the instructions above to reproduce the failure
2. **Analyze Root Cause**: Review test execution logs and artifacts
3. **Implement Fix**: Make necessary code changes
4. **Verify Fix**: Re-run the test to confirm resolution
5. **Add Regression Test**: Ensure this failure type doesn't recur

For questions about this replay, contact the ATP development team.
EOF
}

# Generate evidence summary
generate_evidence_summary() {
    log_step "Generating evidence summary..."

    local file_count=$(find "$REPLAY_DIR" -type f | wc -l)
    local total_size=$(du -sh "$REPLAY_DIR" | cut -f1)

    cat > "$REPLAY_DIR/evidence_summary.json" << EOF
{
    "replay_session": {
        "tag": "$TAG",
        "failure_type": "$FAILURE_TYPE",
        "test_command": "$TEST_COMMAND",
        "generation_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "exit_code": $(cat "$REPLAY_DIR/exit_code")
    },
    "artifacts": {
        "total_files": $file_count,
        "total_size": "$total_size",
        "replay_directory": "$REPLAY_DIR"
    },
    "system_fingerprint": {
        "platform": "$(uname -s)",
        "architecture": "$(uname -m)",
        "git_commit": "$(git rev-parse HEAD)",
        "rust_version": "$(rustc --version 2>/dev/null || echo 'N/A')"
    }
}
EOF
}

# Main execution
main() {
    echo -e "${BLUE}ATP Deterministic Replay Artifact Generator${NC}"
    echo "=============================================="

    # Capture environment and execute test
    capture_system_environment
    capture_environment_variables
    capture_git_state
    capture_cargo_config

    local test_exit_code=0
    execute_with_tracing || test_exit_code=$?

    capture_post_execution_state
    generate_replay_instructions
    generate_evidence_summary

    echo ""
    echo "=============================================="

    if [[ $test_exit_code -eq 0 ]]; then
        echo -e "${GREEN}Test passed - replay artifacts generated for reference${NC}"
    else
        echo -e "${RED}Test failed - complete replay artifacts generated${NC}"
    fi

    echo -e "${BLUE}Replay artifacts stored in: $REPLAY_DIR${NC}"
    echo -e "${BLUE}See REPLAY_INSTRUCTIONS.md for reproduction steps${NC}"

    # Return the original test exit code
    exit $test_exit_code
}

# Execute main function
main "$@"