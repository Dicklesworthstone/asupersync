#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd
)"
SOURCE_DIR="${SCRIPT_DIR}"
CLAUDE_SKILLS_DIR="${HOME}/.claude/skills"
CODEX_SKILLS_DIR="${CODEX_HOME:-${HOME}/.codex}/skills"
GEMINI_SKILLS_DIR="${HOME}/.gemini/skills"

DRY_RUN=false
ASSUME_YES=false

usage() {
    cat <<'EOF'
Install repo-local skills into detected global agent skill directories.

Usage:
  ./skills/install_asupersync_skill_globally.sh [--dry-run] [--yes]

Options:
  --dry-run, -n  Preview rsync operations without writing changes
  --yes, -y      Skip the confirmation prompt
  --help, -h     Show this help message

Notes:
  - Installs skills from this repo's ./skills directory.
  - Detects Claude Code, Codex, and Gemini using command/home-directory hints.
  - Does not delete anything from destination directories.
  - Uses rsync for additive/update mirroring only.
EOF
}

has_command() {
    command -v "$1" >/dev/null 2>&1
}

append_target() {
    local name="$1"
    local dest="$2"
    local reason="$3"

    TARGET_NAMES+=("$name")
    TARGET_DIRS+=("$dest")
    TARGET_REASONS+=("$reason")
}

detect_targets() {
    TARGET_NAMES=()
    TARGET_DIRS=()
    TARGET_REASONS=()

    local reason=""

    reason=""
    if has_command "claude"; then
        reason="detected \`claude\` command"
    elif [[ -d "${HOME}/.claude" ]]; then
        reason="detected ~/.claude home"
    fi
    if [[ -n "$reason" ]]; then
        append_target "Claude Code" "$CLAUDE_SKILLS_DIR" "$reason"
    fi

    reason=""
    if has_command "cod"; then
        reason="detected \`cod\` command"
    elif has_command "codex"; then
        reason="detected \`codex\` command"
    elif [[ -n "${CODEX_HOME:-}" ]]; then
        reason="detected CODEX_HOME"
    elif [[ -d "${HOME}/.codex" ]]; then
        reason="detected ~/.codex home"
    fi
    if [[ -n "$reason" ]]; then
        append_target "Codex" "$CODEX_SKILLS_DIR" "$reason"
    fi

    reason=""
    if has_command "gmi"; then
        reason="detected \`gmi\` command"
    elif has_command "gemini"; then
        reason="detected \`gemini\` command"
    elif [[ -d "${HOME}/.gemini" ]]; then
        reason="detected ~/.gemini home"
    fi
    if [[ -n "$reason" ]]; then
        append_target "Gemini" "$GEMINI_SKILLS_DIR" "$reason"
    fi
}

discover_skills() {
    SKILL_DIRS=()

    while IFS= read -r skill_dir; do
        [[ -n "$skill_dir" ]] && SKILL_DIRS+=("$skill_dir")
    done < <(
        find "$SOURCE_DIR" \
            -mindepth 1 \
            -maxdepth 1 \
            -type d \
            -exec test -f "{}/SKILL.md" \; \
            -print | sort
    )
}

confirm() {
    if $ASSUME_YES; then
        return 0
    fi

    if [[ ! -t 0 ]]; then
        echo "Refusing to install without confirmation from an interactive terminal." >&2
        echo "Re-run with --yes if you want non-interactive execution." >&2
        return 1
    fi

    local answer=""
    printf "Proceed with global skill installation? [y/N] "
    read -r answer
    case "${answer}" in
        y|Y|yes|YES)
            return 0
            ;;
        *)
            echo "Aborted."
            return 1
            ;;
    esac
}

sync_targets() {
    local rsync_flags=(-a --human-readable --itemize-changes)
    if $DRY_RUN; then
        rsync_flags=(-anv --human-readable --itemize-changes)
    fi

    local idx=0
    local skill_dir=""
    local skill_name=""
    local target_dir=""

    for idx in "${!TARGET_NAMES[@]}"; do
        target_dir="${TARGET_DIRS[$idx]}"
        mkdir -p "$target_dir"
        echo
        echo "==> ${TARGET_NAMES[$idx]} -> ${target_dir}"
        for skill_dir in "${SKILL_DIRS[@]}"; do
            skill_name="$(basename "$skill_dir")"
            mkdir -p "${target_dir}/${skill_name}"
            rsync "${rsync_flags[@]}" "${skill_dir}/" "${target_dir}/${skill_name}/"
        done
    done
}

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run|-n)
                DRY_RUN=true
                ;;
            --yes|-y)
                ASSUME_YES=true
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
        esac
        shift
    done

    if ! has_command "rsync"; then
        echo "rsync is required but not installed." >&2
        exit 1
    fi

    discover_skills
    if [[ "${#SKILL_DIRS[@]}" -eq 0 ]]; then
        echo "No repo-local skills found under ${SOURCE_DIR}." >&2
        exit 1
    fi

    detect_targets
    if [[ "${#TARGET_NAMES[@]}" -eq 0 ]]; then
        echo "No supported global agent installations detected." >&2
        echo "Looked for Claude Code, Codex, and Gemini homes/commands." >&2
        exit 1
    fi

    echo "Repo skill source: ${SOURCE_DIR}"
    echo "Skills to install:"
    for skill_dir in "${SKILL_DIRS[@]}"; do
        echo "  - $(basename "$skill_dir")"
    done

    echo "Detected agent targets:"
    local idx=0
    for idx in "${!TARGET_NAMES[@]}"; do
        echo "  - ${TARGET_NAMES[$idx]} -> ${TARGET_DIRS[$idx]} (${TARGET_REASONS[$idx]})"
    done

    if $DRY_RUN; then
        echo "Mode: dry run"
    else
        echo "Mode: live install"
    fi
    echo "Safety: this script only adds/updates files; it does not delete destination content."

    confirm
    sync_targets

    echo
    if $DRY_RUN; then
        echo "Dry run complete."
    else
        echo "Global skill installation complete."
    fi
}

main "$@"
