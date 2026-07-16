#!/usr/bin/env bash
# ATP vs rsync benchmark orchestrator (br-asupersync-iiz6jk).
# Run from the dev box; drives a sender and a receiver fleet machine over the
# open internet. Every transfer is SHA-256-verified on the receiver.
#
# See README.md in this directory for methodology.
set -euo pipefail

# Never inherit the legacy clap environment input into SSH or helper children.
# Reject it instead of silently benchmarking with a different generated key.
if [[ ${ATP_RQ_AUTH_KEY_HEX+x} ]]; then
    set +x
    unset ATP_RQ_AUTH_KEY_HEX RQ_AUTH_SECRET
    echo "ATP_RQ_AUTH_KEY_HEX is forbidden; use --atp-rq-auth-key-stdin" >&2
    exit 2
fi
if [[ ${RQ_AUTH_KEY_HEX+x} ]]; then
    set +x
    unset RQ_AUTH_KEY_HEX RQ_AUTH_SECRET
    echo "RQ_AUTH_KEY_HEX is forbidden; use --atp-rq-auth-key-stdin" >&2
    exit 2
fi
unset RQ_AUTH_SECRET

SENDER="" SENDER_KEY="" RECEIVER="" RECEIVER_KEY=""
ATP_BINARY="target/release/atp"
PAYLOADS="512k,1m,10m,100m,1g,tree"
TOOLS="atp-quic,atp-rq,atp-tcp,rsync-ssh,rsyncd"
RUNS=3
OUT=""
ATP_PORT=8472
RSYNCD_PORT=8730
BASE=/root/atp-bench
RUN_ID=""
ATP_RQ_STREAMS=1
ATP_RQ_SYMBOL_SIZE=1024
ATP_RQ_MAX_BLOCK_SIZE=auto
ATP_RQ_REPAIR_OVERHEAD=1.001
ATP_RQ_TAIL_DRAIN_MS=2
ATP_RQ_AUTH_KEY_STDIN=0
RQ_AUTH_SECRET=""
ATP_QUIC_SERVER_NAME=""
ATP_QUIC_HANDSHAKE_TIMEOUT_MS=30000
MAX_LOAD_PER_CORE=1.5
MAX_SENDER_RSS_MB=0
MAX_RECEIVER_RSS_MB=0

clear_rq_auth_secret() {
    set +x
    if [[ -n "${RQ_AUTH_SECRET:-}" ]]; then
        RQ_AUTH_SECRET=0000000000000000000000000000000000000000000000000000000000000000
    fi
    unset RQ_AUTH_SECRET
}
send_rq_auth_secret() {
    set +x
    [[ ${#RQ_AUTH_SECRET} -eq 64 ]] \
        || { echo "ATP RQ auth key is not initialized" >&2; return 2; }
    builtin printf '%s\n' "$RQ_AUTH_SECRET"
}
trap clear_rq_auth_secret EXIT

is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }
canonical_uint() {
    local value="$1" leading
    is_uint "$value" || return 1
    leading="${value%%[!0]*}"
    value="${value#"$leading"}"
    builtin printf '%s' "${value:-0}"
}
uint_le() {
    local value limit="$2" index value_digit limit_digit
    value=$(canonical_uint "$1") || return 1
    if ((${#value} != ${#limit})); then
        ((${#value} < ${#limit}))
        return
    fi
    for ((index = 0; index < ${#limit}; index++)); do
        value_digit="${value:index:1}"
        limit_digit="${limit:index:1}"
        ((value_digit < limit_digit)) && return 0
        ((value_digit > limit_digit)) && return 1
    done
    return 0
}
positive_uint_le() {
    [[ "$1" =~ [1-9] ]] && uint_le "$1" "$2"
}
is_valid_max_block_size() {
    local value="${1,,}" digits suffix max_count
    [[ "$value" == auto ]] && return 0
    [[ "$value" =~ ^([0-9]+)(gib|gb|g|mib|mb|m|kib|kb|k|b)?$ ]] || return 1
    digits="${BASH_REMATCH[1]}"
    suffix="${BASH_REMATCH[2]:-}"
    case "$suffix" in
        g|gb|gib) max_count=17179869183 ;;
        m|mb|mib) max_count=17592186044415 ;;
        k|kb|kib) max_count=18014398509481983 ;;
        ""|b)     max_count=18446744073709551615 ;;
        *)         return 1 ;;
    esac
    uint_le "$digits" "$max_count"
}
is_finite_decimal() {
    local value="$1" whole
    [[ "$value" =~ ^(0|[1-9][0-9]*)([.][0-9]+)?$ ]] || return 1
    whole="${value%%.*}"
    ((${#whole} <= 64 && ${#value} <= 129))
}
is_finite_decimal_at_least_one() {
    is_finite_decimal "$1" && [[ "${1%%.*}" != 0 ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sender) SENDER="$2"; shift 2;;
        --sender-key) SENDER_KEY="$2"; shift 2;;
        --receiver) RECEIVER="$2"; shift 2;;
        --receiver-key) RECEIVER_KEY="$2"; shift 2;;
        --atp-binary) ATP_BINARY="$2"; shift 2;;
        --payloads) PAYLOADS="$2"; shift 2;;
        --tools) TOOLS="$2"; shift 2;;
        --runs) RUNS="$2"; shift 2;;
        --out) OUT="$2"; shift 2;;
        --base) BASE="$2"; shift 2;;
        --run-id) RUN_ID="$2"; shift 2;;
        --atp-rq-streams) ATP_RQ_STREAMS="$2"; shift 2;;
        --atp-rq-symbol-size) ATP_RQ_SYMBOL_SIZE="$2"; shift 2;;
        --atp-rq-max-block-size) ATP_RQ_MAX_BLOCK_SIZE="$2"; shift 2;;
        --atp-rq-repair-overhead) ATP_RQ_REPAIR_OVERHEAD="$2"; shift 2;;
        --atp-rq-tail-drain-ms) ATP_RQ_TAIL_DRAIN_MS="$2"; shift 2;;
        --atp-rq-auth-key-stdin) ATP_RQ_AUTH_KEY_STDIN=1; shift;;
        --atp-quic-server-name) ATP_QUIC_SERVER_NAME="$2"; shift 2;;
        --atp-quic-handshake-timeout-ms) ATP_QUIC_HANDSHAKE_TIMEOUT_MS="$2"; shift 2;;
        --max-load-per-core) MAX_LOAD_PER_CORE="$2"; shift 2;;
        --max-sender-rss-mb) MAX_SENDER_RSS_MB="$2"; shift 2;;
        --max-receiver-rss-mb) MAX_RECEIVER_RSS_MB="$2"; shift 2;;
        *) echo "unknown arg: $1" >&2; exit 2;;
    esac
done
[[ -n "$SENDER" && -n "$RECEIVER" ]] || { echo "need --sender and --receiver" >&2; exit 2; }
[[ "$ATP_BINARY" =~ ^[A-Za-z0-9_./+-]+$ && "$ATP_BINARY" != -* ]] \
    || { echo "--atp-binary must be a shell-safe local path, not an option or remote source" >&2; exit 2; }
[[ "$BASE" =~ ^/[A-Za-z0-9._/-]+$ ]] \
    || { echo "--base must be an absolute shell-safe path" >&2; exit 2; }
positive_uint_le "$RUNS" 4294967295 \
    || { echo "--runs must be a positive integer no larger than 4294967295" >&2; exit 2; }
positive_uint_le "$ATP_RQ_STREAMS" 18446744073709551615 \
    || { echo "--atp-rq-streams must fit a positive 64-bit usize" >&2; exit 2; }
positive_uint_le "$ATP_RQ_SYMBOL_SIZE" 65535 \
    || { echo "--atp-rq-symbol-size must be an integer from 1 through 65535" >&2; exit 2; }
is_valid_max_block_size "$ATP_RQ_MAX_BLOCK_SIZE" \
    || { echo "--atp-rq-max-block-size must be auto or a 64-bit byte count with an optional K/M/G suffix" >&2; exit 2; }
is_finite_decimal_at_least_one "$ATP_RQ_REPAIR_OVERHEAD" \
    || { echo "--atp-rq-repair-overhead must be a finite decimal at least 1.0" >&2; exit 2; }
uint_le "$ATP_RQ_TAIL_DRAIN_MS" 18446744073709551615 \
    || { echo "--atp-rq-tail-drain-ms must fit an unsigned 64-bit integer" >&2; exit 2; }
positive_uint_le "$ATP_QUIC_HANDSHAKE_TIMEOUT_MS" 18446744073709551615 \
    || { echo "--atp-quic-handshake-timeout-ms must fit a positive unsigned 64-bit integer" >&2; exit 2; }
is_finite_decimal "$MAX_LOAD_PER_CORE" \
    || { echo "--max-load-per-core must be a finite nonnegative decimal" >&2; exit 2; }
uint_le "$MAX_SENDER_RSS_MB" 18446744073709551615 \
    || { echo "--max-sender-rss-mb must fit an unsigned 64-bit integer" >&2; exit 2; }
uint_le "$MAX_RECEIVER_RSS_MB" 18446744073709551615 \
    || { echo "--max-receiver-rss-mb must fit an unsigned 64-bit integer" >&2; exit 2; }
if [[ ! "$ATP_PORT" =~ ^[0-9]{1,5}$ ]] \
    || ((10#$ATP_PORT < 1 || 10#$ATP_PORT > 65535)); then
    echo "ATP port must be an integer from 1 through 65535" >&2
    exit 2
fi
RUNS=$(canonical_uint "$RUNS")
ATP_RQ_STREAMS=$(canonical_uint "$ATP_RQ_STREAMS")
ATP_RQ_SYMBOL_SIZE=$(canonical_uint "$ATP_RQ_SYMBOL_SIZE")
ATP_RQ_TAIL_DRAIN_MS=$(canonical_uint "$ATP_RQ_TAIL_DRAIN_MS")
ATP_QUIC_HANDSHAKE_TIMEOUT_MS=$(canonical_uint "$ATP_QUIC_HANDSHAKE_TIMEOUT_MS")
MAX_SENDER_RSS_MB=$(canonical_uint "$MAX_SENDER_RSS_MB")
MAX_RECEIVER_RSS_MB=$(canonical_uint "$MAX_RECEIVER_RSS_MB")
ATP_PORT=$(canonical_uint "$ATP_PORT")
if [[ -n "$RUN_ID" ]]; then
    case "$RUN_ID" in
        .|..|*[!A-Za-z0-9._-]*) echo "invalid --run-id; use a non-traversing A-Za-z0-9._- value" >&2; exit 2;;
    esac
fi

IFS=',' read -ra TOOL_LIST <<< "$TOOLS"
((${#TOOL_LIST[@]} > 0)) || { echo "--tools must not be empty" >&2; exit 2; }
HAS_ATP_RQ=0
HAS_ATP_QUIC=0
for tool in "${TOOL_LIST[@]}"; do
    case "$tool" in
        atp-quic|atp-rq|atp-tcp|rsync-ssh|rsyncd) ;;
        *) echo "--tools contains an unknown method" >&2; exit 2;;
    esac
    [[ "$tool" == atp-rq ]] && HAS_ATP_RQ=1
    [[ "$tool" == atp-quic ]] && HAS_ATP_QUIC=1
done
if ((HAS_ATP_QUIC)) && ! positive_uint_le "$ATP_RQ_SYMBOL_SIZE" 1144; then
    echo "--atp-rq-symbol-size must be no larger than 1144 when atp-quic is selected" >&2
    exit 2
fi
IFS=',' read -ra PAYLOAD_LIST <<< "$PAYLOADS"
((${#PAYLOAD_LIST[@]} > 0)) || { echo "--payloads must not be empty" >&2; exit 2; }
for payload in "${PAYLOAD_LIST[@]}"; do
    case "$payload" in
        512k|1m|10m|100m|1g|tree) ;;
        *) echo "--payloads contains an unknown payload" >&2; exit 2;;
    esac
done

if [[ "$ATP_RQ_AUTH_KEY_STDIN" -eq 1 ]]; then
    [[ "$HAS_ATP_RQ" -eq 1 ]] \
        || { echo "--atp-rq-auth-key-stdin requires atp-rq" >&2; exit 2; }
    # Never let xtrace copy protected input into a command log.
    set +x
    [[ ! -t 0 ]] \
        || { echo "--atp-rq-auth-key-stdin requires redirected stdin; refusing terminal echo" >&2; exit 2; }
    if ! RQ_AUTH_SECRET=$(/usr/bin/python3 -c '
import sys

data = sys.stdin.buffer.read(66)
valid = (
    len(data) == 65
    and data[-1:] == b"\n"
    and all(byte in b"0123456789abcdefABCDEF" for byte in data[:-1])
)
if not valid:
    raise SystemExit(2)
sys.stdout.buffer.write(data[:-1])
'); then
        echo "ATP RQ auth stdin must contain exactly one 64-hex line" >&2
        exit 2
    fi
fi
OUT="${OUT:-artifacts/atp_bench/$(date +%Y-%m-%d)}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
case "$RUN_ID" in
    .|..|*[!A-Za-z0-9._-]*) echo "invalid --run-id; use a non-traversing A-Za-z0-9._- value" >&2; exit 2;;
esac

SSH_STDIN_CONFIG_CANARY_PATH=/__atp_ssh_stdin_preflight_canary__
SSH_S_OPTS=(-T -x -i "$SENDER_KEY"
    -o BatchMode=yes -o StdinNull=no -o RequestTTY=no
    -o ForkAfterAuthentication=no -o SessionType=default
    -o PermitLocalCommand=no -o LocalCommand=none -o RemoteCommand=none
    -o KnownHostsCommand=none
    -o ControlMaster=no -o ControlPath=none -o ControlPersist=no
    -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes
    -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -S none)
SSH_R_OPTS=(-T -x -i "$RECEIVER_KEY"
    -o BatchMode=yes -o StdinNull=no -o RequestTTY=no
    -o ForkAfterAuthentication=no -o SessionType=default
    -o PermitLocalCommand=no -o LocalCommand=none -o RemoteCommand=none
    -o KnownHostsCommand=none
    -o ControlMaster=no -o ControlPath=none -o ControlPersist=no
    -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes
    -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -S none)
SSH_S=(ssh "${SSH_S_OPTS[@]}" -- "$SENDER")
SSH_R=(ssh "${SSH_R_OPTS[@]}" -- "$RECEIVER")
SCP_S=(scp -i "$SENDER_KEY" -o StrictHostKeyChecking=accept-new)
SCP_R=(scp -i "$RECEIVER_KEY" -o StrictHostKeyChecking=accept-new)

ssh_path_targets_protected_stdin() {
    local path="$1" component normalized prefix remainder variable suffix replacement
    local env_open="\${"
    local current_user_home="${2:-}" tilde_user tilde_home expansions=0
    local -a raw_components=() components=() resolved_paths=()

    # `%d` and bare `~` use the login home from passwd, not inherited HOME.
    # Missing or ambiguous passwd evidence is unsafe for protected stdin.
    [[ "$current_user_home" == /* ]] || return 0

    # `ssh -G` already removes syntactic config quoting. Any quote or
    # backslash that remains is literal or ambiguous filename evidence; do not
    # normalize it into a different path and risk checking the wrong inode.
    if [[ "$path" == *\"* || "$path" == *\'* || "$path" == *\\* ]]; then
        return 0
    fi
    if [[ "$path" == - ]]; then
        return 0
    fi

    # OpenSSH prints tokens and ${VAR} references unexpanded in `ssh -G`, then
    # expands them when it opens the file. Mirror the slash-bearing expansions
    # without eval so traversal cannot disguise an fd0 alias from the probe.
    while [[ "$path" == *"$env_open"* ]]; do
        ((++expansions <= 16)) || return 0
        prefix="${path%%"$env_open"*}"
        remainder="${path#*"$env_open"}"
        [[ "$remainder" == *'}'* ]] || return 0
        variable="${remainder%%'}'*}"
        suffix="${remainder#*'}'}"
        [[ "$variable" =~ ^[A-Za-z_][A-Za-z0-9_]*$ && -v "$variable" ]] || return 0
        replacement="${!variable}"
        path="$prefix$replacement$suffix"
    done
    if [[ "$path" == *%d* ]]; then
        path="${path//%d/$current_user_home}"
    fi
    # Other percent tokens depend on effective host/user fields and can expand
    # to slash-bearing paths after `ssh -G` (for example %h via HostName).
    # Reject them rather than trying to partially reproduce OpenSSH expansion.
    if [[ "$path" == *%* ]]; then
        return 0
    fi

    if [[ "$path" == '~' ]]; then
        path="$current_user_home"
    elif [[ "$path" == \~/* ]]; then
        path="$current_user_home/${path:2}"
    elif [[ "$path" == '~'* ]]; then
        tilde_user="${path#\~}"
        tilde_user="${tilde_user%%/*}"
        [[ "$tilde_user" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] || return 0
        tilde_home=$(/usr/bin/getent passwd "$tilde_user" 2>/dev/null \
            | /usr/bin/awk -F: 'NR == 1 { print $6 }')
        [[ "$tilde_home" == /* ]] || return 0
        path="$tilde_home${path:$((1 + ${#tilde_user}))}"
    elif [[ "$path" != /* ]]; then
        path="$PWD/$path"
    fi

    IFS=/ read -ra raw_components <<< "$path"
    for component in "${raw_components[@]}"; do
        case "$component" in
            ""|.) ;;
            ..)
                if ((${#components[@]} > 0)); then
                    unset 'components[${#components[@]}-1]'
                fi
                ;;
            *) components+=("${component,,}") ;;
        esac
    done
    local IFS=/
    normalized="/${components[*]}"
    if [[ "$normalized" == /dev/stdin \
        || "$normalized" =~ ^/(dev|proc)(/[^/]+)*/fd/0$ ]]; then
        return 0
    fi

    # Resolve both paths in one non-reading process. This catches symlinked fd0
    # aliases such as /proc/self/root/dev/stdin while keeping pipe targets
    # comparable (the resolving process/PID is identical for both arguments).
    mapfile -d '' -t resolved_paths \
        < <(/usr/bin/readlink -fz -- "$path" /dev/stdin 2>/dev/null || true)
    [[ ${#resolved_paths[@]} -eq 2 \
        && "${resolved_paths[0]}" == "${resolved_paths[1]}" ]]
}

ssh_path_list_targets_protected_stdin() {
    local value="$1" current_user_home="$2" candidate=""
    local start end
    local -a words=()

    # `ssh -G` flattens both path-list separators and spaces inside quoted
    # paths. Check every bounded contiguous interpretation so a quoted symlink
    # such as "/tmp/key alias" cannot hide an fd0 target after flattening.
    read -ra words <<< "$value"
    ((${#words[@]} > 0 && ${#words[@]} <= 16)) || return 0
    for ((start = 0; start < ${#words[@]}; start++)); do
        candidate=""
        for ((end = start; end < ${#words[@]}; end++)); do
            candidate+="${candidate:+ }${words[end]}"
            if ssh_path_targets_protected_stdin "$candidate" "$current_user_home"; then
                return 0
            fi
        done
    done
    return 1
}

# Inspect the exact host, options, and eventual remote command before a secret
# is put on stdin. The probe receives only a public config canary, allowing an
# Include that consumes fd 0 to be detected without exposing the RQ key.
ssh_secret_stdin_preflight() {
    local options_name="$1" host="$2" remote_command="$3"
    local effective line name value raw_value lower_value unsafe current_user_home
    local canary_fd canary_line canary_remainder
    declare -n options_ref="$options_name"

    canary_line="IdentityFile $SSH_STDIN_CONFIG_CANARY_PATH"
    exec {canary_fd}<<< "$canary_line"
    if ! effective=$(env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX \
        ssh "${options_ref[@]}" -G -- "$host" "$remote_command" \
        <&"$canary_fd" 2>/dev/null); then
        exec {canary_fd}<&-
        echo "failed to inspect effective SSH config for protected stdin delivery to $host" >&2
        return 2
    fi
    if ! IFS= read -r canary_remainder <&"$canary_fd" \
        || [[ "$canary_remainder" != "$canary_line" ]]; then
        exec {canary_fd}<&-
        echo "effective SSH config for $host consumed the public stdin canary" >&2
        return 2
    fi
    exec {canary_fd}<&-
    current_user_home=$(/usr/bin/getent passwd "$EUID" 2>/dev/null \
        | /usr/bin/awk -F: 'NR == 1 { print $6 }')
    if [[ "$current_user_home" != /* ]]; then
        echo "cannot resolve a safe local passwd home for protected stdin delivery" >&2
        return 2
    fi

    while IFS= read -r line; do
        name="${line%%[[:space:]]*}"
        [[ "$name" != "$line" ]] || continue
        raw_value="${line#"$name"}"
        raw_value="${raw_value:1}"
        value="$raw_value"
        value="${value#"${value%%[![:space:]]*}"}"
        name="${name,,}"
        lower_value="${value,,}"
        unsafe=0
        case "$name" in
            batchmode) [[ "$lower_value" == yes || "$lower_value" == true ]] || unsafe=1 ;;
            controlmaster|controlpersist)
                [[ "$lower_value" == no || "$lower_value" == false ]] || unsafe=1 ;;
            controlpath) [[ "$lower_value" == none ]] || unsafe=1 ;;
            forwardx11|permitlocalcommand|requesttty|stdinnull|forkafterauthentication)
                [[ "$lower_value" == no || "$lower_value" == false ]] || unsafe=1 ;;
            sessiontype) [[ "$lower_value" == default ]] || unsafe=1 ;;
            localcommand|remotecommand) [[ "$lower_value" == none ]] || unsafe=1 ;;
            proxycommand) [[ "$lower_value" != - ]] || unsafe=1 ;;
            identityfile|certificatefile|revokedhostkeys|pkcs11provider|securitykeyprovider|xauthlocation)
                if [[ "${raw_value,,}" == "${SSH_STDIN_CONFIG_CANARY_PATH,,}" ]] \
                    || ssh_path_targets_protected_stdin "$raw_value" "$current_user_home"; then
                    unsafe=1
                fi
                ;;
            userknownhostsfile|globalknownhostsfile)
                # Path-list quoting is erased by `ssh -G`. A single internal
                # space is covered by the contiguous-candidate check; leading,
                # trailing, repeated, or tab whitespace is ambiguous and must
                # fail closed rather than be normalized into a different path.
                if [[ "$raw_value" == [[:space:]]* \
                    || "$raw_value" == *[[:space:]] \
                    || "$raw_value" == *"  "* \
                    || "$raw_value" == *$'\t'* ]] \
                    || ssh_path_list_targets_protected_stdin "$value" "$current_user_home"; then
                    unsafe=1
                fi
                ;;
        esac
        if ((unsafe)); then
            echo "effective SSH config for $host conflicts with protected stdin delivery: $name" >&2
            return 2
        fi
    done <<< "$effective"
}

receiver_host_is_safe() {
    local host="$1"
    if [[ "$host" == *:* ]]; then
        # Raw IPv6 with an optional RFC 4007 zone identifier. `ssh -G` emits
        # HostName without URI brackets, so brackets are neither needed nor
        # safe in the unquoted remote command contexts below.
        [[ "$host" =~ ^[0-9A-Fa-f:]+(%[A-Za-z0-9_.-]+)?$ ]]
    else
        # DNS, IPv4, and locally configured host tokens. The first character
        # rule also prevents downstream option injection through a leading '-'.
        [[ "$host" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]]
    fi
}

# Reject any effective-config collision before creating local output or touching
# either fleet host. Secret-bearing commands repeat this check with their exact
# remote command immediately before delivery.
if ((HAS_ATP_RQ)); then
    ssh_secret_stdin_preflight SSH_S_OPTS "$SENDER" "true"
    ssh_secret_stdin_preflight SSH_R_OPTS "$RECEIVER" "true"
fi

ssh_hostname() {
    ssh -G -- "$1" 2>/dev/null | awk '$1 == "hostname" { print $2; exit }'
}
RECEIVER_IP=$(ssh_hostname "$RECEIVER")
RECEIVER_IP="${RECEIVER_IP:-${RECEIVER##*@}}"
receiver_host_is_safe "$RECEIVER_IP" \
    || { echo "receiver SSH HostName is not a safe hostname or IP literal" >&2; exit 2; }
ATP_QUIC_SERVER_NAME="${ATP_QUIC_SERVER_NAME:-$RECEIVER_IP}"
receiver_host_is_safe "$ATP_QUIC_SERVER_NAME" \
    || { echo "ATP QUIC server name is not a safe hostname or IP literal" >&2; exit 2; }
QUIC_TLS_DIR="$BASE/runs/$RUN_ID/quic_tls"
QUIC_CERT="$QUIC_TLS_DIR/server.pem"
QUIC_KEY="$QUIC_TLS_DIR/server.key"

mkdir -p "$OUT"
RESULTS="$OUT/results.jsonl"
note() { echo "[bench] $(date +%H:%M:%S) $*" >&2; }

# ─── Preflight: deploy ───────────────────────────────────────────────────────
note "deploying scripts + binary"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"${SSH_S[@]}" "mkdir -p $BASE/recv/$RUN_ID $BASE/runs/$RUN_ID $BASE/manifests"
"${SSH_R[@]}" "mkdir -p $BASE/recv/$RUN_ID $BASE/runs/$RUN_ID $BASE/manifests"
"${SCP_S[@]}" -- "$SCRIPT_DIR/gen_payloads.sh" "$SCRIPT_DIR/collect_metrics.sh" "$SCRIPT_DIR/run_one.sh" "$SENDER:$BASE/"
"${SCP_R[@]}" -- "$SCRIPT_DIR/collect_metrics.sh" "$RECEIVER:$BASE/"
"${SCP_S[@]}" -- "$ATP_BINARY" "$SENDER:$BASE/atp"
"${SCP_R[@]}" -- "$ATP_BINARY" "$RECEIVER:$BASE/atp"
"${SSH_S[@]}" "chmod +x $BASE/atp $BASE/*.sh"
"${SSH_R[@]}" "chmod +x $BASE/atp $BASE/*.sh"

ensure_rq_auth_secret() {
    if [[ -z "${RQ_AUTH_SECRET:-}" ]]; then
        note "generating per-run ATP RQ symbol-auth key"
        # Command substitution traces assignment values, so disable xtrace before
        # acquiring the generated secret as well as before accepting stdin input.
        set +x
        RQ_AUTH_SECRET=$("${SSH_S[@]}" "env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX $BASE/atp rq-keygen")
    fi
    [[ "$RQ_AUTH_SECRET" =~ ^[0-9A-Fa-f]{64}$ ]] \
        || { echo "ATP RQ auth key must be 64 hex characters" >&2; exit 2; }
}

if [[ ",$TOOLS," == *",atp-quic,"* ]]; then
    note "generating per-run ATP QUIC TLS certificate"
    "${SSH_R[@]}" "mkdir -p $QUIC_TLS_DIR
san_type=DNS
case '$ATP_QUIC_SERVER_NAME' in *:*) san_type=IP;; *[!0-9.]*) san_type=DNS;; *) san_type=IP;; esac
openssl req -x509 -newkey ed25519 -nodes -keyout $QUIC_KEY -out $QUIC_CERT -days 3 -subj '/CN=$ATP_QUIC_SERVER_NAME' -addext \"subjectAltName=\${san_type}:$ATP_QUIC_SERVER_NAME\" >/dev/null 2>&1 || \
openssl req -x509 -newkey rsa:2048 -nodes -keyout $QUIC_KEY -out $QUIC_CERT -days 3 -subj '/CN=$ATP_QUIC_SERVER_NAME' -addext \"subjectAltName=\${san_type}:$ATP_QUIC_SERVER_NAME\" >/dev/null 2>&1
test -s $QUIC_CERT && test -s $QUIC_KEY" \
        || { echo "failed to generate QUIC TLS certificate on receiver" >&2; exit 1; }
    "${SSH_R[@]}" "cat $QUIC_CERT" | "${SSH_S[@]}" "mkdir -p $QUIC_TLS_DIR && cat > $QUIC_CERT"
fi

# Sender→receiver ssh trust for rsync-ssh (sender's root key onto receiver).
note "ensuring sender→receiver ssh trust"
SENDER_PUB=$("${SSH_S[@]}" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && test -f ~/.ssh/id_ed25519 || ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519 -q; cat ~/.ssh/id_ed25519.pub")
read -r SENDER_PUB_TYPE SENDER_PUB_BLOB _ <<< "$SENDER_PUB"
[[ "$SENDER_PUB_TYPE" == ssh-ed25519 && "$SENDER_PUB_BLOB" =~ ^[A-Za-z0-9+/=]+$ ]] \
    || { echo "sender returned an invalid Ed25519 public key" >&2; exit 2; }
SENDER_PUB="$SENDER_PUB_TYPE $SENDER_PUB_BLOB"
"${SSH_R[@]}" "grep -qF '$SENDER_PUB' /root/.ssh/authorized_keys 2>/dev/null || echo '$SENDER_PUB' >> /root/.ssh/authorized_keys"
"${SSH_S[@]}" "ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 root@$RECEIVER_IP true" \
    || { echo "sender cannot ssh to receiver" >&2; exit 1; }

note "generating payloads on sender (1g + tree take a while on first run)"
"${SSH_S[@]}" "bash $BASE/gen_payloads.sh $BASE"
note "copying manifests to receiver"
"${SSH_S[@]}" "tar -C $BASE -cf - manifests" | "${SSH_R[@]}" "tar -C $BASE -xf -"

# Network conditions snapshot.
note "recording network conditions"
RTT=$("${SSH_S[@]}" "ping -c 10 -q $RECEIVER_IP 2>/dev/null | tail -1" || echo "ping unavailable")
SENDER_CORES=$("${SSH_S[@]}" nproc)
RECEIVER_CORES=$("${SSH_R[@]}" nproc)
cat > "$OUT/conditions.json" <<EOF
{"date":"$(date -u +%FT%TZ)","run_id":"$RUN_ID","sender":"$SENDER","receiver":"$RECEIVER","rtt":"$RTT","sender_cores":$SENDER_CORES,"receiver_cores":$RECEIVER_CORES,"tools":"$TOOLS","payloads":"$PAYLOADS","runs":$RUNS,"atp_rq_streams":$ATP_RQ_STREAMS,"atp_rq_symbol_size":$ATP_RQ_SYMBOL_SIZE,"atp_rq_max_block_size":"$ATP_RQ_MAX_BLOCK_SIZE","atp_rq_repair_overhead":$ATP_RQ_REPAIR_OVERHEAD,"atp_rq_tail_drain_ms":$ATP_RQ_TAIL_DRAIN_MS,"atp_rq_auth":"per-run-stdin-key","atp_quic_tls":"per-run-self-signed","atp_quic_server_name":"$ATP_QUIC_SERVER_NAME","atp_quic_handshake_timeout_ms":$ATP_QUIC_HANDSHAKE_TIMEOUT_MS,"max_load_per_core":$MAX_LOAD_PER_CORE,"max_sender_rss_mb":$MAX_SENDER_RSS_MB,"max_receiver_rss_mb":$MAX_RECEIVER_RSS_MB}
EOF
note "RTT: $RTT"

payload_path() { # payload name -> path under payloads/
    case "$1" in
        512k) echo "single_512k.bin";; 1m) echo "single_1m.bin";;
        10m) echo "single_10m.bin";; 100m) echo "single_100m.bin";;
        1g) echo "single_1g.bin";; tree) echo "tree";;
        *) echo "unknown payload $1" >&2; exit 2;;
    esac
}
manifest_name() { case "$1" in tree) echo tree;; *) echo "single_$1";; esac; }

payload_bytes() {
    "${SSH_S[@]}" "du -sb $BASE/payloads/$(payload_path "$1") | cut -f1"
}

# ─── rsyncd lifecycle on receiver ────────────────────────────────────────────
# NOTE: do not `pkill -f 'rsync --daemon'` — the remote shell's own command line
# contains that string, so pkill -f would kill the launching ssh session
# (exit 255). Kill by pid file instead. `uid = root`/`gid = root` are required
# so the module can write into the root-owned dest; `setsid </dev/null` fully
# detaches the daemon so it survives the ssh session closing.
start_rsyncd() {
    "${SSH_R[@]}" "test -f $BASE/rsyncd.pid && kill \$(cat $BASE/rsyncd.pid) 2>/dev/null; sleep 0.5
printf 'port = %s\nuse chroot = false\nuid = root\ngid = root\nmax connections = 32\npid file = %s/rsyncd.pid\n[bench]\n    path = %s/recv\n    read only = false\n' '$RSYNCD_PORT' '$BASE' '$BASE' | tee $BASE/rsyncd.conf >/dev/null
setsid rsync --daemon --config=$BASE/rsyncd.conf </dev/null >/dev/null 2>&1
sleep 0.6
ss -tlnp 2>/dev/null | grep -q ':$RSYNCD_PORT ' && echo rsyncd-listening"
}
stop_rsyncd() {
    "${SSH_R[@]}" "test -f $BASE/rsyncd.pid && kill \$(cat $BASE/rsyncd.pid) 2>/dev/null || true"
}

# ─── One run ─────────────────────────────────────────────────────────────────
run_transfer() { # tool payload run_idx -> appends one JSON line to RESULTS
    local tool="$1" payload="$2" run_idx="$3"
    local ppath bytes mname label run_rel run_dest run_dir
    ppath=$(payload_path "$payload")
    bytes=$(payload_bytes "$payload")
    [[ "$bytes" =~ ^[0-9]+$ ]] \
        || { echo "sender payload byte count is not an unsigned integer" >&2; return 2; }
    mname=$(manifest_name "$payload")
    label="${tool}_${payload}_r${run_idx}"
    run_rel="$RUN_ID/$tool/$payload/r$run_idx"
    run_dest="$BASE/recv/$run_rel"
    run_dir="$BASE/runs/$run_rel"
    "${SSH_R[@]}" "mkdir -p $run_dest $run_dir"

    # Receiver-side sampler + (for atp) the one-shot receiver under time -v.
    local recv_pid_file="$run_dir/recv_run.pid" receiver_command="" sender_command=""
    if [[ "$tool" == atp-rq ]]; then
        receiver_command="nohup env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX $BASE/collect_metrics.sh '$BASE/atp recv' $run_dir/sampler.jsonl </dev/null >/dev/null 2>&1 & echo \$! > $run_dir/sampler.pid
nohup /usr/bin/time -v -o $run_dir/recv_time.txt env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX $BASE/atp recv $run_dest --listen 0.0.0.0:$ATP_PORT --once --transport rq --symbol-size $ATP_RQ_SYMBOL_SIZE --max-block-size '$ATP_RQ_MAX_BLOCK_SIZE' --repair-overhead $ATP_RQ_REPAIR_OVERHEAD --rq-tail-drain-ms $ATP_RQ_TAIL_DRAIN_MS --rq-auth-key-stdin <&0 > $run_dir/recv_out.txt 2>&1 & echo \$! > $recv_pid_file"
        sender_command="env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX bash $BASE/run_one.sh $label $bytes -- env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX $BASE/atp send $BASE/payloads/$ppath $RECEIVER_IP:$ATP_PORT --transport rq --streams $ATP_RQ_STREAMS --symbol-size $ATP_RQ_SYMBOL_SIZE --max-block-size '$ATP_RQ_MAX_BLOCK_SIZE' --repair-overhead $ATP_RQ_REPAIR_OVERHEAD --rq-tail-drain-ms $ATP_RQ_TAIL_DRAIN_MS --rq-auth-key-stdin"
        ssh_secret_stdin_preflight SSH_R_OPTS "$RECEIVER" "$receiver_command"
        ssh_secret_stdin_preflight SSH_S_OPTS "$SENDER" "$sender_command"
    fi
    case "$tool" in
        atp-rq)
            send_rq_auth_secret | "${SSH_R[@]}" "$receiver_command"
            sleep 1 ;;
        atp-quic)
            "${SSH_R[@]}" "nohup env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX $BASE/collect_metrics.sh '$BASE/atp recv' $run_dir/sampler.jsonl </dev/null >/dev/null 2>&1 & echo \$! > $run_dir/sampler.pid
nohup /usr/bin/time -v -o $run_dir/recv_time.txt env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX $BASE/atp recv $run_dest --listen 0.0.0.0:$ATP_PORT --once --transport quic --symbol-size $ATP_RQ_SYMBOL_SIZE --max-block-size '$ATP_RQ_MAX_BLOCK_SIZE' --repair-overhead $ATP_RQ_REPAIR_OVERHEAD --rq-tail-drain-ms $ATP_RQ_TAIL_DRAIN_MS --server-cert $QUIC_CERT --server-key $QUIC_KEY --quic-handshake-timeout-ms $ATP_QUIC_HANDSHAKE_TIMEOUT_MS > $run_dir/recv_out.txt 2>&1 & echo \$! > $recv_pid_file"
            sleep 1 ;;
        atp-tcp)
            "${SSH_R[@]}" "nohup env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX $BASE/collect_metrics.sh '$BASE/atp recv' $run_dir/sampler.jsonl </dev/null >/dev/null 2>&1 & echo \$! > $run_dir/sampler.pid
nohup /usr/bin/time -v -o $run_dir/recv_time.txt env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX $BASE/atp recv $run_dest --listen 0.0.0.0:$ATP_PORT --once --transport tcp > $run_dir/recv_out.txt 2>&1 & echo \$! > $recv_pid_file"
            sleep 1 ;;
        rsync-ssh)
            "${SSH_R[@]}" "nohup env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX $BASE/collect_metrics.sh 'rsync' $run_dir/sampler.jsonl </dev/null >/dev/null 2>&1 & echo \$! > $run_dir/sampler.pid" ;;
        rsyncd)
            "${SSH_R[@]}" "nohup env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX $BASE/collect_metrics.sh 'rsync' $run_dir/sampler.jsonl </dev/null >/dev/null 2>&1 & echo \$! > $run_dir/sampler.pid" ;;
        *)
            echo "unknown tool: $tool" >&2; exit 2 ;;
    esac

    # Sender command.
    local sender_json
    case "$tool" in
        atp-rq)
            sender_json=$(send_rq_auth_secret | "${SSH_S[@]}" "$sender_command") ;;
        atp-quic)
            sender_json=$("${SSH_S[@]}" "env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX bash $BASE/run_one.sh $label $bytes -- env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX $BASE/atp send $BASE/payloads/$ppath $RECEIVER_IP:$ATP_PORT --transport quic --symbol-size $ATP_RQ_SYMBOL_SIZE --max-block-size '$ATP_RQ_MAX_BLOCK_SIZE' --repair-overhead $ATP_RQ_REPAIR_OVERHEAD --rq-tail-drain-ms $ATP_RQ_TAIL_DRAIN_MS --ca $QUIC_CERT --server-name '$ATP_QUIC_SERVER_NAME' --quic-handshake-timeout-ms $ATP_QUIC_HANDSHAKE_TIMEOUT_MS") ;;
        atp-tcp)
            sender_json=$("${SSH_S[@]}" "env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX bash $BASE/run_one.sh $label $bytes -- env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX $BASE/atp send $BASE/payloads/$ppath $RECEIVER_IP:$ATP_PORT --transport tcp") ;;
        rsync-ssh)
            sender_json=$("${SSH_S[@]}" "env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX bash $BASE/run_one.sh $label $bytes -- rsync -aW --inplace -e 'ssh -T -x -o Compression=no -o StrictHostKeyChecking=accept-new -c aes128-gcm@openssh.com' $BASE/payloads/$ppath root@$RECEIVER_IP:$run_dest/") ;;
        rsyncd)
            sender_json=$("${SSH_S[@]}" "env -u ATP_RQ_AUTH_KEY_HEX -u RQ_AUTH_KEY_HEX bash $BASE/run_one.sh $label $bytes -- rsync -aW --inplace --port $RSYNCD_PORT $BASE/payloads/$ppath rsync://$RECEIVER_IP/bench/$run_rel/") ;;
        *)
            echo "unknown tool: $tool" >&2; exit 2 ;;
    esac

    # Wait for the atp receiver to finish committing (it exits on --once).
    if [[ "$tool" == atp-* ]]; then
        "${SSH_R[@]}" "for i in \$(seq 1 120); do kill -0 \$(cat $recv_pid_file) 2>/dev/null || exit 0; sleep 0.5; done; exit 1" \
            || note "WARN: atp receiver still alive after 60s"
    fi

    # Stop sampler, fetch receiver metrics.
    "${SSH_R[@]}" "kill \$(cat $run_dir/sampler.pid) 2>/dev/null || true"
    local recv_sampler recv_time_json=null
    recv_sampler=$("${SSH_R[@]}" "python3 - <<'PY'
import json
peak_rss=avg_rss=peak_cpu=avg_cpu=peak_load=0.0; n=0
try:
    for line in open('$run_dir/sampler.jsonl'):
        s=json.loads(line); n+=1
        peak_rss=max(peak_rss,s['rss_kb']); avg_rss+=s['rss_kb']
        peak_cpu=max(peak_cpu,s['cpu_pct']); avg_cpu+=s['cpu_pct']
        peak_load=max(peak_load,s['load1'])
except FileNotFoundError: pass
if n: avg_rss/=n; avg_cpu/=n
print(json.dumps({'samples':n,'peak_rss_kb':peak_rss,'avg_rss_kb':round(avg_rss,1),'peak_cpu_pct':peak_cpu,'avg_cpu_pct':round(avg_cpu,1),'peak_load1':peak_load}))
PY")
    if [[ "$tool" == atp-* ]]; then
        recv_time_json=$("${SSH_R[@]}" "python3 - <<'PY'
import json,re
d={}
try:
    t=open('$run_dir/recv_time.txt').read()
    m=re.search(r'Maximum resident set size.*: (\d+)',t)
    if m: d['max_rss_kb']=int(m.group(1))
    m=re.search(r'Elapsed \(wall clock\).*: ([\d:.]+)',t)
    if m:
        p=[float(x) for x in m.group(1).split(':')]
        d['wall_s']=p[0]*3600+p[1]*60+p[2] if len(p)==3 else p[0]*60+p[1] if len(p)==2 else p[0]
except FileNotFoundError: pass
print(json.dumps(d) if d else 'null')
PY")
    fi

    local resource_guard
    resource_guard=$(SENDER_JSON="$sender_json" RECEIVER_SAMPLER_JSON="$recv_sampler" RECEIVER_TIME_JSON="$recv_time_json" \
        MAX_LOAD_PER_CORE="$MAX_LOAD_PER_CORE" MAX_SENDER_RSS_MB="$MAX_SENDER_RSS_MB" MAX_RECEIVER_RSS_MB="$MAX_RECEIVER_RSS_MB" \
        SENDER_CORES="$SENDER_CORES" RECEIVER_CORES="$RECEIVER_CORES" python3 - <<'PY'
import json
import os


def number(value, default=0.0):
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


sender = json.loads(os.environ["SENDER_JSON"])
sampler = json.loads(os.environ["RECEIVER_SAMPLER_JSON"])
receiver_time_raw = os.environ["RECEIVER_TIME_JSON"]
receiver_time = {} if receiver_time_raw == "null" else json.loads(receiver_time_raw)

max_load_per_core = number(os.environ["MAX_LOAD_PER_CORE"])
max_sender_rss_mb = number(os.environ["MAX_SENDER_RSS_MB"])
max_receiver_rss_mb = number(os.environ["MAX_RECEIVER_RSS_MB"])
sender_cores = max(1.0, number(os.environ["SENDER_CORES"], 1.0))
receiver_cores = max(1.0, number(os.environ["RECEIVER_CORES"], 1.0))

checks = []


def add_check(name, observed, limit, unit):
    checks.append(
        {
            "name": name,
            "observed": round(observed, 3),
            "limit": round(limit, 3),
            "unit": unit,
            "passed": observed <= limit,
        }
    )


if max_load_per_core > 0:
    sender_load_limit = sender_cores * max_load_per_core
    receiver_load_limit = receiver_cores * max_load_per_core
    sender_load = max(number(sender.get("load1_start")), number(sender.get("load1_end")))
    receiver_load = number(sampler.get("peak_load1"))
    add_check("sender_load1", sender_load, sender_load_limit, "loadavg")
    add_check("receiver_load1", receiver_load, receiver_load_limit, "loadavg")

if max_sender_rss_mb > 0:
    add_check("sender_peak_rss", number(sender.get("max_rss_kb")) / 1024.0, max_sender_rss_mb, "MiB")

if max_receiver_rss_mb > 0:
    receiver_rss_kb = max(number(receiver_time.get("max_rss_kb")), number(sampler.get("peak_rss_kb")))
    add_check("receiver_peak_rss", receiver_rss_kb / 1024.0, max_receiver_rss_mb, "MiB")

print(
    json.dumps(
        {
            "schema_version": "atp-bench-resource-guard-v1",
            "ok": all(check["passed"] for check in checks),
            "checks": checks,
            "configured": {
                "max_load_per_core": max_load_per_core,
                "max_sender_rss_mb": max_sender_rss_mb,
                "max_receiver_rss_mb": max_receiver_rss_mb,
            },
        },
        separators=(",", ":"),
    )
)
PY
    )

    # Bit-for-bit verification against the manifest. Always recorded.
    local verify_ok=false
    if "${SSH_R[@]}" "cd $run_dest && sha256sum --status -c $BASE/manifests/$mname.sha256"; then
        verify_ok=true
    fi

    echo "{\"tool\":\"$tool\",\"payload\":\"$payload\",\"run\":$run_idx,\"run_id\":\"$RUN_ID\",\"receiver_dest\":\"$run_dest\",\"receiver_run_dir\":\"$run_dir\",\"verify_ok\":$verify_ok,\"sender\":$sender_json,\"receiver_sampler\":$recv_sampler,\"receiver_time\":$recv_time_json,\"resource_guard\":$resource_guard}" >> "$RESULTS"
    local wall
    wall=$(echo "$sender_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["wall_s"])')
    note "$label: wall=${wall}s verify_ok=$verify_ok"
    [[ "$verify_ok" == true ]] || note "!!! VERIFY FAILED for $label"
    if [[ "$(echo "$resource_guard" | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["ok"]).lower())')" != true ]]; then
        note "!!! RESOURCE GUARD FAILED for $label: $resource_guard"
        exit 1
    fi
}

# ─── Main loop ───────────────────────────────────────────────────────────────
for tool in "${TOOL_LIST[@]}"; do
    [[ "$tool" == atp-rq ]] && ensure_rq_auth_secret
    [[ "$tool" == rsyncd ]] && start_rsyncd
    for payload in "${PAYLOAD_LIST[@]}"; do
        # Responsiveness guard before each series.
        for host_cmd in SSH_S SSH_R; do
            declare -n ssh_ref=$host_cmd
            load=$("${ssh_ref[@]}" "cut -d' ' -f1 /proc/loadavg")
            cores=$("${ssh_ref[@]}" nproc)
            if python3 -c "exit(0 if float('$load') < float('$MAX_LOAD_PER_CORE')*$cores else 1)"; then :; else
                note "ABORT series: $host_cmd loadavg $load exceeds ${MAX_LOAD_PER_CORE}x$cores cores"; exit 1
            fi
        done
        run_transfer "$tool" "$payload" 0   # warmup
        for r in $(seq 1 "$RUNS"); do run_transfer "$tool" "$payload" "$r"; done
    done
    [[ "$tool" == rsyncd ]] && stop_rsyncd
    [[ "$tool" == atp-rq ]] && clear_rq_auth_secret
done

note "done: $RESULTS"
note "generate the report with: python3 $SCRIPT_DIR/report.py $RESULTS > $OUT/report.md"
