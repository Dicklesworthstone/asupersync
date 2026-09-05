#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${RUN_ID:-atp-session-$(date -u +%Y%m%dT%H%M%SZ)}"
OUTPUT_ROOT="${OUTPUT_ROOT:-target/atp-session-negotiation-e2e/${RUN_ID}}"
LOG_FILE="${OUTPUT_ROOT}/events.ndjson"
TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_atp_session_negotiation_e2e}"
SESSION_CARGO_HOME="${ATP_SESSION_CARGO_HOME:-/tmp/rch_cargo_home_asupersync_reality}"
# Keep child logs outside RCH's disposable per-command source root. The test
# appends a unique process/time directory and never deletes previous artifacts.
SESSION_ARTIFACT_ROOT="${ATP_SESSION_ARTIFACT_ROOT:-/tmp/asupersync-atp-session-negotiation-artifacts}"
SESSION_WORKER="${ATP_SESSION_RCH_WORKER:-${RCH_WORKER:-}}"
CURRENT_OVERLAY_FINGERPRINT=""
PRE_REPAIR_BASE="97c5b2d02146d8cf60cfba57241a852e68ae4926"
PRE_REPAIR_CODEC_SHA="a724a6138cf7a6239f6af721de7484670b9cc2f5a539b616e545b50d0b99a8a3"
OLD_BINARY="${SESSION_ARTIFACT_ROOT}/mixed-build-${RUN_ID}-$$/pre-repair-peer"
export RCH_REQUIRE_REMOTE=1
export RCH_VISIBILITY="${RCH_VISIBILITY:-verbose}"

mkdir -p "${OUTPUT_ROOT}"

log_event() {
  local status="$1"
  local stage="$2"
  local detail="$3"
  printf '{"run_id":"%s","status":"%s","stage":"%s","detail":"%s","target_dir":"%s"}\n' \
    "${RUN_ID}" "${status}" "${stage}" "${detail}" "${TARGET_DIR}" | tee -a "${LOG_FILE}"
}

run_stage() {
  local stage="$1"
  shift
  log_event "start" "${stage}" "$*"
  local status=0
  "$@" 2>&1 | tee "${OUTPUT_ROOT}/${stage}.log" || status=$?
  if [[ "${status}" != "0" ]]; then
    log_event "fail" "${stage}" "terminal_exit=${status}; first output retained"
    return "${status}"
  fi
  log_event "pass" "${stage}" "$*"
}

verify_remote_stage() {
  local stage="$1"
  local base="$2"
  local source_kind="${3:-current}"
  local expected_overlay=""
  if [[ "${source_kind}" == "current" ]]; then
    expected_overlay="${CURRENT_OVERLAY_FINGERPRINT}"
  elif [[ "${source_kind}" != "pre-repair" ]]; then
    log_event "fail" "source-provenance" "unknown source kind: ${source_kind}"
    return 1
  fi
  local verified_receipt verified_worker verified_overlay
  verified_receipt="$(python3 - "${OUTPUT_ROOT}/${stage}.log" "${SESSION_WORKER}" "${base}" \
    "${expected_overlay}" "${stage}" <<'PY'
import pathlib, re, sys
path, worker, base, expected_overlay, stage = sys.argv[1:]
text = re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(path).read_text())
selected = re.findall(r"Selected worker: ([A-Za-z0-9_.-]+) at ", text)
terminal = re.findall(r"^\[RCH\] remote ([A-Za-z0-9_.-]+) \([^\n]+\)$", text, re.M)
receipts = re.findall(r"^\[RCH\] clean-overlay receipt: base=([0-9a-f]{40}) overlay-fingerprint=([0-9a-f]{64})$", text, re.M)
assert len(selected) == 1, ("selected worker ambiguous/absent", selected)
if worker:
    assert selected == [worker], ("selected worker mismatch", selected, worker)
assert terminal == selected, ("terminal remote worker mismatch/absence", terminal, selected)
assert len(receipts) == 1 and receipts[0][0] == base, ("source receipt mismatch/absence", receipts, base)
if expected_overlay:
    assert receipts[0][1] == expected_overlay, ("current source overlay changed between stages", receipts[0][1], expected_overlay)
assert re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed;", text), "nonzero terminal test result required"
if stage == "unit-session-state-machine":
    assert re.search(r"test result: ok\. 24 passed; 0 failed; 0 ignored;", text), "all 24 session unit tests must execute"
print(f"verified_remote_stage worker={selected[0]} base={base} overlay={receipts[0][1]}", file=sys.stderr)
print(selected[0], receipts[0][1])
PY
)"
  read -r verified_worker verified_overlay <<< "${verified_receipt}"
  # No operator pin is required: learn it only from the first successful
  # required current stage's actual selection, terminal and source receipts.
  SESSION_WORKER="${verified_worker}"
  if [[ "${source_kind}" == "current" ]]; then
    CURRENT_OVERLAY_FINGERPRINT="${verified_overlay}"
  fi
  log_event "pass" "worker-pin" "stage=${stage}; verified_worker=${SESSION_WORKER}"
}

run_remote_command() {
  # Expand at invocation, after the previous stage may have captured the pin.
  # An empty first-stage pin gives RCH normal strict admission/selection.
  # Clear the plural alias because RCH otherwise merges both worker sets.
  env RCH_WORKER="${SESSION_WORKER}" RCH_WORKERS= NO_COLOR=1 "$@"
}

verify_fixture_sources() {
  python3 - "${OUTPUT_ROOT}/integration-session-e2e.log" "${CURRENT_CODEC_SHA}" \
    "${SESSION_SOURCE_SHA}" "${TEST_SOURCE_SHA}" <<'PY'
import json, pathlib, re, sys
path, codec, session, test = sys.argv[1:]
text = re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(path).read_text())
rows = []
for line in text.splitlines():
    start = line.find("{")
    if start < 0:
        continue
    try:
        row = json.loads(line[start:])
    except json.JSONDecodeError:
        continue
    if row.get("scenario_id") == "native_two_process_extension_exchange":
        rows.append(row)
assert len(rows) == 1, ("missing/ambiguous native fixture receipt", len(rows))
summary = rows[0]
assert summary["result"] == "pass" and summary["child_processes"] == 4
assert summary["negotiated_sessions"] == 2 and len(summary["scenarios"]) == 2
assert {row["scenario"] for row in summary["scenarios"]} == {"canonical_sender", "historical_sender"}
binary = summary["test_binary_sha256"]
assert re.fullmatch(r"[0-9a-f]{64}", binary), "current parent executable identity absent"
children = []
for scenario in summary["scenarios"]:
    for role in ("sender", "receiver"):
        child = scenario[role]
        assert child["role"] == role and child["scenario_id"] == scenario["scenario"]
        assert child["codec_source_sha256"] == codec, "fixture codec source mismatch"
        assert child["session_source_sha256"] == session, "fixture session source mismatch"
        assert child["test_source_sha256"] == test, "fixture harness source mismatch"
        assert child["binary_sha256"] == binary, "fixture child/parent executable mismatch"
        children.append(child)
assert len(children) == 4
print(f"verified_fixture_sources children=4 executable={binary} codec={codec} session={session} test={test}")
PY
}

# Parse only executable-emitted receipts, and require the explicitly selected
# ignored test to pass. Missing artifacts or filtered helpers are failures.
mixed_receipt() {
  local stage="$1"
  local mode="$2"
  python3 - "${OUTPUT_ROOT}/${stage}.log" "${mode}" "${OLD_BINARY}" \
    "${PRE_REPAIR_BASE}" "${PRE_REPAIR_CODEC_SHA}" "${CURRENT_CODEC_SHA}" \
    "${SESSION_SOURCE_SHA}" "${TEST_SOURCE_SHA}" <<'PY'
import json, pathlib, re, sys
path, mode, binary, old_base, old_codec, current_codec, session, test = sys.argv[1:]
text = re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(path).read_text())
name = "prepare_pre_repair_peer_binary" if mode == "prepare" else "mixed_codec_two_process_extension_exchange"
marker = "pre_repair_peer_prepared" if mode == "prepare" else name
assert re.search(rf"test extension_wire::{name} \.\.\.[\s\S]*?\bok\n", text), "named helper did not pass"
assert re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", text), "one executed helper required"
rows = []
for line in text.splitlines():
    start = line.find("{")
    if start < 0:
        continue
    try:
        row = json.loads(line[start:])
    except json.JSONDecodeError:
        continue
    if row.get("scenario_id") == marker:
        rows.append(row)
assert len(rows) == 1, ("missing/ambiguous executable receipt", marker, len(rows))
row = rows[0]
assert row["result"] == "pass" and row["historical_released_binary_executed"] is False
if mode == "prepare":
    assert row["binary_path"] == binary and row["source_base"] == old_base
    assert row["codec_source_sha256"] == old_codec
    assert row["session_source_sha256"] == session and row["test_source_sha256"] == test
    assert 0 < row["binary_bytes"] <= 512 * 1024 * 1024
    assert 1 <= row["old_noncanonical_encode_attempts"] <= 128
    assert re.fullmatch(r"[0-9a-f]{64}", row["binary_sha256"])
    print(row["binary_sha256"])
else:
    assert row["child_processes"] == 4 and row["negotiated_sessions"] == 2
    assert row["old_codec_source_sha256"] == old_codec
    assert row["current_codec_source_sha256"] == current_codec
    assert row["old_binary_sha256"] != row["current_binary_sha256"]
    assert {r["scenario"] for r in row["scenarios"]} == {"mixed_old_sender", "mixed_old_receiver"}
    print("verified_mixed_binary_receipt old=" + row["old_binary_sha256"] + " current=" + row["current_binary_sha256"])
PY
}

if ! command -v rch >/dev/null 2>&1; then
  log_event "blocked" "preflight" "rch not found"
  exit 127
fi

log_event "start" "preflight" "ATP session negotiation e2e"

# Capture installed capability evidence; example/prose mentions do not count
# as option declarations. Unsupported clients stop before any Cargo command.
run_stage "rch-version" rch --version
run_stage "rch-exec-help" rch exec --help
run_stage "rch-capabilities" rch capabilities --json
run_stage "rch-binary-identity" sha256sum "$(command -v rch)"
if ! grep -q '[^[:space:]]' "${OUTPUT_ROOT}/rch-version.log"; then
  log_event "blocked" "clean-overlay-capability" "empty installed version identity; no proof command emitted"
  exit 2
fi
for flag in --base --clean-overlay --overlay-path --no-overlay; do
  if ! awk -v flag="${flag}" '
    /^Options:/ { options = 1; next }
    /^[^[:space:]]/ { options = 0 }
    options && /^[[:space:]]+(-[[:alnum:]], )?--/ {
      for (i = 1; i <= NF; i++) if ($i == flag) found = 1
    }
    END { exit !found }
  ' "${OUTPUT_ROOT}/rch-exec-help.log"; then
    log_event "blocked" "clean-overlay-capability" "missing option declaration: ${flag}; no proof command emitted"
    exit 2
  fi
done
if [[ ( -n "${SESSION_WORKER}" && ! "${SESSION_WORKER}" =~ ^[A-Za-z0-9_.-]+$ ) || "${SESSION_ARTIFACT_ROOT}" != /* ||
      ! "${RUN_ID}" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  log_event "blocked" "mixed-binary-preflight" "worker override must name one worker; require absolute artifact root and safe run id"
  exit 2
fi
python3 - "${OUTPUT_ROOT}/rch-capabilities.log" <<'PY'
import json, sys
with open(sys.argv[1]) as source:
    response = json.load(source)
assert response["success"] is True
data = response["data"]
assert data["contract_version"] == "rch.capabilities.v1"
env = {row["name"]: row["effect"] for row in data["env_vars"]}
assert "RCH_WORKER" in env and "refused" in env["RCH_WORKER"], "installed worker-pin refusal capability absent"
assert "RCH_REQUIRE_REMOTE" in env and "Fail closed" in env["RCH_REQUIRE_REMOTE"], "strict remote capability absent"
PY
if [[ "$(git branch --show-current)" != "main" || -n "$(git rev-parse --show-prefix)" ]]; then
  log_event "blocked" "source" "run from project root on main"
  exit 2
fi
BASE_COMMIT="$(git rev-parse --verify "${RCH_BASE:-HEAD}^{commit}")"
git rev-parse --verify "${PRE_REPAIR_BASE}^{commit}" >/dev/null
CURRENT_CODEC_SHA="$(sha256sum src/net/atp/protocol/codec.rs | cut -d ' ' -f 1)"
SESSION_SOURCE_SHA="$(sha256sum src/net/atp/protocol/session.rs | cut -d ' ' -f 1)"
TEST_SOURCE_SHA="$(sha256sum tests/atp_session_negotiation.rs | cut -d ' ' -f 1)"
run_stage "source-identities" sha256sum src/net/atp/protocol/codec.rs \
  src/net/atp/protocol/session.rs tests/atp_session_negotiation.rs \
  scripts/run_atp_session_negotiation_e2e.sh
# Coordinate these exact Agent Mail reservations before execution on dirty main.
# The codec owner grants a read-overlay; the old build NEVER overlays its codec.
RCH_COMMAND=(rch exec --base "${BASE_COMMIT}" --clean-overlay
  --overlay-path src/net/atp/protocol/codec.rs
  --overlay-path src/net/atp/protocol/session.rs
  --overlay-path tests/atp_session_negotiation.rs
  --overlay-path scripts/run_atp_session_negotiation_e2e.sh)
RCH_OLD_COMMAND=(rch exec --base "${PRE_REPAIR_BASE}" --clean-overlay
  --overlay-path src/net/atp/protocol/session.rs
  --overlay-path tests/atp_session_negotiation.rs
  --overlay-path scripts/run_atp_session_negotiation_e2e.sh)
log_event "pass" "clean-overlay-capability" "base=${BASE_COMMIT}; old_base=${PRE_REPAIR_BASE}; worker=${SESSION_WORKER}; exact owned paths selected; remote required"

if [[ "${ATP_SESSION_RUN_LIB_UNIT:-1}" == "1" ]]; then
  run_stage "unit-session-state-machine" \
    run_remote_command "${RCH_COMMAND[@]}" -- env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_HOME="${SESSION_CARGO_HOME}" \
      CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' \
      cargo test -p asupersync --locked \
      --lib net::atp::protocol::session::tests -- --nocapture
  verify_remote_stage "unit-session-state-machine" "${BASE_COMMIT}"
else
  log_event "skip" "unit-session-state-machine" \
    "explicit integration-only run; required unit proof omitted"
fi

run_stage "integration-session-e2e" \
  run_remote_command "${RCH_COMMAND[@]}" -- env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_HOME="${SESSION_CARGO_HOME}" \
    CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' \
    ASUPERSYNC_TEST_ARTIFACTS_DIR="${SESSION_ARTIFACT_ROOT}" cargo test -p asupersync \
    --locked --features tls --test atp_session_negotiation -- --nocapture
verify_remote_stage "integration-session-e2e" "${BASE_COMMIT}"

# A missing TLS feature or accidentally filtered/empty test suite must not
# manufacture process proof. This receipt is emitted only after the parent
# checks both child-process pairs, received frames, refusals and transcripts.
if ! grep -F '"scenario_id":"native_two_process_extension_exchange"' \
    "${OUTPUT_ROOT}/integration-session-e2e.log" \
    | grep -F '"child_processes":4' | grep -F '"negotiated_sessions":2' \
    | grep -F '"result":"pass"' >/dev/null; then
  log_event "fail" "native-extension-process-proof" "required nonzero process result absent"
  exit 1
fi
if ! grep -F 'test result: ok. 9 passed; 0 failed; 3 ignored;' \
    "${OUTPUT_ROOT}/integration-session-e2e.log" >/dev/null; then
  log_event "fail" "native-extension-process-proof" "expected nine parent tests and three explicitly invoked helpers; inspect actual counts"
  exit 1
fi
verify_fixture_sources

# Retain a distinct executable with create_new and bounded streaming copy/hash
# inside the existing Rust helper. Its source is the pre-repair codec plus the
# current parser/harness overlays, not an independently released historical app.
run_stage "prepare-pre-repair-peer" \
  run_remote_command "${RCH_OLD_COMMAND[@]}" -- env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_HOME="${SESSION_CARGO_HOME}" \
    CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' \
    ASUPERSYNC_EXTENSION_EXPORT_BINARY="${OLD_BINARY}" cargo test -p asupersync \
    --locked --features tls --test atp_session_negotiation \
    extension_wire::prepare_pre_repair_peer_binary -- --exact --ignored --nocapture --test-threads=1
verify_remote_stage "prepare-pre-repair-peer" "${PRE_REPAIR_BASE}" "pre-repair"
OLD_BINARY_SHA="$(mixed_receipt "prepare-pre-repair-peer" "prepare")"

run_stage "mixed-codec-session-e2e" \
  run_remote_command "${RCH_COMMAND[@]}" -- env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_HOME="${SESSION_CARGO_HOME}" \
    CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' \
    ASUPERSYNC_TEST_ARTIFACTS_DIR="${SESSION_ARTIFACT_ROOT}" \
    ASUPERSYNC_EXTENSION_OLD_BINARY="${OLD_BINARY}" \
    ASUPERSYNC_EXTENSION_OLD_BINARY_SHA="${OLD_BINARY_SHA}" cargo test -p asupersync \
    --locked --features tls --test atp_session_negotiation \
    extension_wire::mixed_codec_two_process_extension_exchange -- --exact --ignored --nocapture --test-threads=1
verify_remote_stage "mixed-codec-session-e2e" "${BASE_COMMIT}"
mixed_receipt "mixed-codec-session-e2e" "mixed"

log_event "pass" "summary" "ATP session negotiation stages complete; unit_mode=${ATP_SESSION_RUN_LIB_UNIT:-1}; fixture_parent=9_pass_3_helpers_ignored; separately_executed_helpers=2; native_children=8; negotiated_sessions=4; pre-repair_codec_build_not_historical_release"
