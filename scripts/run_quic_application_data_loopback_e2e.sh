#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == --kernel-controller ]]; then
  if [[ "$#" != 3 ]]; then
    echo "refused: --kernel-controller requires the actual test executable and its fresh artifact directory" >&2
    exit 2
  fi
  exec python3 - "$2" "$3" "$ROOT" <<'PY_KERNEL'
import decimal, hashlib, json, os, pathlib, re, selectors, signal, subprocess, sys, time

executable, artifact_arg, root_arg = sys.argv[1:]
artifacts, root = pathlib.Path(artifact_arg), pathlib.Path(root_arg)
entry = "authenticated_managed_kernel_backpressure"
parent = json.loads((artifacts / "kernel-parent.json").read_text())
assert os.geteuid() == 0, "declared_unavailable: isolated kernel setup needs noninteractive sudo"
assert os.readlink("/proc/self/ns/net") != os.readlink(f"/proc/{parent['pid']}/ns/net"), "controller must be in a fresh network namespace"
paths = dict(test="tests/quic_h3_live_udp.rs", runner="scripts/run_quic_application_data_loopback_e2e.sh", manager="src/net/quic_native/connection_manager.rs", managed="src/net/quic_native/managed_endpoint.rs", owner="src/net/quic_native/udp_connection.rs", handshake_driver="src/net/quic_native/handshake_driver.rs", endpoint="src/net/quic_native/endpoint.rs", application="src/net/quic_native/endpoint_api.rs", exports="src/net/quic_native/mod.rs")
assert {key: hashlib.sha256((root / path).read_bytes()).hexdigest() for key, path in paths.items()} == parent["source"], "compiled/actual controller source identity"

def file_sha(path):
    path = pathlib.Path(path)
    size = path.stat().st_size
    assert 0 < size <= 512 * 1024 * 1024, (path, size)
    digest, total = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while data := stream.read(64 * 1024):
            total += len(data)
            assert total <= size
            digest.update(data)
    assert total == size
    return digest.hexdigest()

assert file_sha(executable) == parent["executable_sha256"], "actual executable differs from the parent"
command_log = (artifacts / "kernel-commands.log").open("x")
peers = []
started = time.monotonic()

def log_event(value):
    line = json.dumps(value, sort_keys=True)
    command_log.write(line + "\n")
    command_log.flush()
    print(line, flush=True)

def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=3)
    log_event(dict(command=list(args), exit=result.returncode, stdout=result.stdout, stderr=result.stderr))
    assert result.returncode == 0, (args, result.returncode, result.stderr)
    return result.stdout

def write_receipt(name, value):
    with (artifacts / name).open("x") as output:
        json.dump(value, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())

def read_receipt(name):
    path = artifacts / name
    if not path.exists():
        return None
    data = path.read_bytes()
    assert len(data) <= 64 * 1024
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return None  # A create_new peer writer may still be completing.

def watch():
    assert time.monotonic() - started < 50, "bounded isolated kernel controller watchdog"
    for role, process in peers:
        status = process.poll()
        assert status is None or status == 0, ("actual peer failed", role, status)

def wait_receipt(name):
    while True:
        watch()
        value = read_receipt(name)
        if value is not None:
            return value
        time.sleep(0.01)

def literal(value):
    if re.fullmatch(r"(?:\\x[0-9a-f]{2})*", value):
        return bytes.fromhex(value.replace("\\x", ""))
    assert "\\" not in value, "unsupported or truncated strace literal"
    return value.encode("ascii")

def packet_event(body, time_ns, tid, local, peer, cid):
    call = re.match(r"(sendto|sendmsg|sendmmsg)\(\d+<UDP:\[([^]]+)\]>", body)
    if call is None or call[2].split("->", 1)[0] != local:
        return None
    addresses = re.findall(r'sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]*)"\)', body)
    if len(addresses) != 1 or f"{literal(addresses[0][1]).decode('ascii')}:{addresses[0][0]}" != peer:
        return None
    if call[1] == "sendto":
        chunks = re.findall(r'^sendto\([^,]+, "([^"]*)", (\d+),', body)
    else:
        chunks = re.findall(r'iov_base="([^"]*)", iov_len=(\d+)', body)
        if call[1] == "sendmmsg" and body.count("msg_hdr=") != 1:
            return None
    if len(chunks) != 1:
        return None
    data = literal(chunks[0][0])
    if len(data) != int(chunks[0][1]) or not 20 < len(data) <= 1500:
        return None
    if data[0] & 0xC0 != 0x40 or data[1:1 + len(cid)] != cid:
        return None  # Only protected 1-RTT output to the authenticated peer.
    result = re.search(r" = (-?\d+)(?: ([A-Z][A-Z0-9_]+))?", body)
    if result is None:
        return None
    sent = int(result[1])
    success = sent == (1 if call[1] == "sendmmsg" else len(data))
    blocked = sent == -1 and result[2] == "EAGAIN"
    if not (success or blocked):
        return None
    return dict(tid=tid, time_ns=time_ns, syscall=call[1], ciphertext_hex=data.hex(), ciphertext_sha256=hashlib.sha256(data).hexdigest(), ciphertext_bytes=len(data), success=success, errno="EAGAIN" if blocked else None, raw_call=body)

def read_events(local, peer, cid, tids):
    events = []
    traces = sorted(artifacts.glob("kernel-client.syscall.*"))
    assert len(traces) <= 64, "bounded owned trace threads"
    for path in traces:
        tid = int(path.name.rsplit(".", 1)[1])
        if tid not in tids:
            continue
        assert path.stat().st_size <= 16 * 1024 * 1024, "bounded raw syscall trace"
        pending = None
        for ordinal, line in enumerate(path.read_text().splitlines()):
            parsed = re.match(r"(\d+\.\d+)\s+(.*)", line)
            if parsed is None:
                continue
            stamp = int(decimal.Decimal(parsed[1]) * 1_000_000_000)
            body = parsed[2]
            if body.endswith("<unfinished ...>"):
                pending = body.removesuffix("<unfinished ...>")
                continue
            resumed = re.match(r"<\.\.\. (\w+) resumed>(.*)", body)
            if resumed:
                assert pending is not None and pending.startswith(resumed[1] + "("), "matching per-thread unfinished syscall required"
                body, pending = pending + resumed[2], None
            event = packet_event(body, stamp, tid, local, peer, cid)
            if event is not None:
                event.update(trace=path.name, ordinal=ordinal)
                events.append(event)
    return sorted(events, key=lambda event: (event["time_ns"], event["tid"], event["ordinal"]))

def collect_tids(pid, tids):
    directory = pathlib.Path(f"/proc/{pid}/task")
    try:
        entries = list(directory.iterdir())
    except FileNotFoundError:
        return
    for path in entries:
        try:
            status = (path / "status").read_text()
        except FileNotFoundError:
            continue
        assert re.search(rf"^Tgid:\s+{pid}$", status, re.M), "trace thread must belong to the actual client process"
        tids.add(int(path.name))

def interrupted(signum, _frame):
    raise RuntimeError(f"owned controller interrupted by signal {signum}")

signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
try:
    assert {row["ifname"] for row in json.loads(command("ip", "-j", "link"))} == {"lo"}, "fresh namespace only"
    command("strace", "--version")
    command("ip", "link", "set", "lo", "up")
    server_env = dict(os.environ, ASUPERSYNC_MANAGED_QUIC_KERNEL_ROLE="server", ASUPERSYNC_MANAGED_QUIC_KERNEL_DIR=str(artifacts), ATP_QUIC_TRACE="1")
    anchor = """import os,subprocess,sys
print(os.getpid(),flush=True)
assert sys.stdin.readline().strip()=='configure'
for args in [['ip','link','set','lo','up'],['ip','addr','add','192.0.2.2/24','dev','qs76'],['ip','link','set','qs76','up']]:
    subprocess.run(args,check=True,timeout=3)
with open(sys.argv[2],'xb') as output:
    os.dup2(output.fileno(),1)
os.execv(sys.argv[1],[sys.argv[1],'--exact','authenticated_managed_kernel_backpressure','--ignored','--nocapture','--test-threads=1'])
"""
    server_stderr = (artifacts / "kernel-server.stderr.log").open("xb")
    server_process = subprocess.Popen(["unshare", "--net", "python3", "-u", "-c", anchor, executable, str(artifacts / "kernel-server.stdout.log")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=server_stderr, text=True, env=server_env, start_new_session=True)
    peers.append(("server", server_process))
    selector = selectors.DefaultSelector()
    selector.register(server_process.stdout, selectors.EVENT_READ)
    assert selector.select(3), "actual server namespace PID"
    assert int(server_process.stdout.readline()) == server_process.pid
    selector.close()
    assert os.readlink(f"/proc/{server_process.pid}/ns/net") != os.readlink("/proc/self/ns/net")
    command("ip", "link", "add", "qc76", "type", "veth", "peer", "name", "qs76")
    command("ip", "link", "set", "qs76", "netns", str(server_process.pid))
    command("ip", "addr", "add", "192.0.2.1/24", "dev", "qc76")
    command("ip", "link", "set", "qc76", "up")
    server_process.stdin.write("configure\n")
    server_process.stdin.flush()
    ready = wait_receipt("kernel-server-ready.json")
    assert ready["pid"] == server_process.pid and ready["source"] == parent["source"] and ready["executable_sha256"] == parent["executable_sha256"]
    mac = json.loads(command("nsenter", "-t", str(server_process.pid), "-n", "ip", "-j", "link", "show", "dev", "qs76"))[0]["address"]
    assert re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac)
    command("ip", "neigh", "replace", "192.0.2.2", "lladdr", mac, "nud", "permanent", "dev", "qc76")
    client_env = dict(os.environ, ASUPERSYNC_MANAGED_QUIC_KERNEL_ROLE="client", ASUPERSYNC_MANAGED_QUIC_KERNEL_DIR=str(artifacts), ASUPERSYNC_MANAGED_QUIC_SERVER_ADDR=ready["server_addr"], ATP_QUIC_TRACE="1")
    client_stdout = (artifacts / "kernel-client.stdout.log").open("xb")
    client_stderr = (artifacts / "kernel-client.stderr.log").open("xb")
    tracer = subprocess.Popen(["strace", "-ff", "-ttt", "-yy", "-xx", "-v", "-s", "2048", "-e", "trace=sendto,sendmsg,sendmmsg", "-o", str(artifacts / "kernel-client.syscall"), executable, "--exact", entry, "--ignored", "--nocapture", "--test-threads=1"], stdout=client_stdout, stderr=client_stderr, env=client_env, start_new_session=True)
    peers.append(("client-tracer", tracer))
    client = wait_receipt("kernel-client-healthy.json")
    server = wait_receipt("kernel-server-healthy.json")
    for identity in (client, server):
        assert identity["source"] == parent["source"] and identity["executable_sha256"] == parent["executable_sha256"]
        assert identity["healthy_round"]["received_bytes"] == 535 and identity["healthy_round"]["fin"]
        assert identity["alpn"] == "asupersync-managed-test"
        assert identity["requested_send_buffer"] == 8192 and identity["applied_send_buffer"] >= 8192
    assert len({parent["pid"], client["pid"], server["pid"]}) == 3 and server["pid"] == server_process.pid
    assert client["local_addr"] == server["peer_addr"] and client["peer_addr"] == server["local_addr"]
    assert client["local_cid"] == server["peer_cid"] and client["peer_cid"] == server["local_cid"]
    assert client["netns"] != server["netns"] and client["netns"] == os.readlink("/proc/self/ns/net")
    cid = bytes.fromhex(re.fullmatch(r"ConnectionId\(([0-9a-f]+)\)", client["peer_cid"])[1])
    command("tc", "qdisc", "add", "dev", "qc76", "clsact")
    command("tc", "filter", "add", "dev", "qc76", "ingress", "protocol", "arp", "pref", "1", "flower", "action", "drop")
    command("sysctl", "-w", "net.ipv4.neigh.qc76.retrans_time_ms=10000")
    command("ip", "neigh", "replace", "192.0.2.2", "nud", "incomplete", "dev", "qc76")
    blocked = dict(client_pid=client["pid"], peer_addr=client["peer_addr"], time_ns=time.time_ns(), neighbour=json.loads(command("ip", "-j", "neigh", "show", "dev", "qc76")))
    assert any(row["dst"] == "192.0.2.2" and "INCOMPLETE" in row["state"] for row in blocked["neighbour"])
    write_receipt("kernel-blocked.json", blocked)
    tids, witness = set(), None
    while witness is None:
        watch()
        collect_tids(client["pid"], tids)
        events = [event for event in read_events(client["local_addr"], client["peer_addr"], cid, tids) if event["time_ns"] >= blocked["time_ns"]]
        for index, event in enumerate(events):
            if event["errno"] == "EAGAIN":
                accepted = sum(prior["success"] for prior in events[:index])
                assert accepted > 0, "nonempty actual protected send prefix before EAGAIN"
                witness = dict(event, pid=client["pid"], local_addr=client["local_addr"], peer_addr=client["peer_addr"], accepted_prefix_packets=accepted)
                # Mutation controls start from the actual successful setup and
                # observed syscall. They prove the trace oracle rejects false
                # credit; they are not another live socket/EAGAIN result.
                body = witness["raw_call"]
                arguments = (witness["time_ns"], witness["tid"], client["local_addr"], client["peer_addr"], cid)
                assert packet_event(body, *arguments)["errno"] == "EAGAIN"
                assert packet_event(body.replace("EAGAIN", "EPERM"), *arguments) is None
                assert packet_event(body, witness["time_ns"], witness["tid"], "192.0.2.99:9", client["peer_addr"], cid) is None
                assert packet_event(body, witness["time_ns"], witness["tid"], client["local_addr"], "192.0.2.99:9", cid) is None
                wrong_cid = bytes([cid[0] ^ 1]) + cid[1:]
                assert packet_event(body, witness["time_ns"], witness["tid"], client["local_addr"], client["peer_addr"], wrong_cid) is None
                raw_hex = "".join(f"\\x{byte:02x}" for byte in bytes.fromhex(witness["ciphertext_hex"]))
                assert body.count(raw_hex) == 1
                assert packet_event(body.replace(raw_hex, raw_hex[:-4], 1), *arguments) is None
                witness["trace_negative_controls"] = ["non_EAGAIN", "wrong_socket", "wrong_peer", "wrong_CID", "truncated_ciphertext"]
                write_receipt("kernel-eagain.json", witness)
                break
        time.sleep(0.005)
    cancelled = wait_receipt("kernel-cancelled.json")
    assert cancelled["pid"] == client["pid"] and cancelled["typed_result"] == "Cancelled" and cancelled["parked_before_abort"]
    assert cancelled["polls_after_abort"] > cancelled["polls_before_abort"] > 0 and cancelled["wakes_after_abort"] > cancelled["wakes_before_abort"]
    assert cancelled["retained_connections"] == 1 and cancelled["ciphertext_sha256"] == witness["ciphertext_sha256"]
    neighbour = json.loads(command("ip", "-j", "neigh", "show", "dev", "qc76"))
    assert any(row["dst"] == "192.0.2.2" and "INCOMPLETE" in row["state"] for row in neighbour), "still blocked until owned cancellation completes"
    recovery_started = time.time_ns()
    command("ip", "neigh", "replace", "192.0.2.2", "lladdr", mac, "nud", "permanent", "dev", "qc76")
    write_receipt("kernel-recovered.json", dict(client_pid=client["pid"], time_ns=time.time_ns(), observed_peer_mac=mac))
    while any(process.poll() is None for _, process in peers):
        watch()
        collect_tids(client["pid"], tids)
        time.sleep(0.005)
    watch()
    events = read_events(client["local_addr"], client["peer_addr"], cid, tids)
    retries = [event for event in events if event["success"] and event["time_ns"] >= recovery_started and event["ciphertext_hex"] == witness["ciphertext_hex"]]
    assert retries, "same retained protected ciphertext must succeed after recovery"
    assert not any(event["success"] and witness["time_ns"] < event["time_ns"] < recovery_started and event["ciphertext_hex"] == witness["ciphertext_hex"] for event in events), "failed ciphertext was not sent before the controlled recovery"
    receipts = []
    expected_payload = bytes(index % 251 for index in range(32 * 1024))
    for role in ("client", "server"):
        receipt = wait_receipt(f"kernel-{role}-receipt.json")
        identity = client if role == "client" else server
        assert receipt["identity"] == identity and receipt["runtime_quiescent"]
        assert receipt["active_connections_after_shutdown"] == receipt["pending_timers_after_shutdown"] == 0
        assert receipt["application_payload_writes"] == 1
        result = receipt["recovery"]
        assert result["received_bytes"] == len(expected_payload) and result["sha256"] == hashlib.sha256(expected_payload).hexdigest() and result["fin"]
        assert result["packets_sent"] > 0 and result["packets_received"] > 0 and result["application_polls"] > 0 and result["application_self_wake"] is False
        stdout = (artifacts / f"kernel-{role}.stdout.log").read_text()
        assert re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", stdout) == [("1", "0", "0", "0", "9")]
        emitted = [json.loads(line.split("MANAGED_QUIC_KERNEL_PEER ", 1)[1]) for line in stdout.splitlines() if "MANAGED_QUIC_KERNEL_PEER " in line]
        assert emitted == [receipt]
        receipts.append(receipt)
    trace_files = [dict(path=path.name, bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted(artifacts.glob("kernel-client.syscall.*"))]
    summary = dict(source=parent["source"], executable_sha256=parent["executable_sha256"], actual_authenticated_sessions=1, actual_child_count=2, syscall_errno="EAGAIN", same_ciphertext_retry=True, parked_cancellation_and_recovery=True, witness=witness, successful_retry=retries[0], cancellation=cancelled, children=receipts, trace_files=trace_files, same_router_multi_peer_proof=False, performance_claim=False)
    write_receipt("kernel-summary.json", summary)
    log_event(dict(kernel_proof="actual authenticated EAGAIN, native parked cancellation, exact ciphertext retry and application recovery", artifact_directory=str(artifacts)))
finally:
    # Only these two owned process groups exist in these private namespaces.
    # No namespace names, host routes, files, or unrelated processes are removed.
    original_failure = sys.exc_info()[0] is not None
    cleanup_errors = []
    for role, process in peers:
        try:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass  # The owned process may finish between poll and kill.
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=3)
            log_event(dict(owned_process=role, pid=process.pid, terminal_exit=process.returncode))
        except Exception as error:
            cleanup_errors.append((role, repr(error)))
            log_event(dict(owned_process=role, cleanup_error=repr(error)))
    command_log.close()
    if cleanup_errors and not original_failure:
        raise AssertionError(("owned process cleanup failed", cleanup_errors))
PY_KERNEL
fi

RUN_ID="${RUN_ID:-managed-quic-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_${RUN_ID}}"
OUTPUT_ROOT="${OUTPUT_ROOT:-${TMPDIR:-/tmp}/asupersync-quic-${RUN_ID}}"
BASE_REV="$(git rev-parse "${ASUPERSYNC_QUIC_BASE:-HEAD}^{commit}")"
OVERLAY_MODE="${ASUPERSYNC_QUIC_CLEAN_OVERLAY:-0}"
QUIC_WORKER="${ASUPERSYNC_QUIC_RCH_WORKER:-${RCH_WORKER:-}}"
BUILD_JOBS="${ASUPERSYNC_QUIC_BUILD_JOBS:-8}"
STAGE_TIMEOUT="${ASUPERSYNC_QUIC_STAGE_TIMEOUT:-1800}"
QUIC_CARGO_HOME="${ASUPERSYNC_QUIC_CARGO_HOME:-${CARGO_HOME:-}}"
QUIC_ARTIFACT_BASE="${ASUPERSYNC_MANAGED_QUIC_ARTIFACT_BASE:-}"
OVERLAY_FINGERPRINT=""
if [[ ! "${BUILD_JOBS}" =~ ^[1-9][0-9]*$ || ! "${STAGE_TIMEOUT}" =~ ^[1-9][0-9]*$ ]]; then
  echo "refused: build jobs and stage timeout must be positive integers" >&2
  exit 2
fi
if [[ "$(git branch --show-current)" != main ]]; then
  echo "refused: this proof runner operates on main" >&2
  exit 2
fi
REMOTE_CARGO_ENV=()
if [[ -n "${QUIC_CARGO_HOME}" ]]; then
  REMOTE_CARGO_ENV+=("CARGO_HOME=${QUIC_CARGO_HOME}")
fi
if [[ -n "${QUIC_ARTIFACT_BASE}" ]]; then
  if [[ "${QUIC_ARTIFACT_BASE}" != /* ]]; then
    echo "refused: ASUPERSYNC_MANAGED_QUIC_ARTIFACT_BASE must be an absolute remote directory" >&2
    exit 2
  fi
  # Select an existing worker directory outside the clean-overlay snapshot to
  # retain process artifacts after RCH reaps that snapshot. Forward explicitly;
  # the harness creates its own unique child directory beneath this base.
  REMOTE_CARGO_ENV+=("ASUPERSYNC_MANAGED_QUIC_ARTIFACT_BASE=${QUIC_ARTIFACT_BASE}")
fi
if [[ -e "${OUTPUT_ROOT}" ]]; then
  echo "refused: OUTPUT_ROOT already exists; preserve its earlier evidence: ${OUTPUT_ROOT}" >&2
  exit 2
fi
mkdir -p "${OUTPUT_ROOT}" "${TARGET_DIR}"

# Installed executable evidence, not a version-number assumption. Refuse before
# issuing proof commands if the complete source-selection surface is missing.
rch exec --help > "${OUTPUT_ROOT}/rch-exec-help.log"
for option in --base --clean-overlay --overlay-path --no-overlay; do
  if ! grep -q -- "${option}" "${OUTPUT_ROOT}/rch-exec-help.log"; then
    echo "declared_unavailable: installed RCH lacks ${option}" >&2
    exit 2
  fi
done
SOURCE_ARGS=(--base "${BASE_REV}")
if [[ "${OVERLAY_MODE}" == 1 ]]; then
  # This is the complete, reviewable managed-handoff source slice. The caller
  # coordinates these exact reservations; unselected peer dirt stays excluded.
  SOURCE_ARGS+=(--clean-overlay)
  for path in src/net/quic_native/connection_manager.rs src/net/quic_native/managed_endpoint.rs \
    src/net/quic_native/udp_connection.rs src/net/quic_native/handshake_driver.rs \
    src/net/quic_native/endpoint.rs \
    src/net/quic_native/endpoint_api.rs src/net/quic_native/mod.rs \
    tests/quic_h3_live_udp.rs tests/quic_native_handshake_udp_loopback.rs \
    scripts/run_quic_application_data_loopback_e2e.sh; do
    SOURCE_ARGS+=(--overlay-path "${path}")
  done
elif [[ "${OVERLAY_MODE}" == 0 ]]; then
  SOURCE_ARGS+=(--no-overlay)
else
  echo "refused: ASUPERSYNC_QUIC_CLEAN_OVERLAY must be 0 or 1" >&2
  exit 2
fi

echo "ATP_QUIC_TRACE=${ATP_QUIC_TRACE:-1}"
echo "CARGO_TARGET_DIR=${TARGET_DIR}"
echo "build_jobs=${BUILD_JOBS} cargo_home=${QUIC_CARGO_HOME:-remote-default}"
echo "managed_artifact_base=${QUIC_ARTIFACT_BASE:-remote-test-default}"
echo "base=${BASE_REV} overlay_mode=${OVERLAY_MODE} logs=${OUTPUT_ROOT}"

run_stage() {
  local stage="$1" features="$2" target="$3" status=0 receipt
  local -a target_args
  shift 3
  if [[ "${target}" == --lib ]]; then
    target_args=(--lib)
  else
    target_args=(--test "${target}")
  fi
  timeout --signal=TERM --kill-after=30s "${STAGE_TIMEOUT}s" \
    env RCH_REQUIRE_REMOTE=1 RCH_DISABLE_TARGET_REUSE=1 RCH_VISIBILITY=verbose RCH_WORKER="${QUIC_WORKER}" RCH_WORKERS= NO_COLOR=1 \
    rch exec "${SOURCE_ARGS[@]}" -- env "${REMOTE_CARGO_ENV[@]}" \
    ATP_QUIC_TRACE="${ATP_QUIC_TRACE:-1}" \
    CARGO_TARGET_DIR="${TARGET_DIR}/${stage}" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
    RUSTFLAGS='-D warnings -C debuginfo=0' \
    cargo test --jobs "${BUILD_JOBS}" -p asupersync --locked \
    --features "${features}" "${target_args[@]}" -- --nocapture "$@" \
    2>&1 | tee "${OUTPUT_ROOT}/${stage}.log" || status=$?
  if [[ "${status}" != 0 ]]; then
    echo "failed: ${stage} terminal_exit=${status}; original output retained" >&2
    return "${status}"
  fi
  receipt="$(python3 - "${OUTPUT_ROOT}/${stage}.log" "${BASE_REV}" "${QUIC_WORKER}" "${OVERLAY_FINGERPRINT}" <<'PY'
import pathlib, re, sys
path, base, worker, fingerprint = sys.argv[1:]
log = re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(path).read_text())
selected = re.findall(r"Selected worker: ([A-Za-z0-9_.-]+) at ", log)
terminal = re.findall(r"^\[RCH\] remote ([A-Za-z0-9_.-]+) \([^\n]+\)$", log, re.M)
sources = re.findall(r"^\[RCH\] clean-overlay receipt: base=([0-9a-f]{40}) overlay-fingerprint=([0-9a-f]{64})$", log, re.M)
assert len(selected) == 1 and terminal == selected, "actual unique remote terminal worker required"
assert not worker or selected == [worker], "worker changed between required stages"
assert len(sources) == 1 and sources[0][0] == base, "selected source receipt required"
assert not fingerprint or sources[0][1] == fingerprint, "source changed between required stages"
assert re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed;", log), "nonzero terminal tests required"
print(selected[0], sources[0][1])
PY
)"
  read -r QUIC_WORKER OVERLAY_FINGERPRINT <<< "${receipt}"
}

# Native cancellation semantics are the prerequisite for every runtime change.
run_stage native test-internals,tls runtime_abort_vs_cancel_semantics_audit --test-threads=1
python3 - "${OUTPUT_ROOT}/native.log" <<'PY'
import pathlib, re, sys
log = pathlib.Path(sys.argv[1]).read_text()
counts = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", log)
assert len(counts) == 1 and int(counts[0][0]) > 0 and counts[0][1:] == ("0", "0", "0", "0"), ("complete unfiltered native prerequisite required", counts)
PY
# The retained TLS driver must preserve the existing public owner's auto-traits.
run_stage public-api-traits http3,tls quic_endpoint_api_roundtrip
python3 - "${OUTPUT_ROOT}/public-api-traits.log" <<'PY'
import pathlib, re, sys
log = pathlib.Path(sys.argv[1]).read_text()
assert re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", log) == [("8", "0", "0", "0", "0")]
assert len(re.findall(r"^test managed_public_types_preserve_config_traits_and_error_conversions \.\.\. ok$", log, re.M)) == 1
PY
run_stage managed-mechanics http3,tls --lib net::quic_native::managed_endpoint::tests --test-threads=1
python3 - "${OUTPUT_ROOT}/managed-mechanics.log" <<'PY'
import pathlib, re, sys
log = pathlib.Path(sys.argv[1]).read_text()
counts = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", log)
assert len(counts) == 1 and counts[0][:4] == ("20", "0", "0", "0"), ("all 15 original and five new managed mechanics required", counts)
tests = re.findall(r"^test net::quic_native::managed_endpoint::tests::authenticated_accept_tests::([A-Za-z0-9_]+) \.\.\. ok$", log, re.M)
expected = {
    "managed_accept_server_rejects_encoded_retry_without_claiming_other_cids",
    "managed_accept_preflight_receipt_and_packet_bounds_preserve_existing_owner",
    "managed_accept_actual_initial_credit_bounds_queued_prefix_and_pto_replay",
    "managed_accept_tls_callback_cancellation_stops_at_one_packet_and_keeps_other_cid",
    "managed_remove_connection_preserves_same_address_peer_queues_and_timer",
}
assert len(tests) == len(expected) and set(tests) == expected, ("all five named authenticated admission mechanics required", tests)
PY
# Preserve the original protocol fixture stage and its assertions. Its keys and
# manually established state are not credited as authenticated managed proof.
run_stage protocol-fixture test-internals,tls quic_application_data_udp_loopback
python3 - "${OUTPUT_ROOT}/protocol-fixture.log" <<'PY'
import pathlib, re, sys
log = pathlib.Path(sys.argv[1]).read_text()
assert re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", log) == [("6", "0", "0", "0", "0")]
PY
# The managed tests use public APIs for real TLS handshakes and consuming
# handoffs. The conformance dev-dependency unifies test-internals into this
# target, so all four original tests and three managed parents must execute.
# Two parents explicitly execute their ignored helpers in four owned processes.
run_stage authenticated-managed http3,tls quic_h3_live_udp
python3 - "${OUTPUT_ROOT}/authenticated-managed.log" "${BASE_REV}" "${OVERLAY_MODE}" <<'PY'
import hashlib, json, pathlib, re, ssl, subprocess, sys
path, base, overlay = sys.argv[1:]
log = re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(path).read_text())
counts = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", log)
assert counts == [("1", "0", "0", "0", "9")] * 4 + [("7", "0", "3", "0", "0")], ("all seven public parents, four executed child helpers and three intentional ignores required", counts)
parents = {
    "authenticated_h3_router_request_response_crosses_real_udp",
    "authenticated_h3_produced_response_obeys_live_udp_credit_and_quiesces",
    "cancellation_refuses_live_request_before_router_dispatch",
    "negotiated_non_h3_alpn_refuses_live_application_handles",
    "authenticated_managed_public_handoff_self_wake_and_restart_cross_real_udp",
    "authenticated_managed_two_process_public_exchange_cancel_and_restart",
    "managed_multi_peer::authenticated_same_socket_multi_peer",
}
passed = re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\. ok$", log, re.M)
assert len(passed) == len(parents) and set(passed) == parents, ("all seven named parents must pass exactly once", passed)
ignored = re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\. ignored(?:, [^\n]*)?$", log, re.M)
assert len(ignored) == 3 and set(ignored) == {"authenticated_managed_process_peer", "authenticated_managed_kernel_backpressure", "managed_multi_peer::authenticated_same_socket_process_peer"}, ("only the three explicitly selected helpers may be ignored", ignored)
rows = [json.loads(line.split("MANAGED_QUIC_TWO_PROCESS ", 1)[1]) for line in log.splitlines() if "MANAGED_QUIC_TWO_PROCESS " in line]
assert len(rows) == 1, "one actual two-process summary required"
summary = rows[0]
paths = dict(test="tests/quic_h3_live_udp.rs", runner="scripts/run_quic_application_data_loopback_e2e.sh", manager="src/net/quic_native/connection_manager.rs", managed="src/net/quic_native/managed_endpoint.rs", owner="src/net/quic_native/udp_connection.rs", handshake_driver="src/net/quic_native/handshake_driver.rs", endpoint="src/net/quic_native/endpoint.rs", application="src/net/quic_native/endpoint_api.rs", exports="src/net/quic_native/mod.rs")
expected = {key: hashlib.sha256(pathlib.Path(value).read_bytes() if overlay == "1" else subprocess.check_output(["git", "show", f"{base}:{value}"])).hexdigest() for key, value in paths.items()}
assert summary["source"] == expected, "compiled source identity differs from the selected revision/overlay"
children = summary["children"]
assert len(children) == summary["actual_child_count"] == 2
assert summary["actual_authenticated_sessions"] == 1
assert {child["role"] for child in children} == {"client", "server"}
assert len({child["pid"] for child in children}) == 2
assert re.fullmatch(r"[0-9a-f]{64}", summary["executable_sha256"])
for child in children:
    assert child["source"] == expected and child["executable_sha256"] == summary["executable_sha256"]
    assert child["runtime_quiescent"] and child["parked_cancelled_and_restarted"]
    assert child["active_connections_after_shutdown"] == 0 and len(child["rounds"]) == 2
    assert all(round["received_bytes"] > 0 and round["packets_sent"] > 0 and round["packets_received"] > 0 for round in child["rounds"])
print("verified original managed public proof: two executed child helpers, one authenticated session and two exchange rounds")

def rows_for(marker):
    return [json.loads(line.split(marker, 1)[1]) for line in log.splitlines() if marker in line]

multi_rows = rows_for("MANAGED_QUIC_MULTI_PEER ")
assert len(multi_rows) == 1, "one actual same-socket multi-peer summary required"
multi = multi_rows[0]
assert multi["schema"] == "asupersync.managed_quic.multi_peer.v1"
assert multi["source"] == expected and multi["executable_sha256"] == summary["executable_sha256"]
assert multi["actual_children"] == 2 and multi["elapsed_micros"] > 0
assert all(multi[field] is True for field in ("same_server_socket", "distinct_verified_client_identities", "same_router_multi_peer_proof"))
assert all(multi[field] is False for field in ("kernel_would_block_claim", "retained_ciphertext_queue_claim", "performance_claim"))
server, clients = multi["server"], multi["clients"]
emitted = rows_for("MANAGED_QUIC_MULTI_PEER_PROCESS ")
assert len(emitted) == 2 and {row["role"] for row in emitted} == {"server", "clients"}
assert {row["role"]: row for row in emitted} == {"server": server, "clients": clients}, "actual process stdout must join the parent receipts"
assert server["pid"] != clients["pid"] and min(server["pid"], clients["pid"]) > 0
for child, task_count in ((server, 1), (clients, 3)):
    assert child["schema"] == "asupersync.managed_quic.multi_peer.process.v1"
    assert child["source"] == expected and child["executable_sha256"] == multi["executable_sha256"]
    assert child["runtime_quiescent"] is True and child["owned_region_reclaimed"] is True
    assert all(child[field] == 0 for field in ("tasks_after_cleanup", "leaked_obligations_after_cleanup", "draining_regions_after_cleanup", "active_connections_after_shutdown", "pending_timers_after_shutdown"))
    assert min(child["packets_sent"], child["packets_received"], child["elapsed_micros"]) > 0
    terminals = child["actual_terminal_sequences"]
    assert len(terminals) == task_count and len(set(terminals.values())) == task_count
    assert all(isinstance(seq, int) and 0 <= seq < child["owned_region_close_sequence"] for seq in terminals.values()), "actual full-ID completion must precede owned region close"
    assert child["owned_region"] and all(terminals)
assert len(clients["joined_client_tasks"]) == len(set(clients["joined_client_tasks"])) == 2
assert set(clients["joined_client_tasks"]) < set(clients["actual_terminal_sequences"])
assert server["server_addr"] == clients["server_addr"] == clients["a"]["peer_addr"]
assert server["a_peer"] == clients["a"]["local_addr"] != server["server_addr"]
assert server["a_fin"] is True and clients["a"]["fin"] is True
a_records = server["a_records"]
assert a_records == clients["a"]["records"] and 0 < len(a_records) <= 8192
def record_sha(sequence, tag):
    return hashlib.sha256(sequence.to_bytes(8, "big") + bytes((tag + index % 251) & 255 for index in range(512))).hexdigest()
assert a_records == [record_sha(sequence, ord("A")) for sequence in range(len(a_records))], "independent actual A byte/order comparison"
test_bytes = pathlib.Path(paths["test"]).read_bytes() if overlay == "1" else subprocess.check_output(["git", "show", f"{base}:{paths['test']}"])
def client_identity(name):
    certificates = re.findall(r'const ' + name + r': &str = "(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)";', test_bytes.decode(), re.S)
    assert len(certificates) == 1
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificates[0])).hexdigest()
a_identity, b_identity = client_identity("CLIENT_A"), client_identity("CLIENT_B")
assert a_identity != b_identity
assert server["verified_client_signatures"] == [a_identity, b_identity, b_identity, b_identity], "actual TLS signature verification must bind distinct input certificates"
outcomes = ["accepted_removed", "cancelled", "client_certificate_refused", "alpn_refused", "accepted_removed"]
assert len(server["attempts"]) == len(clients["attempts"]) == len(outcomes)
for index, (accepted, client, result) in enumerate(zip(server["attempts"], clients["attempts"], outcomes), 1):
    assert accepted["attempt"] == client["attempt"] == index
    assert accepted["result"] == client["result"] == result
    assert accepted["peer"] == client["local_addr"] != server["a_peer"]
    assert accepted["active_connections"] == 1
    assert 0 <= accepted["a_records_before"] <= accepted["a_records_after"] <= len(a_records)
    if result == "accepted_removed":
        assert accepted["b_records"] == client["payload"]["records"] == [record_sha(0, ord("B"))]
        assert accepted["b_fin"] is True and client["payload"]["fin"] is True
        assert accepted["client_cid"] == client["client_cid"] and accepted["server_cid"] == client["server_cid"]
        assert accepted["verified_client_sha256"] == b_identity and accepted["alpn"] == "asupersync-managed-test"
        assert accepted["queued_application_suffix"] is True and accepted["retained_ciphertext_queue_claim"] is False
        assert accepted["a_records_before"] <= accepted["a_records_at_removal"] < accepted["a_records_after"]
    elif result == "cancelled":
        assert accepted["actual_initial_sent"] is True and client["initial_packets_sent"] > 0 and client["owned_connect_future_retired"] is True
        assert accepted["a_records_after"] > accepted["a_records_before"]
    elif result == "client_certificate_refused":
        assert "read_hs_fatal_alert" in accepted["error"] and client["server_refusal"] == accepted["error"]
        assert client["owned_connect_future_retired"] is True and min(client["packets_sent"], client["packets_received"]) > 0
    else:
        assert "alpn" in accepted["error"].lower()
assert server["attempts"][0]["server_cid"] != server["attempts"][4]["server_cid"]
witness = server["timer_witness"]
assert 0 <= witness["a_records_before"] < witness["a_records_during_b_handshake"] <= len(a_records)
assert witness["a_pto_after"] > witness["a_pto_before"] and witness["sent_after_pto_observation"] > 0
assert witness["egress_counter_scope"] == "shared_socket_not_CID_specific_probe_delivery"
assert witness["b_tls_held_after_real_initial"] is True and witness["a_reply_queued_after_pause"] is True
observed = witness["a_peer_observed_record"]
assert observed["bytes"] == 520 and observed["b_attempt"] == 1
assert 0 <= observed["sequence"] < len(a_records) and observed["sha256"] == a_records[observed["sequence"]]
assert observed["a_records_before"] == witness["a_records_before"]
assert witness["a_last_record_sha256"] == a_records[witness["a_records_during_b_handshake"] - 1]
negative = multi["negative_controls"]
assert "ConnectionCreationFailed" in negative["duplicate_cid"]["typed_refusal"]
assert all(negative[field] is True for field in ("pending_handshake_cancel", "fatal_tls_no_client_certificate", "post_tls_alpn_refusal"))
print("verified same-socket authenticated A/B admission, cancellation/refusals/removal/readmission, ordered actual payloads, A timer progress and four real task completions before two region closes; no ciphertext, kernel or performance claim")
PY
run_stage authenticated-quiet http3,tls,test-internals quic_native_handshake_udp_loopback --exact managed_quiet::native_managed_quiet_burst_and_timer_recovery --test-threads=1
python3 - "${OUTPUT_ROOT}/authenticated-quiet.log" <<'PY'
import hashlib, json, pathlib, re, sys
log = re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(sys.argv[1]).read_text())
counts = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", log)
assert counts == [("1", "0", "0", "0", "4")], ("actual quiet parent required", counts)
rows = re.findall(r"^MANAGED_QUIC_QUIET_SUMMARY (.+)$", log, re.M)
assert len(rows) == 1, "one complete actual two-process quiet receipt"
summary = json.loads(rows[0])
assert summary["schema"] == "asupersync.managed_quic_quiet.v1"
paths = {
    "test": "tests/quic_native_handshake_udp_loopback.rs",
    "manager": "src/net/quic_native/connection_manager.rs",
    "managed": "src/net/quic_native/managed_endpoint.rs",
    "owner": "src/net/quic_native/udp_connection.rs",
    "endpoint": "src/net/quic_native/endpoint.rs",
    "application": "src/net/quic_native/endpoint_api.rs",
    "exports": "src/net/quic_native/mod.rs",
    "handshake_driver": "src/net/quic_native/handshake_driver.rs",
    "transport": "src/net/quic_native/transport.rs",
    "connection": "src/net/quic_native/connection.rs",
}
assert summary["source"] == {key: hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() for key, path in paths.items()}
assert len({summary[key] for key in ("parent_pid", "server_pid", "client_pid")}) == 3
assert all(type(summary[key]) is int and summary[key] > 0 for key in ("parent_pid", "server_pid", "client_pid"))
executable = summary["executable"]
assert re.fullmatch(r"[0-9a-f]{64}", executable["sha256"]) and executable["bytes"] > 0
assert pathlib.Path(executable["path"]).is_absolute()
assert summary["clock_ticks_per_second"] > 0 and 0 < summary["elapsed_nanos"] < 120_000_000_000
def record_hash(sequence):
    data = sequence.to_bytes(8, "big") + bytes(((sequence & 255) + i % 251) & 255 for i in range(512))
    return hashlib.sha256(data).hexdigest()
sent, echoed = [0, 1, 2, 3, 4, 5], [0, 1, 2, 9000, 3, 9001, 4, 5]
for role, received, outbound in (("server", sent, echoed), ("client", echoed, sent)):
    child = summary[role]
    assert child["role"] == role and child["pid"] == summary[role + "_pid"]
    assert child["source"] == summary["source"] and child["executable"] == executable
    terminal = child["libtest"]
    assert [terminal[key] for key in ("passed", "failed", "ignored", "measured", "filtered")] == [1, 0, 0, 0, 4]
    assert re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in [0-9]+(?:\.[0-9]+)?s", terminal["raw"])
    assert child["driver_instances"] == 1 and child["runtime_shutdown"] is True
    assert re.fullmatch(r"TaskId\([0-9]+:[0-9]+\)", child["task"])
    assert re.fullmatch(r"RegionId\([0-9]+:[0-9]+\)", child["region"])
    assert child["complete_seq"] < child["region_close_seq"]
    assert all(child[key] == 0 for key in ("tasks_after_cleanup", "leaked_obligations_after_cleanup",
        "draining_regions_after_cleanup", "active_connections_after_shutdown", "pending_timers_after_shutdown"))
    state = child["state"]
    assert state["received"] == received and state["sent"] == outbound
    assert state["received_bytes"] == 520 * len(received)
    assert state["received_sha256"] == [record_hash(sequence) for sequence in received]
    assert state["fin"] is True and state["fin_sent"] is True
quiet = summary["quiet_intervals"]
assert len(quiet) == 7 and len({row["phase"] for row in quiet}) == 7
for row in quiet:
    assert row["oracle"] == "quiet" and row["injected_periodic_wake"] is False
    assert row["elapsed_nanos"] >= 400_000_000
    before, after = row["before"], row["after"]
    assert before["pid"] == after["pid"] == summary["server_pid"]
    assert before["polls"] == after["polls"] and before["wakes"] == after["wakes"]
    for sample in (before, after):
        assert sample["parked"] is True and sample["paused"] is False
        assert sample["pending_timers"] == 0 and sample["deadline"] is None
        assert sample["state"]["bytes_in_flight"] == sample["state"]["queued_stream_bytes"] == 0
        assert sample["state"]["pending_stream_frames"] is False
    for key in ("packets_sent", "packets_received"):
        assert before["state"][key] == after["state"][key]
    assert row["cpu_before"]["pid"] == row["cpu_after"]["pid"] == summary["server_pid"]
    assert row["cpu_before"]["start_ticks"] == row["cpu_after"]["start_ticks"]
    assert all(row["cpu_after"][key] >= row["cpu_before"][key] for key in ("user_ticks", "system_ticks"))
assert [row["sequence"] for row in summary["bursts"]] == [0, 1, 2, 4, 5]
assert all(row["record_sha256"] == record_hash(row["sequence"]) for row in summary["bursts"])
recovery = summary["recovery"]
first, later = recovery["initial"], recovery["later"]
assert 0 < recovery["setup_wait_limit_nanos"] <= 90_000_000_000
assert later["state"]["pto_count"] >= first["state"]["pto_count"] + 6
assert later["state"]["packets_sent"] > first["state"]["packets_sent"]
assert later["state"]["packets_received"] == first["state"]["packets_received"]
assert later["deadline"] > first["deadline"] and later["deadline"] > later["now"] + 800_000_000
assert recovery["packet_received_at"] < recovery["retained_deadline"] == later["deadline"]
assert 3 in recovery["packet_before_deadline"]["state"]["received"]
assert recovery["removed_by_ack"]["pending_timers"] == recovery["removed_by_ack"]["state"]["pto_count"] == 0
assert recovery["earlier_rearm_after_ack"]["deadline"] < recovery["retained_deadline"]
negative = summary["periodic_wake_negative"]
assert negative["oracle"] == "PeriodicWake" and negative["injected_periodic_wake"] is True
assert negative["after"]["polls"] > negative["before"]["polls"]
assert negative["after"]["wakes"] > negative["before"]["wakes"]
assert summary["claim_boundary"] == "actual candidate measurements and planted wake control; no incumbent comparison"
assert summary["remaining_acceptance"] == ["identical-workload real incumbent distributions",
    "simultaneous packet/deadline readiness", "active earlier/later timer replacement",
    "relative-clock/receive-first/missing-wake mutations", "saturated cancellation and fresh endpoint recovery"]
print("verified actual retained-driver quiet intervals, protected bursts, PTO/ACK timer recovery and planted periodic wake refusal; no incumbent or performance comparison")
PY

run_stage authenticated-kernel-backpressure http3,tls quic_h3_live_udp --exact authenticated_managed_kernel_backpressure --ignored --test-threads=1
python3 - "${OUTPUT_ROOT}/authenticated-kernel-backpressure.log" "${OUTPUT_ROOT}/authenticated-managed.log" <<'PY'
import json, pathlib, re, sys
kernel, public = [re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(path).read_text()) for path in sys.argv[1:]]
counts = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", kernel)
assert counts == [("1", "0", "0", "0", "9")] * 3, ("actual two kernel peers and explicitly selected parent must each execute", counts)
def summaries(log, marker):
    return [json.loads(line.split(marker, 1)[1]) for line in log.splitlines() if marker in line]
rows = summaries(kernel, "MANAGED_QUIC_KERNEL_TWO_PROCESS ")
normal = summaries(public, "MANAGED_QUIC_TWO_PROCESS ")
assert len(rows) == len(normal) == 1
summary = rows[0]
assert summary["source"] == normal[0]["source"], "kernel/public compiled source differs"
assert re.fullmatch(r"[0-9a-f]{64}", summary["executable_sha256"])
assert summary["actual_authenticated_sessions"] == 1 and summary["actual_child_count"] == 2
assert summary["syscall_errno"] == "EAGAIN" and summary["same_ciphertext_retry"] and summary["parked_cancellation_and_recovery"]
assert summary["witness"]["ciphertext_hex"] == summary["successful_retry"]["ciphertext_hex"]
assert summary["witness"]["accepted_prefix_packets"] > 0 and summary["successful_retry"]["success"]
assert {child["identity"]["role"] for child in summary["children"]} == {"client", "server"}
assert len({child["identity"]["pid"] for child in summary["children"]}) == 2
for child in summary["children"]:
    assert child["identity"]["source"] == summary["source"] and child["identity"]["executable_sha256"] == summary["executable_sha256"]
    assert child["recovery"]["received_bytes"] == 32768 and child["recovery"]["fin"] and child["runtime_quiescent"]
    assert child["active_connections_after_shutdown"] == child["pending_timers_after_shutdown"] == 0
assert not summary["same_router_multi_peer_proof"] and not summary["performance_claim"]
print("verified actual authenticated kernel EAGAIN, parked native cancellation, same ciphertext retry and 32768-byte/FIN recovery; no same-router or performance claim")
PY
