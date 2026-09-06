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
paths = dict(test="tests/quic_h3_live_udp.rs", runner="scripts/run_quic_application_data_loopback_e2e.sh", manager="src/net/quic_native/connection_manager.rs", managed="src/net/quic_native/managed_endpoint.rs", owner="src/net/quic_native/udp_connection.rs", endpoint="src/net/quic_native/endpoint.rs", application="src/net/quic_native/endpoint_api.rs", exports="src/net/quic_native/mod.rs")
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
        assert re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", stdout) == [("1", "0", "0", "0", "7")]
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
QUIC_CARGO_HOME="${ASUPERSYNC_QUIC_CARGO_HOME:-${CARGO_HOME:-}}"
QUIC_ARTIFACT_BASE="${ASUPERSYNC_MANAGED_QUIC_ARTIFACT_BASE:-}"
OVERLAY_FINGERPRINT=""
if [[ ! "${BUILD_JOBS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "refused: ASUPERSYNC_QUIC_BUILD_JOBS must be a positive integer" >&2
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
mkdir -p "${OUTPUT_ROOT}"

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
    src/net/quic_native/udp_connection.rs src/net/quic_native/endpoint.rs \
    src/net/quic_native/endpoint_api.rs src/net/quic_native/mod.rs \
    tests/quic_h3_live_udp.rs scripts/run_quic_application_data_loopback_e2e.sh; do
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
  shift 3
  env RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose RCH_WORKER="${QUIC_WORKER}" RCH_WORKERS= NO_COLOR=1 \
    rch exec "${SOURCE_ARGS[@]}" -- env "${REMOTE_CARGO_ENV[@]}" \
    ATP_QUIC_TRACE="${ATP_QUIC_TRACE:-1}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
    RUSTFLAGS='-D warnings -C debuginfo=0' \
    cargo test --jobs "${BUILD_JOBS}" -p asupersync --locked \
    --features "${features}" --test "${target}" -- --nocapture "$@" \
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

# Preserve the original protocol fixture stage and its assertions. Its keys and
# manually established state are not credited as authenticated managed proof.
run_stage protocol-fixture test-internals,tls quic_application_data_udp_loopback
# The managed tests use public APIs for real TLS handshakes and consuming
# handoffs. The conformance dev-dependency unifies test-internals into this
# target, so all four original tests and both managed parents must execute.
# The ignored peer is explicitly executed twice by its parent.
run_stage authenticated-managed http3,tls quic_h3_live_udp
python3 - "${OUTPUT_ROOT}/authenticated-managed.log" "${BASE_REV}" "${OVERLAY_MODE}" <<'PY'
import hashlib, json, pathlib, re, subprocess, sys
path, base, overlay = sys.argv[1:]
log = re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(path).read_text())
counts = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", log)
assert counts[-1:] == [("6", "0", "2", "0", "0")], ("all public parents and both intentional helpers required", counts)
parents = {
    "authenticated_h3_router_request_response_crosses_real_udp",
    "authenticated_h3_produced_response_obeys_live_udp_credit_and_quiesces",
    "cancellation_refuses_live_request_before_router_dispatch",
    "negotiated_non_h3_alpn_refuses_live_application_handles",
    "authenticated_managed_public_handoff_self_wake_and_restart_cross_real_udp",
    "authenticated_managed_two_process_public_exchange_cancel_and_restart",
}
passed = re.findall(r"^test ([A-Za-z0-9_]+) \.\.\. ok$", log, re.M)
assert len(passed) == len(parents) and set(passed) == parents, ("all six named parents must pass exactly once", passed)
ignored = re.findall(r"^test ([A-Za-z0-9_]+) \.\.\. ignored(?:, [^\n]*)?$", log, re.M)
assert len(ignored) == 2 and set(ignored) == {"authenticated_managed_process_peer", "authenticated_managed_kernel_backpressure"}, ("only the two explicitly selected helpers may be ignored", ignored)
rows = [json.loads(line.split("MANAGED_QUIC_TWO_PROCESS ", 1)[1]) for line in log.splitlines() if "MANAGED_QUIC_TWO_PROCESS " in line]
assert len(rows) == 1, "one actual two-process summary required"
summary = rows[0]
paths = dict(test="tests/quic_h3_live_udp.rs", runner="scripts/run_quic_application_data_loopback_e2e.sh", manager="src/net/quic_native/connection_manager.rs", managed="src/net/quic_native/managed_endpoint.rs", owner="src/net/quic_native/udp_connection.rs", endpoint="src/net/quic_native/endpoint.rs", application="src/net/quic_native/endpoint_api.rs", exports="src/net/quic_native/mod.rs")
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
print("verified managed public proof: 6 parent tests; 2 executed child helpers; 1 authenticated session; 2 exchange rounds; managed tests use public APIs; no same-router, WouldBlock, or performance claim")
PY
run_stage authenticated-kernel-backpressure http3,tls quic_h3_live_udp --exact authenticated_managed_kernel_backpressure --ignored --test-threads=1
python3 - "${OUTPUT_ROOT}/authenticated-kernel-backpressure.log" "${OUTPUT_ROOT}/authenticated-managed.log" <<'PY'
import json, pathlib, re, sys
kernel, public = [re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(path).read_text()) for path in sys.argv[1:]]
counts = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", kernel)
assert counts == [("1", "0", "0", "0", "7")] * 3, ("actual two kernel peers and explicitly selected parent must each execute", counts)
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
