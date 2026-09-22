/**
 * WebTransport host-facade regressions. Replay (Node 18.12+):
 * node --experimental-vm-modules --test scripts/test_browser_webtransport_lifecycle.mjs
 *
 * bead_id: N/A; scenario_id: WT-* test names; fixture: native WHATWG streams
 * and an intentional test double that records task-ABI calls. The actual JS
 * facade is compiled as an ES module, isolated for every test. This proves JS
 * host behavior and ABI requests, NOT Rust dispatcher execution, packaged WASM,
 * live HTTP/3, or browser conformance. expected_outcome: pass; artifact: TAP stdout.
 * ASUPERSYNC_BROWSER_CORE_SOURCE selects an old snapshot for red/green replay.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, SourceTextModule, SyntheticModule } from "node:vm";

const sourcePath = process.env.ASUPERSYNC_BROWSER_CORE_SOURCE
  ?? fileURLToPath(new URL("../packages/browser-core/index.js", import.meta.url));
const source = readFileSync(sourcePath, "utf8");
const streamSourcePath = fileURLToPath(new URL("../packages/browser-core/webtransport-streams.js", import.meta.url));
const streamSource = readFileSync(streamSourcePath, "utf8");
console.log(JSON.stringify({
  scenario_id: "browser-webtransport-host-lifecycle",
  bead_id: "N/A",
  source_sha256: createHash("sha256").update(source).digest("hex"),
  stream_source_sha256: createHash("sha256").update(streamSource).digest("hex"),
  evidence_scope: "JS facade, native WHATWG streams, intentional task-ABI call recorder",
  no_claim: ["Rust dispatcher execution", "WASM integration", "live HTTP/3", "browser conformance"],
}));

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const turn = () => new Promise((resolve) => setImmediate(resolve));
const normalize = (value) => structuredClone(value);
const unitJson = '{"outcome":"ok","value":{"kind":"unit"}}';

async function fixture(options = {}) {
  const hosts = [];
  const calls = { join: [], cancel: [], scopeClose: [], runtimeClose: [] };
  let nextTask = 1;
  let nextRegion = 100;

  // Real stream locking, queued reads, cancellation and write rejection;
  // a controlled session lifecycle, not an HTTP/3 implementation.
  class ControlledTransport {
    constructor() {
      this.events = [];
      this.streams = [];
      this.completion = deferred();
      this.closed = this.completion.promise;
      this.handshake = deferred();
      this.ready = this.handshake.promise;
      if (!options.pendingHandshake) this.handshake.resolve();
      this.datagrams = {
        readable: new ReadableStream({
          start: (controller) => { this.input = controller; },
          cancel: (reason) => { this.events.push(["cancel", reason]); },
        }),
        writable: new WritableStream({
          write: (value) => {
            this.events.push(["write", Array.from(value)]);
            if (options.writeError) throw options.writeError;
          },
          close: () => { this.events.push(["writer-close"]); },
        }),
      };
      hosts.push(this);
    }

    createBidirectionalStream() {
      this.events.push(["create-bidirectional"]);
      if (options.createStream) return options.createStream(this);
      const stream = duplex();
      this.streams.push(stream);
      return Promise.resolve(stream);
    }

    close(info = {}) {
      this.events.push(["close", info.reason]);
      if (options.closeError) this.completion.reject(options.closeError);
      else this.completion.resolve(info);
    }
  }

  const context = createContext({
    ArrayBuffer, Uint8Array, URL, TextEncoder, Error, TypeError,
    WebTransport: ControlledTransport,
  });
  const names = [
    "default", "abi_fingerprint", "abi_version", "fetch_request",
    "runtime_close", "runtime_create", "scope_close", "scope_enter",
    "task_cancel", "task_join", "task_spawn", "websocket_cancel",
    "websocket_close", "websocket_open", "websocket_recv", "websocket_send",
  ];
  const implementations = {
    runtime_create: () => JSON.stringify({
      kind: "runtime", slot: 0, generation: 1, owner_token: "42",
    }),
    scope_enter: () => JSON.stringify({
      kind: "region", slot: nextRegion++, generation: 1, owner_token: "42",
    }),
    runtime_close: (handle) => {
      calls.runtimeClose.push(JSON.parse(handle));
      return unitJson;
    },
    task_spawn: () => JSON.stringify({
      kind: "task", slot: nextTask++, generation: 1, owner_token: "42",
    }),
    task_join: (handle, outcome, version) => {
      calls.join.push({ handle: JSON.parse(handle), outcome: JSON.parse(outcome), version });
      return options.joinResponse ?? outcome;
    },
    task_cancel: (request) => {
      calls.cancel.push(JSON.parse(request));
      return options.cancelResponse ?? unitJson;
    },
    scope_close: (handle) => {
      calls.scopeClose.push(JSON.parse(handle));
      return unitJson;
    },
  };
  const bindings = new SyntheticModule(names, function () {
    for (const name of names) {
      this.setExport(name, implementations[name] ?? (() => {
        throw new Error(`Unexpected raw ABI call: ${name}`);
      }));
    }
  }, { context });
  // Expose the private map only in the test VM to assert exact cleanup. No
  // production function is replaced and no source file is rewritten on disk.
  const module = new SourceTextModule(
    `${source}\nexport { INFLIGHT_WEBTRANSPORTS as hostSessions };`,
    { context, identifier: sourcePath },
  );
  const streamModule = new SourceTextModule(streamSource, { context, identifier: streamSourcePath });
  await module.link((specifier) => {
    if (specifier === "./webtransport-streams.js") return streamModule;
    assert.equal(specifier, "./asupersync.js");
    return bindings;
  });
  await module.evaluate();
  const core = module.namespace;
  const created = core.runtime_create();
  assert.equal(created.outcome, "ok");
  const runtime = created.value;
  const entered = core.scope_enter({ parent: runtime });
  assert.equal(entered.outcome, "ok");
  const scope = entered.value;
  const opened = core.webtransport_open({ scope, url: "https://transport.example.test/" });
  assert.equal(opened.outcome, "ok");
  await turn();
  return { core, calls, hosts, host: hosts[0], runtime, scope, session: opened.value };
}

function duplex(options = {}) {
  const events = [];
  let input;
  let output;
  const host = {
    readable: new ReadableStream({
      start(controller) { input = controller; },
      cancel(reason) { events.push(["cancel", reason]); return options.cancel?.(reason); },
    }),
    writable: new WritableStream({
      start(controller) { output = controller; },
      write(bytes) {
        events.push(["write", Array.from(bytes)]);
        return options.write?.(bytes);
      },
      close() { events.push(["finish"]); return options.finish?.(); },
      abort(reason) { events.push(["abort", reason]); return options.abort?.(reason); },
    }),
    get input() { return input; },
    get output() { return output; },
    events,
  };
  return host;
}

async function openedStream(core, session) {
  const result = await core.webtransport_open_stream({ session });
  assert.equal(result.outcome, "ok", JSON.stringify(result));
  return result.value;
}

function assertReleased(core, session) {
  assert.equal(core.hostSessions.size, 0);
  const result = core.webtransport_recv({ session });
  assert.equal(result.outcome, "err");
  assert.equal(result.failure.code, "invalid_handle");
}

function assertHostClosed(host) {
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
  assert.equal(host.datagrams.readable.locked, false);
  assert.equal(host.datagrams.writable.locked, false);
}

test("WT-EOF: drain accepted datagrams before exactly one terminal outcome", async () => {
  const { core, calls, host, session } = await fixture();
  assert.equal(core.webtransport_recv({ session }).value, undefined);
  host.input.enqueue(new Uint8Array([4, 5]));
  await turn();
  host.input.close();
  await turn();
  assert.equal(calls.join.length, 1, "finish the task without waiting for recv");
  const datagram = core.webtransport_recv({ session });
  assert.equal(datagram.outcome, "ok");
  assert.deepEqual(Array.from(datagram.value), [4, 5]);
  assert.deepEqual(normalize(core.webtransport_recv({ session })), {
    outcome: "cancelled",
    cancellation: {
      kind: "webtransport_close", phase: "completed", origin_region: "browser",
      origin_task: "task:1:1", timestamp_nanos: 0,
      message: "webtransport datagram reader closed", truncated: false,
    },
  });
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-WRITE: retain write failure and release unsent buffers", async () => {
  const { core, calls, host, session } = await fixture({ writeError: new Error("sink offline") });
  assert.equal(core.webtransport_send({ session, value: [1] }).outcome, "ok");
  assert.equal(core.webtransport_send({ session, value: [2] }).outcome, "ok");
  await turn();
  assert.equal(calls.join.length, 1);
  const state = [...core.hostSessions.values()][0];
  assert.ok(state, "retain the terminal inbox until consumed");
  assert.equal(state.pendingWrites.length, 0);
  assert.deepEqual(normalize(core.webtransport_recv({ session })), {
    outcome: "err",
    failure: {
      code: "internal_failure", recoverability: "transient",
      message: "webtransport datagram write failed: sink offline",
    },
  });
  assert.deepEqual(host.events.filter(([kind]) => kind === "write"), [["write", [1]]]);
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-READ: propagate reader failure rather than an unknown-handle error", async () => {
  const { core, calls, host, session } = await fixture();
  host.input.error(new Error("reader offline"));
  await turn();
  assert.equal(calls.join.length, 1);
  assert.deepEqual(normalize(core.webtransport_recv({ session })), {
    outcome: "err",
    failure: {
      code: "internal_failure", recoverability: "transient",
      message: "webtransport datagram read failed: reader offline",
    },
  });
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-CLOSE: acknowledge retained completion without joining twice", async () => {
  const { core, calls, host, session } = await fixture();
  host.completion.resolve({ reason: "peer shutdown" });
  await turn();
  assert.equal(calls.join.length, 1);
  const terminal = core.webtransport_close({ session, reason: "caller cleanup" });
  assert.equal(terminal.outcome, "cancelled");
  assert.equal(terminal.cancellation.message, "peer shutdown");
  assert.equal(calls.join.length, 1, "the task was already finalized");
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-CANCEL: discard retained completion without cancelling a released task", async () => {
  const { core, calls, host, session } = await fixture();
  host.completion.resolve({ reason: "peer shutdown" });
  await turn();
  const terminal = core.webtransport_cancel({ session, kind: "abort_signal" });
  assert.equal(terminal.outcome, "cancelled");
  assert.equal(terminal.cancellation.message, "peer shutdown");
  assert.equal(calls.join.length, 1);
  assert.equal(calls.cancel.length, 0);
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-SCOPE: owner close removes retained terminal inboxes", async () => {
  const { core, calls, host, scope, session } = await fixture();
  host.completion.resolve({ reason: "peer shutdown" });
  await turn();
  assert.equal(core.hostSessions.size, 1);
  assert.equal(core.scope_close(scope).outcome, "ok");
  assert.equal(calls.scopeClose.length, 1);
  assert.equal(calls.join.length, 1);
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-JOIN: preserve the canonical terminal result returned by the ABI", async () => {
  const expected = {
    outcome: "err",
    failure: { code: "compatibility_rejected", recoverability: "permanent", message: "ABI rejected join" },
  };
  const { core, calls, host, session } = await fixture({ joinResponse: JSON.stringify(expected) });
  host.completion.resolve({ reason: "peer shutdown" });
  await turn();
  assert.deepEqual(normalize(core.webtransport_recv({ session })), expected);
  assert.equal(calls.join.length, 1);
  assertReleased(core, session);
});

test("WT-ACTIVE-CLOSE: explicit close still finalizes an active task once", async () => {
  const { core, calls, host, session } = await fixture();
  const result = core.webtransport_close({ session, reason: "caller shutdown" });
  assert.equal(result.outcome, "cancelled");
  assert.equal(result.cancellation.kind, "webtransport_close");
  assert.equal(result.cancellation.phase, "completed");
  assert.equal(result.cancellation.message, "caller shutdown");
  await turn();
  assert.equal(calls.join.length, 1);
  assert.equal(calls.cancel.length, 0);
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-ACTIVE-CANCEL: explicit cancel still requests cancellation before joining", async () => {
  const { core, calls, host, session } = await fixture();
  const result = core.webtransport_cancel({ session, kind: "abort_signal", message: "caller abort" });
  assert.equal(result.outcome, "cancelled");
  assert.equal(result.cancellation.kind, "abort_signal");
  assert.equal(result.cancellation.phase, "cancelling");
  assert.equal(result.cancellation.message, "caller abort");
  await turn();
  assert.equal(calls.cancel.length, 1);
  assert.equal(calls.cancel[0].kind, "abort_signal");
  assert.equal(calls.join.length, 1);
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-CANCEL-REJECTED: failed cancellation preserves an active host session", async () => {
  const expected = {
    outcome: "err",
    failure: { code: "compatibility_rejected", recoverability: "permanent", message: "ABI mismatch" },
  };
  const { core, calls, host, scope, session } = await fixture({ cancelResponse: JSON.stringify(expected) });
  assert.deepEqual(normalize(core.webtransport_cancel({ session, kind: "abort_signal" })), expected);
  assert.equal(core.hostSessions.size, 1);
  assert.equal(calls.cancel.length, 1);
  assert.equal(calls.join.length, 0);
  assert.equal(host.events.length, 0);
  assert.equal(core.scope_close(scope).outcome, "ok");
  await turn();
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-UNKNOWN-CANCEL: reject ordinary task handles without ABI side effects", async () => {
  const { core, calls, host, scope, session } = await fixture();
  const ordinary = core.task_spawn({ scope, label: "not-a-webtransport-session" });
  assert.equal(ordinary.outcome, "ok");
  const result = core.webtransport_cancel({ session: ordinary.value, kind: "abort_signal" });
  assert.equal(result.outcome, "err");
  assert.equal(result.failure.code, "invalid_handle");
  assert.equal(calls.cancel.length, 0);
  assert.equal(calls.join.length, 0);
  assert.equal(host.events.length, 0);
  assert.equal(core.scope_close(scope).outcome, "ok");
  await turn();
  assertReleased(core, session);
});

test("WT-UNKNOWN-FIELDS: unknown sessions never evaluate cancellation payload getters", async () => {
  const { core, calls, scope } = await fixture();
  const unknown = new core.TaskHandle({ kind: "task", slot: 500, generation: 1, owner_token: "42" });
  const result = core.webtransport_cancel({
    session: unknown,
    get kind() { throw new Error("kind must not be read"); },
    get message() { throw new Error("message must not be read"); },
  });
  assert.equal(result.failure.code, "invalid_handle");
  assert.equal(calls.cancel.length, 0);
  assert.equal(calls.join.length, 0);
  assert.equal(core.scope_close(scope).outcome, "ok");
});

test("WT-CANCEL-SNAPSHOT: evaluate the session handle exactly once", async () => {
  const { core, calls, host, session } = await fixture();
  let reads = 0;
  const result = core.webtransport_cancel({
    get session() {
      reads += 1;
      if (reads > 1) throw new Error("session was read twice");
      return session;
    },
    kind: "abort_signal",
    message: "snapshot cancel",
  });
  assert.equal(result.outcome, "cancelled");
  assert.equal(reads, 1);
  assert.equal(calls.cancel.length, 1);
  assert.equal(calls.join.length, 1);
  assert.deepEqual(calls.join[0].handle, calls.cancel[0].task);
  await turn();
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-CLOSE-SNAPSHOT: evaluate the session handle exactly once", async () => {
  const { core, calls, host, session } = await fixture();
  let reads = 0;
  const result = core.webtransport_close({
    get session() {
      reads += 1;
      if (reads > 1) throw new Error("session was read twice");
      return session;
    },
    reason: "snapshot close",
  });
  assert.equal(result.outcome, "cancelled");
  assert.equal(reads, 1);
  assert.equal(calls.join.length, 1);
  await turn();
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-CLOSE-OPTIONS: reject a throwing reason before detaching host state", async () => {
  const { core, calls, host, scope, session } = await fixture();
  const result = core.webtransport_close({
    session,
    get reason() { throw new Error("reason getter failed"); },
  });
  assert.equal(result.outcome, "err");
  assert.equal(result.failure.code, "compatibility_rejected");
  assert.match(result.failure.message, /reason getter failed/);
  assert.equal(core.hostSessions.size, 1);
  assert.equal(calls.join.length, 0);
  assert.equal(host.events.length, 0);
  assert.equal(core.webtransport_send({ session, value: [9] }).outcome, "ok");
  assert.equal(core.scope_close(scope).outcome, "ok");
  await turn();
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-CLOSE-TYPE: reject invalid reason types without closing the session", async () => {
  const { core, calls, host, scope, session } = await fixture();
  for (const reason of [123, false, {}, Symbol("reason")]) {
    const result = core.webtransport_close({ session, reason });
    assert.equal(result.outcome, "err");
    assert.equal(result.failure.code, "compatibility_rejected");
    assert.equal(core.hostSessions.size, 1);
    assert.equal(calls.join.length, 0);
    assert.equal(host.events.length, 0);
  }
  assert.equal(core.scope_close(scope).outcome, "ok");
  await turn();
  assertReleased(core, session);
});

test("WT-CLEANUP-THROW: synchronous host cleanup failures do not skip join or other resources", async () => {
  const { core, calls, host, session } = await fixture();
  const state = [...core.hostSessions.values()][0];
  const attempted = [];
  // The streams and lock release remain native; only the failing host methods
  // are injected to exercise synchronous exception containment.
  state.reader.cancel = () => { attempted.push("reader-cancel"); throw new Error("cancel failed"); };
  state.writer.close = () => { attempted.push("writer-close"); throw new Error("close failed"); };
  const result = core.webtransport_close({ session, reason: "shutdown" });
  assert.equal(result.outcome, "cancelled");
  assert.deepEqual(attempted, ["reader-cancel", "writer-close"]);
  assert.equal(calls.join.length, 1);
  await turn();
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-HANDSHAKE-FAIL: observe closed rejection even when readiness fails", async () => {
  const { core, calls, host, session } = await fixture({
    pendingHandshake: true, closeError: new Error("closed after handshake failure"),
  });
  host.handshake.reject(new Error("handshake denied"));
  await turn();
  assert.equal(calls.join.length, 1);
  const result = core.webtransport_recv({ session });
  assert.equal(result.outcome, "err");
  assert.equal(result.failure.code, "compatibility_rejected");
  assert.match(result.failure.message, /webtransport handshake failed: handshake denied/);
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-EARLY-CLOSE: closing during handshake observes rejection and never acquires streams", async () => {
  const { core, calls, host, session } = await fixture({
    pendingHandshake: true, closeError: new Error("closed before ready"),
  });
  assert.equal(core.webtransport_send({ session, value: [1] }).outcome, "ok");
  assert.equal(core.webtransport_close({ session }).outcome, "cancelled");
  await turn();
  host.handshake.resolve();
  await turn();
  assert.equal(calls.join.length, 1);
  assert.equal(host.events.filter(([kind]) => kind === "write").length, 0);
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-EARLY-SCOPE: owner teardown during handshake consumes later promise rejection", async () => {
  const { core, calls, host, scope, session } = await fixture({
    pendingHandshake: true, closeError: new Error("scope closed before ready"),
  });
  assert.equal(core.scope_close(scope).outcome, "ok");
  host.handshake.reject(new Error("late handshake failure"));
  await turn();
  assert.equal(calls.join.length, 0, "owner already released its child tasks");
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-REENTRANT-CLOSE: a reason getter that closes the owner cannot join twice", async () => {
  const { core, calls, host, scope, session } = await fixture();
  const result = core.webtransport_close({
    session,
    get reason() {
      assert.equal(core.scope_close(scope).outcome, "ok");
      return "owner already closed";
    },
  });
  assert.equal(result.outcome, "err");
  assert.equal(result.failure.code, "invalid_handle");
  assert.equal(calls.join.length, 0);
  assert.equal(calls.scopeClose.length, 1);
  await turn();
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-REENTRANT-CANCEL: a message getter that closes the owner cannot cancel a stale task", async () => {
  const { core, calls, host, scope, session } = await fixture();
  const result = core.webtransport_cancel({
    session,
    kind: "abort_signal",
    get message() {
      assert.equal(core.scope_close(scope).outcome, "ok");
      return "owner already closed";
    },
  });
  assert.equal(result.outcome, "err");
  assert.equal(result.failure.code, "invalid_handle");
  assert.equal(calls.cancel.length, 0);
  assert.equal(calls.join.length, 0);
  await turn();
  assertHostClosed(host);
  assertReleased(core, session);
});

test("WT-RUNTIME: close nested active and retained sessions without duplicate joins", async () => {
  const { core, calls, hosts, host, runtime, scope, session } = await fixture();
  const child = core.scope_enter({ parent: scope });
  assert.equal(child.outcome, "ok");
  const opened = core.webtransport_open({ scope: child.value, url: "https://transport.example.test/child" });
  assert.equal(opened.outcome, "ok");
  await turn();
  host.completion.resolve({ reason: "peer shutdown" });
  await turn();
  assert.equal(core.hostSessions.size, 2);
  assert.equal(calls.join.length, 1);
  assert.equal(core.runtime_close(runtime).outcome, "ok");
  await turn();
  assert.equal(calls.runtimeClose.length, 1);
  assert.equal(calls.join.length, 1);
  hosts.forEach(assertHostClosed);
  assertReleased(core, session);
  assertReleased(core, opened.value);
});

test("WT-SUBTREE: closing one scope preserves an unrelated sibling session", async () => {
  const { core, hosts, runtime, scope, session } = await fixture();
  const sibling = core.scope_enter({ parent: runtime });
  assert.equal(sibling.outcome, "ok");
  const opened = core.webtransport_open({ scope: sibling.value, url: "https://transport.example.test/sibling" });
  assert.equal(opened.outcome, "ok");
  await turn();
  assert.equal(core.scope_close(scope).outcome, "ok");
  await turn();
  assert.equal(core.hostSessions.size, 1);
  assert.equal(core.webtransport_recv({ session }).failure.code, "invalid_handle");
  assert.equal(core.webtransport_send({ session: opened.value, value: [7] }).outcome, "ok");
  await turn();
  assert.deepEqual(hosts[1].events, [["write", [7]]]);
  assert.equal(core.runtime_close(runtime).outcome, "ok");
  await turn();
  hosts.forEach(assertHostClosed);
  assertReleased(core, opened.value);
});

test("WT-LATE-READ: a pending read never appends data behind a terminal outcome", async () => {
  const { core, calls, host, session } = await fixture();
  host.completion.resolve({ reason: "peer finished" });
  host.input.enqueue(new Uint8Array([8]));
  await turn();
  const state = [...core.hostSessions.values()][0];
  assert.ok(state);
  assert.equal(state.inbox.length, 1);
  assert.equal(state.inbox[0].outcome, "cancelled");
  assert.equal(calls.join.length, 1);
  assert.equal(core.webtransport_recv({ session }).outcome, "cancelled");
  assertReleased(core, session);
});

test("WTS-BIDI: reliable bytes and both independent half-close orders", async () => {
  for (const readFirst of [false, true]) {
    const { core, host, session, scope, calls } = await fixture();
    const stream = await openedStream(core, session);
    const wire = host.streams[0];
    assert.equal(stream.direction, "bidirectional");
    assert.ok(Object.isFrozen(stream));
    assert.equal((await stream.write(new Uint8Array([1, 2]))).outcome, "ok");
    wire.input.enqueue(new Uint8Array([3, 4]));
    assert.deepEqual(normalize(await stream.read()), { outcome: "ok", value: { done: false, value: new Uint8Array([3, 4]) } });
    let done = false;
    void stream.closed.then(() => { done = true; });
    if (readFirst) {
      wire.input.close();
      assert.deepEqual(normalize(await stream.read()), { outcome: "ok", value: { done: true } });
      assert.equal(done, false, "read EOF is not write FIN");
      assert.equal((await stream.write(new Uint8Array([5]))).outcome, "ok");
      assert.equal((await stream.finish()).outcome, "ok");
    } else {
      const finishing = stream.finish();
      assert.equal(stream.finish(), finishing, "FIN is shared by concurrent callers");
      assert.equal((await finishing).outcome, "ok");
      assert.equal(done, false, "write FIN must keep receive side available");
      wire.input.enqueue(new Uint8Array([6]));
      assert.equal((await stream.read()).value.value[0], 6);
      wire.input.close();
      assert.equal((await stream.read()).value.done, true);
    }
    assert.equal((await stream.closed).outcome, "ok");
    assert.equal(wire.readable.locked, false);
    assert.equal(wire.writable.locked, false);
    assert.equal(calls.join.length, 0, "stream completion must not finish its owning session");
    assert.equal((await stream.write(new Uint8Array([9]))).outcome, "err");
    core.scope_close(scope);
  }
});

test("WTS-BACKPRESSURE: own admitted bytes and reject excess writes before host I/O", async () => {
  const gate = deferred();
  const wire = duplex({ write: () => gate.promise });
  const { core, session, scope } = await fixture({ createStream: () => wire });
  const stream = await openedStream(core, session);
  const input = new Uint8Array([7, 8]);
  const first = stream.write(input);
  input.fill(0);
  let sent = false;
  void first.then(() => { sent = true; });
  await turn();
  assert.equal(sent, false);
  assert.deepEqual(wire.events, [["write", [7, 8]]]);
  const excess = await stream.write(new Uint8Array([9]));
  assert.equal(excess.failure.recoverability, "transient");
  const finishing = stream.finish();
  assert.equal((await stream.write(new Uint8Array([10]))).outcome, "err");
  assert.equal(wire.events.length, 1, "FIN waits for the admitted write");
  gate.resolve();
  assert.equal((await first).outcome, "ok");
  assert.equal((await finishing).outcome, "ok");
  assert.deepEqual(wire.events, [["write", [7, 8]], ["finish"]]);
  wire.input.close();
  await stream.read();
  assert.equal((await stream.closed).outcome, "ok");
  core.scope_close(scope);
});

test("WTS-QUOTAS: bound live streams, pending creations, and copied write bytes", async () => {
  const { core, host, session, scope } = await fixture();
  const streams = [];
  for (let i = 0; i < core.WEBTRANSPORT_STREAM_LIMITS.maxStreamsPerSession; i++) {
    streams.push(await openedStream(core, session));
  }
  const full = await core.webtransport_open_stream({ session });
  assert.equal(full.failure.recoverability, "transient");
  assert.equal(host.streams.length, 64);
  const oversized = await streams[0].write(new Uint8Array(core.WEBTRANSPORT_STREAM_LIMITS.maxWriteBytes + 1));
  assert.equal(oversized.outcome, "err");
  assert.equal(host.streams[0].events.length, 0);
  assert.equal((await streams[0].write("not bytes")).outcome, "err");
  assert.equal((await streams[0].cancel()).outcome, "cancelled");
  const replacement = await openedStream(core, session);
  assert.equal(host.streams.length, 65);
  core.scope_close(scope);
  await Promise.all([...streams, replacement].map((s) => s.closed));
  for (const wire of host.streams) {
    assert.equal(wire.readable.locked, false);
    assert.equal(wire.writable.locked, false);
  }

  const creation = deferred();
  const pending = await fixture({ createStream: () => creation.promise });
  const requests = Array.from({ length: 64 }, () => pending.core.webtransport_open_stream({ session: pending.session }));
  await turn();
  assert.equal((await pending.core.webtransport_open_stream({ session: pending.session })).failure.recoverability, "transient");
  assert.equal(pending.host.events.filter(([kind]) => kind === "create-bidirectional").length, 64);
  pending.core.scope_close(pending.scope);
  creation.reject(new Error("session ended"));
  for (const result of await Promise.all(requests)) assert.equal(result.outcome, "cancelled");
});

test("WTS-CANCEL-DRAIN: retain capacity and cancellation result until in-flight write settles", async () => {
  const gate = deferred();
  const wire = duplex({ write: () => gate.promise });
  const { core, session, scope } = await fixture({ createStream: () => wire });
  const stream = await openedStream(core, session);
  const read = stream.read();
  assert.equal((await stream.read()).failure.recoverability, "transient");
  const write = stream.write(new Uint8Array([1]));
  await turn();
  const cancellation = stream.cancel("stop transfer");
  assert.equal(stream.cancel("again"), cancellation);
  let drained = false;
  void cancellation.then(() => { drained = true; });
  await turn();
  assert.equal(drained, false, "native sink still owns its in-flight write");
  gate.resolve();
  const results = await Promise.all([read, write, cancellation, stream.closed]);
  for (const result of results) {
    assert.equal(result.outcome, "cancelled");
    assert.equal(result.cancellation.message, "stop transfer");
  }
  assert.equal(wire.events.filter(([kind]) => kind === "abort").length, 1);
  assert.equal(wire.readable.locked, false);
  assert.equal(wire.writable.locked, false);
  core.scope_close(scope);
});

test("WTS-OWNERSHIP: parent shutdown drains streams without touching sibling sessions", async () => {
  const { core, session, scope, runtime, host } = await fixture();
  const sibling = core.scope_enter({ parent: runtime }).value;
  const siblingSession = core.webtransport_open({ scope: sibling, url: "https://transport.example.test/" }).value;
  const [first, second] = await Promise.all([openedStream(core, session), openedStream(core, siblingSession)]);
  const waiting = first.read();
  core.scope_close(scope);
  assert.equal((await waiting).outcome, "cancelled");
  assert.equal((await first.closed).outcome, "cancelled");
  assert.equal(host.streams[0].readable.locked, false);
  assert.equal((await second.write(new Uint8Array([1]))).outcome, "ok");
  core.runtime_close(runtime);
  assert.equal((await second.closed).outcome, "cancelled");
});

test("WTS-LATE-ADMISSION: dispose a stream created after its owner closed before returning", async () => {
  const creation = deferred();
  const cleanup = deferred();
  const wire = duplex({ cancel: () => cleanup.promise });
  const { core, session, scope } = await fixture({ createStream: () => creation.promise });
  const opening = core.webtransport_open_stream({ session });
  await turn();
  core.scope_close(scope);
  creation.resolve(wire);
  let finished = false;
  void opening.then(() => { finished = true; });
  await turn();
  assert.equal(finished, false, "late host resource must drain before admission returns");
  assert.equal(wire.events.filter(([kind]) => kind === "cancel").length, 1);
  assert.equal(wire.events.filter(([kind]) => kind === "abort").length, 1);
  cleanup.resolve();
  assert.equal((await opening).outcome, "cancelled");
  assert.equal(wire.readable.locked, false);
  assert.equal(wire.writable.locked, false);
});

test("WTS-PREFLIGHT: reject unrelated handles and release admission before handshake", async () => {
  const { core, session, scope, host } = await fixture({ pendingHandshake: true });
  const unrelated = core.task_spawn({ scope }).value;
  assert.equal((await core.webtransport_open_stream({ session: unrelated })).failure.code, "invalid_handle");
  assert.equal((await core.webtransport_open_stream({ get session() { throw new Error("invalid"); } })).failure.code, "invalid_handle");
  const waiting = core.webtransport_open_stream({ session });
  core.scope_close(scope);
  assert.equal((await waiting).outcome, "cancelled");
  assert.equal(host.events.filter(([kind]) => kind === "create-bidirectional").length, 0);
  host.handshake.resolve();
});

test("WTS-ERRORS: stream read/write/FIN failures release both halves and not the session", async () => {
  for (const operation of ["read", "write", "finish"]) {
    const failure = new Error(`broken ${operation}`);
    const wire = duplex({ [operation]: () => { throw failure; } });
    const { core, session, scope, calls } = await fixture({ createStream: () => wire });
    const stream = await openedStream(core, session);
    let result;
    if (operation === "read") {
      const reading = stream.read();
      wire.input.error(failure);
      result = await reading;
    } else if (operation === "write") result = await stream.write(new Uint8Array([1]));
    else result = await stream.finish();
    assert.equal(result.outcome, "err");
    assert.match(result.failure.message, new RegExp(`broken ${operation}`));
    assert.equal((await stream.closed).outcome, "err");
    assert.equal(wire.readable.locked, false);
    assert.equal(wire.writable.locked, false);
    assert.equal(calls.join.length, 0);
    assert.equal(core.webtransport_send({ session, value: [1] }).outcome, "ok");
    core.scope_close(scope);
  }
});

test("WTS-SESSION-ERROR: propagate the parent failure to pending stream operations", async () => {
  const { core, session, host } = await fixture();
  const stream = await openedStream(core, session);
  const pending = stream.read();
  host.completion.reject(new Error("lost connection"));
  const result = await pending;
  assert.equal(result.outcome, "err");
  assert.match(result.failure.message, /lost connection/);
  assert.deepEqual(normalize(await stream.closed), normalize(result));
  core.webtransport_recv({ session });
});

test("WTS-ACQUIRE-FAILURE: release a reader when writer acquisition fails", async () => {
  const wire = duplex();
  const existingWriter = wire.writable.getWriter();
  const { core, session, scope } = await fixture({ createStream: () => wire });
  const result = await core.webtransport_open_stream({ session });
  assert.equal(result.outcome, "err");
  assert.equal(wire.readable.locked, false);
  assert.equal(wire.events.filter(([kind]) => kind === "cancel").length, 1);
  await existingWriter.abort();
  existingWriter.releaseLock();
  core.scope_close(scope);
});

test("WTS-IDLE-RESET: reclaim an idle reset stream without waiting for another caller operation", async () => {
  for (const side of ["input", "output"]) {
    const { core, session, scope, host } = await fixture();
    const stream = await openedStream(core, session);
    const wire = host.streams[0];
    wire[side].error(new Error("peer reset"));
    const outcome = await stream.closed;
    assert.equal(outcome.outcome, "err");
    assert.match(outcome.failure.message, /peer reset/);
    assert.equal(wire.readable.locked, false);
    assert.equal(wire.writable.locked, false);
    core.scope_close(scope);
  }
});

test("WTS-BYTE-BOUNDARIES: preserve view offsets and drain queued bytes after peer FIN", async () => {
  const { core, session, scope, host } = await fixture();
  const stream = await openedStream(core, session);
  const wire = host.streams[0];
  const buffer = new Uint8Array([0, 1, 2, 3]).buffer;
  assert.equal((await stream.write(new DataView(buffer, 1, 2))).outcome, "ok");
  assert.deepEqual(wire.events[0], ["write", [1, 2]]);
  assert.equal((await stream.write(new ArrayBuffer(0))).outcome, "ok");
  assert.equal((await stream.write(new Uint8Array(core.WEBTRANSPORT_STREAM_LIMITS.maxWriteBytes))).outcome, "ok");
  wire.input.enqueue(new Uint8Array([9]));
  wire.input.enqueue(new Uint8Array([10, 11]));
  wire.input.close();
  await stream.finish();
  let complete = false;
  void stream.closed.then(() => { complete = true; });
  await turn();
  assert.equal(complete, false, "peer FIN must not discard queued readable bytes");
  assert.deepEqual(Array.from((await stream.read()).value.value), [9]);
  assert.deepEqual(Array.from((await stream.read()).value.value), [10, 11]);
  assert.equal((await stream.read()).value.done, true);
  assert.equal((await stream.closed).outcome, "ok");
  core.scope_close(scope);
});
