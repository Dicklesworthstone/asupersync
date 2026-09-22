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
console.log(JSON.stringify({
  scenario_id: "browser-webtransport-host-lifecycle",
  bead_id: "N/A",
  source_sha256: createHash("sha256").update(source).digest("hex"),
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
  const calls = { join: [], cancel: [], scopeClose: [] };
  let nextTask = 1;

  // Real stream locking, queued reads, cancellation and write rejection;
  // a controlled session lifecycle, not an HTTP/3 implementation.
  class ControlledTransport {
    constructor() {
      this.events = [];
      this.completion = deferred();
      this.closed = this.completion.promise;
      this.ready = Promise.resolve();
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

    close(info = {}) {
      this.events.push(["close", info.reason]);
      this.completion.resolve(info);
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
  await module.link((specifier) => {
    assert.equal(specifier, "./asupersync.js");
    return bindings;
  });
  await module.evaluate();
  const core = module.namespace;
  const scope = new core.RegionHandle({
    kind: "region", slot: 100, generation: 1, owner_token: "42",
  });
  const opened = core.webtransport_open({ scope, url: "https://transport.example.test/" });
  assert.equal(opened.outcome, "ok");
  await turn();
  return { core, calls, hosts, host: hosts[0], scope, session: opened.value };
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
