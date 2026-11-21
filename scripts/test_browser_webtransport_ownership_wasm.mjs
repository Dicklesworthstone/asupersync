/**
 * Async WebTransport ownership over the actual SDK and checked-in WASM ABI.
 * The controlled transport supplies native Node WHATWG streams and independent
 * connection/cleanup gates. This is not browser or live HTTP/3 evidence.
 *
 * node --unhandled-rejections=strict --experimental-vm-modules --test \
 *   --test-concurrency=1 scripts/test_browser_webtransport_ownership_wasm.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { createContext, runInContext, SourceTextModule, SyntheticModule } from "node:vm";

const files = [
  ["sdk", "packages/browser/src/index.ts", true],
  ["@asupersync/browser-core", "packages/browser-core/index.js", false],
  ["./fetch.js", "packages/browser/src/fetch.ts", true],
  ["./websocket.js", "packages/browser/src/websocket.ts", true],
  ["./stream-pipe.js", "packages/browser/src/stream-pipe.ts", true],
  ["./byte-pipe.js", "packages/browser/src/byte-pipe.ts", true],
  ["./asupersync.js", "packages/browser-core/asupersync.js", false],
  ["./webtransport-streams.js", "packages/browser-core/webtransport-streams.js", false],
];
const inputs = new Map();
const hashes = {};
for (const [, path] of files) {
  const bytes = readFileSync(new URL(`../${path}`, import.meta.url));
  inputs.set(path, bytes.toString());
  hashes[path] = createHash("sha256").update(bytes).digest("hex");
}
const wasmPath = "packages/browser-core/asupersync_bg.wasm";
const wasmBytes = readFileSync(new URL(`../${wasmPath}`, import.meta.url));
hashes[wasmPath] = createHash("sha256").update(wasmBytes).digest("hex");
console.log(JSON.stringify({
  scenario_id: "browser-webtransport-async-ownership-packaged-wasm",
  evidence_scope: "actual SDK, checked-in generated JS/WASM ABI, native Node WHATWG streams, controlled transport connection",
  fault_injection: "Named fault cases inject one task_join failure and, for admission, owner closure after real task_spawn; all other ABI calls delegate to checked-in WASM.",
  no_claim: ["browser-engine execution", "live HTTP/3", "Rust rebuild", "Rust executor dispatch"],
  source_sha256: hashes,
}));

const turn = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}
function gates() {
  const all = [];
  return {
    make() { const gate = deferred(); all.push(gate); return gate; },
    release() { for (const gate of all) gate.resolve(); },
  };
}
function ok(outcome) {
  assert.equal(outcome.outcome, "ok", JSON.stringify(outcome));
  return outcome.value;
}
function cancelled(outcome) {
  assert.equal(outcome.outcome, "cancelled", JSON.stringify(outcome));
  return outcome.cancellation;
}
async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("WebTransport ownership did not settle")), 3000);
    })]);
  } finally { clearTimeout(timer); }
}
function observer(promise) {
  const state = { settled: false, value: undefined, error: undefined };
  void promise.then(value => { state.settled = true; state.value = value; },
    error => { state.settled = true; state.error = error; });
  return state;
}
function wire(options = {}) {
  const events = [];
  let input;
  const readable = new ReadableStream({
    start(controller) { input = controller; },
    cancel(reason) { events.push(["cancel", reason]); return options.cancel?.(reason); },
  }, { highWaterMark: 0 });
  const writable = new WritableStream({
    write(bytes) { events.push(["write", [...bytes]]); return options.write?.(bytes); },
    abort(reason) { events.push(["abort", reason]); return options.abort?.(reason); },
    close() { events.push(["finish"]); return options.finish?.(); },
  });
  return { readable, writable, input, events };
}

async function fixture(t, options = {}) {
  const hosts = [];
  class ControlledTransport {
    constructor(url, configuration) {
      this.url = url;
      this.configuration = configuration;
      this.events = [];
      this.wires = [];
      this.handshake = deferred();
      this.ready = this.handshake.promise;
      this.connection = deferred();
      this.closed = this.connection.promise;
      this.closeStarted = deferred();
      this.datagrams = {
        readable: new ReadableStream({
          start: controller => { this.datagramInput = controller; },
          cancel: reason => {
            this.events.push(["datagram-cancel", reason]);
            return options.datagramCancel?.(this, reason);
          },
        }, { highWaterMark: 0 }),
        writable: new WritableStream({
          write: bytes => {
            this.events.push(["datagram-write", [...bytes]]);
            return options.datagramWrite?.(this, bytes);
          },
          abort: reason => {
            this.events.push(["datagram-abort", reason]);
            return options.datagramAbort?.(this, reason);
          },
        }),
      };
      this.incomingBidirectionalStreams = new ReadableStream({
        start: controller => { this.bidirectionalInput = controller; },
        cancel: reason => {
          this.events.push(["incoming-bidi-cancel", reason]);
          return options.incomingCancel?.(this, "bidirectional", reason);
        },
      }, { highWaterMark: 0 });
      this.incomingUnidirectionalStreams = new ReadableStream({
        start: controller => { this.unidirectionalInput = controller; },
        cancel: reason => {
          this.events.push(["incoming-uni-cancel", reason]);
          return options.incomingCancel?.(this, "unidirectional", reason);
        },
      }, { highWaterMark: 0 });
      hosts.push(this);
      options.configure?.(this);
      if (!options.pendingHandshake) this.handshake.resolve();
    }
    createBidirectionalStream() {
      this.events.push(["create-bidirectional"]);
      if (options.createBidirectional) return options.createBidirectional(this);
      const endpoint = wire(options.streamOptions);
      this.wires.push(endpoint);
      return Promise.resolve(endpoint);
    }
    createUnidirectionalStream() {
      this.events.push(["create-unidirectional"]);
      const endpoint = wire(options.streamOptions);
      this.wires.push(endpoint);
      return Promise.resolve(endpoint.writable);
    }
    close(closeOptions) {
      this.events.push(["close", closeOptions]);
      this.closeStarted.resolve();
      options.close?.(this, closeOptions);
      if (!options.holdConnectionClose) this.connection.resolve();
    }
  }
  const context = createContext({
    console, AbortController, AbortSignal, ArrayBuffer, DataView, Uint8Array, URL,
    EventTarget, MessageEvent, WebSocket, WebTransport: ControlledTransport,
    TextEncoder, TextDecoder, ReadableStream, ReadableStreamDefaultReader, WritableStream, WebAssembly,
    Response, Request, structuredClone, queueMicrotask, setTimeout, clearTimeout,
    window: {}, document: {}, isSecureContext: true,
  });
  const modules = new Map();
  for (const [name, path, typescript] of files) {
    const text = inputs.get(path);
    modules.set(name, new SourceTextModule(
      typescript ? stripTypeScriptTypes(text, { mode: "transform" }) : text,
      { context, identifier: fileURLToPath(new URL(`../${path}`, import.meta.url)) },
    ));
  }
  modules.set("@asupersync/browser-core/webtransport-streams", modules.get("./webtransport-streams.js"));
  const actualBindings = modules.get("./asupersync.js");
  const abiCalls = { join: 0, forwardedJoins: 0, cancel: 0 };
  if (options.refuseFirstJoin || options.afterTaskSpawn) {
    // Interpose one explicit refusal without replacing the real ledger. The
    // rejected call has no WASM effect; every other operation reaches the
    // original generated bindings, including cancellation and the retry join.
    await actualBindings.link(specifier => { throw new Error(`unexpected generated import ${specifier}`); });
    await actualBindings.evaluate();
    const real = actualBindings.namespace;
    const names = Object.keys(real);
    const interposed = new SyntheticModule(names, function () {
      for (const name of names) {
        this.setExport(name, name === "task_join" ? (...args) => {
          if (++abiCalls.join === 1 && options.refuseFirstJoin) return JSON.stringify({
            outcome: "err", failure: {
              code: "compatibility_rejected", recoverability: "transient",
              message: "injected terminal publication refusal",
            },
          });
          abiCalls.forwardedJoins++;
          return real.task_join(...args);
        } : name === "task_cancel" ? (...args) => {
          abiCalls.cancel++;
          return real.task_cancel(...args);
        } : name === "task_spawn" ? (...args) => {
          const result = real.task_spawn(...args);
          // Unlike task_join, the raw task_spawn ABI returns a bare handle and
          // throws on failure. The public core facade supplies its Outcome.
          assert.equal(JSON.parse(result).kind, "task");
          options.afterTaskSpawn?.();
          return result;
        } : real[name]);
      }
    }, { context });
    modules.set("./asupersync.js", interposed);
  }
  const entry = modules.get("sdk");
  await entry.link(specifier => {
    assert.ok(modules.has(specifier), `unexpected module import ${specifier}`);
    return modules.get(specifier);
  });
  await entry.evaluate();
  context.sdk = entry.namespace;
  context.wasmBytes = wasmBytes;
  await runInContext("sdk.init({ module_or_path: wasmBytes })", context);
  const sdk = entry.namespace;
  const raw = actualBindings.namespace;
  const snapshot = () => JSON.parse(raw.browser_operator_snapshot());
  const runtime = ok(await sdk.createBrowserRuntime({ eagerInit: false }));
  const scope = ok(runtime.enterScope("WebTransport ownership"));
  t.after(async () => {
    await options.release?.();
    for (const host of hosts) { host.handshake.resolve(); host.connection.resolve(); }
    await bounded(runtime.closeAsync());
  });
  const open = async (owner = scope) => {
    const session = ok(owner.openWebTransport("https://transport.example.test/"));
    if (!options.pendingHandshake) ok(await session.ready());
    return { session, host: hosts.at(-1) };
  };
  return { sdk, runtime, scope, snapshot, open, hosts, abiCalls };
}

test("WASM WT owner close waits for a pending datagram write and asynchronous abort", { timeout: 10000 }, async t => {
  const hold = gates(), writeStarted = hold.make(), writeRelease = hold.make();
  const abortStarted = hold.make(), abortRelease = hold.make();
  const cancelStarted = hold.make(), cancelRelease = hold.make();
  const { scope, snapshot, open } = await fixture(t, {
    datagramWrite() { writeStarted.resolve(); return writeRelease.promise; },
    datagramAbort() { abortStarted.resolve(); return abortRelease.promise; },
    datagramCancel() { cancelStarted.resolve(); return cancelRelease.promise; },
    release: () => hold.release(),
  });
  const { session, host } = await open();
  const first = session.sendDatagram(Uint8Array.of(1, 2));
  const queued = session.sendDatagram(Uint8Array.of(3));
  await bounded(writeStarted.promise);
  const closing = scope.closeAsync(), state = observer(closing);
  await turn();
  assert.equal(state.settled, false, "owner close cannot outrun a parked native datagram write");
  assert.equal(snapshot().tasks.total, 1, "native cleanup remains owned by the actual ABI task");
  writeRelease.resolve();
  await bounded(abortStarted.promise); await turn();
  assert.equal(state.settled, false, "native abort settlement is part of owner closure");
  assert.equal(host.datagrams.writable.locked, true);
  abortRelease.resolve();
  await bounded(cancelStarted.promise); await turn();
  assert.equal(state.settled, false, "the independently pending readable cancel must also settle");
  assert.equal(host.datagrams.readable.locked, true);
  cancelRelease.resolve();
  ok(await bounded(closing));
  cancelled(await bounded(first)); cancelled(await bounded(queued));
  assert.deepEqual(host.events.filter(([kind]) => kind === "datagram-write").map(([, bytes]) => bytes), [[1, 2]]);
  assert.equal(host.events.filter(([kind]) => kind === "datagram-abort").length, 1);
  assert.equal(host.events.filter(([kind]) => kind === "datagram-cancel").length, 1);
  assert.equal(host.datagrams.readable.locked, false);
  assert.equal(host.datagrams.writable.locked, false);
  assert.equal(snapshot().tasks.total, 0);
});

test("WASM WT owner close waits for connection completion after native stream cleanup", { timeout: 10000 }, async t => {
  const { scope, snapshot, open } = await fixture(t, { holdConnectionClose: true });
  const { host } = await open();
  const closing = scope.closeAsync(), state = observer(closing);
  await bounded(host.closeStarted.promise); await turn();
  assert.equal(state.settled, false, "calling native close is not evidence that the connection closed");
  assert.equal(snapshot().tasks.total, 1);
  host.connection.resolve();
  ok(await bounded(closing));
  assert.equal(snapshot().tasks.total, 0);
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
});

test("WASM WT an already errored native datagram reader retires after connection closure", { timeout: 10000 }, async t => {
  const { scope, snapshot, open } = await fixture(t, { holdConnectionClose: true });
  const { session, host } = await open();
  const receiving = session.recvDatagram();
  const reset = new Error("native datagram peer reset");
  host.datagramInput.error(reset);
  const failure = await bounded(receiving);
  assert.equal(failure.outcome, "err");
  assert.match(failure.failure.message, /peer reset/);
  const closing = scope.closeAsync(), state = observer(closing);
  await bounded(host.closeStarted.promise); await turn();
  assert.equal(state.settled, false, "an errored datagram source does not prove the connection closed");
  assert.equal(snapshot().tasks.total, 1);
  host.connection.resolve();
  ok(await bounded(closing));
  assert.equal(host.datagrams.readable.locked, false);
  assert.equal(host.datagrams.writable.locked, false);
  assert.equal(host.events.filter(([kind]) => kind === "datagram-cancel").length, 0,
    "native cancellation of an already errored stream does not invoke its underlying source");
  assert.equal(snapshot().tasks.total, 0);
});

test("WASM WT a rejected underlying datagram cancel remains a cleanup failure until explicit retry", { timeout: 10000 }, async t => {
  const { scope, snapshot, open } = await fixture(t, {
    holdConnectionClose: true,
    datagramCancel() { return Promise.reject(new Error("underlying datagram cancel failed")); },
  });
  const { host } = await open();
  const closing = scope.closeAsync();
  await bounded(host.closeStarted.promise);
  host.connection.resolve();
  const first = await bounded(closing);
  assert.equal(first.outcome, "err", JSON.stringify(first));
  assert.match(first.failure.message, /cancel/i);
  assert.equal(snapshot().tasks.total, 1, "a genuine native cleanup failure cannot publish a successful task retirement");
  assert.equal(host.datagrams.readable.locked, false);
  assert.equal(host.datagrams.writable.locked, false);
  ok(await bounded(scope.closeAsync()));
  assert.equal(snapshot().tasks.total, 0);
  assert.equal(host.events.filter(([kind]) => kind === "datagram-cancel").length, 1);
  assert.equal(host.events.filter(([kind]) => kind === "datagram-abort").length, 1);
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
});

test("WASM WT a throwing ready getter still closes and retains the constructed connection", { timeout: 10000 }, async t => {
  const { scope, snapshot, hosts } = await fixture(t, {
    holdConnectionClose: true,
    configure(host) { Object.defineProperty(host, "ready", { get() { throw new Error("host ready getter failed"); } }); },
  });
  const opened = scope.openWebTransport("https://transport.example.test/ready-getter");
  assert.equal((await bounded(ok(opened).ready())).outcome, "err");
  assert.equal(hosts.length, 1);
  const host = hosts[0];
  await bounded(host.closeStarted.promise);
  const closing = scope.closeAsync(), state = observer(closing);
  await turn();
  assert.equal(state.settled, false, "a failed readiness lookup cannot detach the already constructed connection");
  // Preserve the existing automatic operation-error publication contract. Its
  // accepted task join is independent of the retained native cleanup owner.
  assert.equal(snapshot().tasks.total, 0);
  host.connection.resolve();
  ok(await bounded(closing));
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
  assert.equal(snapshot().tasks.total, 0);
});

test("WASM WT an unobservable closed promise keeps cleanup failed across explicit retries", { timeout: 10000 }, async t => {
  const { scope, snapshot, hosts } = await fixture(t, {
    holdConnectionClose: true,
    configure(host) { Object.defineProperty(host, "closed", { get() { throw new Error("host closed getter failed"); } }); },
  });
  const opened = scope.openWebTransport("https://transport.example.test/closed-getter");
  ok(opened);
  const host = hosts[0];
  await bounded(host.closeStarted.promise);
  const first = await bounded(scope.closeAsync());
  assert.equal(first.outcome, "err", JSON.stringify(first));
  assert.equal(snapshot().tasks.total, 1);
  host.connection.resolve();
  const retry = await bounded(scope.closeAsync());
  assert.equal(retry.outcome, "err", "settling a promise the SDK could never observe cannot invent quiescence evidence");
  assert.equal(snapshot().tasks.total, 1);
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
});

test("WASM WT a datagram acquisition that hides an acquired native lock cannot retry into success", { timeout: 10000 }, async t => {
  let hiddenReader;
  const { scope, snapshot, hosts } = await fixture(t, {
    configure(host) {
      const acquire = host.datagrams.readable.getReader.bind(host.datagrams.readable);
      host.datagrams.readable.getReader = () => {
        hiddenReader = acquire();
        throw new Error("native reader was acquired but not returned");
      };
    },
    async release() {
      if (hiddenReader) {
        await hiddenReader.cancel("fixture teardown");
        hiddenReader.releaseLock();
      }
    },
  });
  const session = ok(scope.openWebTransport("https://transport.example.test/hidden-reader"));
  assert.equal((await bounded(session.ready())).outcome, "err");
  assert.ok(hiddenReader);
  assert.equal(hosts[0].datagrams.readable.locked, true);
  const first = await bounded(scope.closeAsync());
  assert.equal(first.outcome, "err", JSON.stringify(first));
  assert.equal(snapshot().tasks.total, 1);
  const retry = await bounded(scope.closeAsync());
  assert.equal(retry.outcome, "err", "an unknown native lock has no safe SDK release retry");
  assert.equal(snapshot().tasks.total, 1);
  assert.equal(hosts[0].datagrams.readable.locked, true);
  assert.equal(hosts[0].events.filter(([kind]) => kind === "close").length, 1);
});

test("WASM WT pre-ready closure settles parked operations and prevents late native lock acquisition", { timeout: 10000 }, async t => {
  const { scope, snapshot, open } = await fixture(t, { pendingHandshake: true });
  const { session, host } = await open();
  const acquisitions = { reader: 0, writer: 0 };
  const reader = host.datagrams.readable.getReader.bind(host.datagrams.readable);
  const writer = host.datagrams.writable.getWriter.bind(host.datagrams.writable);
  host.datagrams.readable.getReader = (...args) => { acquisitions.reader++; return reader(...args); };
  host.datagrams.writable.getWriter = (...args) => { acquisitions.writer++; return writer(...args); };
  const operations = [session.ready(), session.recvDatagram(), session.sendDatagram(Uint8Array.of(6)), session.openStream()];
  await turn();
  assert.deepEqual(acquisitions, { reader: 0, writer: 0 });
  // The connection's closed promise resolves independently. An indefinitely
  // pending ready promise must not acquire new locks after terminal ownership.
  ok(await bounded(scope.closeAsync()));
  for (const result of await Promise.all(operations)) cancelled(result);
  assert.equal(snapshot().tasks.total, 0);
  host.handshake.resolve(); await turn();
  assert.deepEqual(acquisitions, { reader: 0, writer: 0 });
  assert.equal(host.datagrams.readable.locked, false);
  assert.equal(host.datagrams.writable.locked, false);
  assert.equal(host.events.filter(([kind]) => kind === "datagram-write" || kind === "create-bidirectional").length, 0);
});

test("WASM WT draining owners reject new sessions and suppress new datagram and reliable I/O", { timeout: 10000 }, async t => {
  const { scope, snapshot, open, hosts } = await fixture(t, { holdConnectionClose: true });
  const { session, host } = await open();
  const closing = scope.closeAsync();
  await bounded(host.closeStarted.promise);
  const refused = scope.openWebTransport("https://transport.example.test/late");
  assert.equal(refused.outcome, "err", JSON.stringify(refused));
  const descendant = scope.enterScope("created during drain");
  if (descendant.outcome === "ok") {
    assert.equal(descendant.value.openWebTransport("https://transport.example.test/child").outcome, "err");
  }
  assert.equal(hosts.length, 1, "refused admission cannot construct another host transport");
  assert.notEqual((await session.sendDatagram(Uint8Array.of(99))).outcome, "ok");
  assert.notEqual((await session.openStream()).outcome, "ok");
  assert.notEqual((await session.acceptUnidirectionalStream()).outcome, "ok");
  assert.equal(host.events.filter(([kind]) => kind === "datagram-write" || kind === "create-bidirectional").length, 0);
  host.connection.resolve();
  ok(await bounded(closing));
  assert.equal(snapshot().tasks.total, 0);
});

test("WASM WT drain includes reliable I/O, pending accept, late creation and late endpoint cleanup", { timeout: 10000 }, async t => {
  const hold = gates(), writeStarted = hold.make(), writeRelease = hold.make();
  const abortStarted = hold.make(), abortRelease = hold.make();
  const incomingStarted = hold.make(), incomingRelease = hold.make();
  const createStarted = hold.make(), creation = deferred(), lateAbortStarted = hold.make(), lateAbortRelease = hold.make();
  const active = wire({
    write() { writeStarted.resolve(); return writeRelease.promise; },
    abort() { abortStarted.resolve(); return abortRelease.promise; },
  });
  const late = wire({ abort() { lateAbortStarted.resolve(); return lateAbortRelease.promise; } });
  let creates = 0;
  const { scope, snapshot, open } = await fixture(t, {
    createBidirectional() {
      if (++creates === 1) return Promise.resolve(active);
      createStarted.resolve(); return creation.promise;
    },
    incomingCancel() { incomingStarted.resolve(); return incomingRelease.promise; },
    release() { hold.release(); creation.resolve(late); },
  });
  const { session, host } = await open();
  const stream = ok(await session.openStream());
  const writing = stream.write(Uint8Array.of(5));
  await bounded(writeStarted.promise);
  const creating = session.openStream();
  const accepting = session.acceptUnidirectionalStream();
  await bounded(createStarted.promise); await turn();
  assert.equal(host.incomingUnidirectionalStreams.locked, true);
  const closing = scope.closeAsync(), state = observer(closing);
  await bounded(incomingStarted.promise); await turn();
  assert.equal(state.settled, false, "owner retains active and pending reliable operations");
  assert.equal(snapshot().tasks.total, 1);
  writeRelease.resolve(); await bounded(abortStarted.promise); abortRelease.resolve();
  incomingRelease.resolve(); await turn();
  assert.equal(state.settled, false, "an unresolved host creation still owns a reservation");
  creation.resolve(late); await bounded(lateAbortStarted.promise); await turn();
  assert.equal(state.settled, false, "late endpoints must drain before their admission is released");
  lateAbortRelease.resolve();
  ok(await bounded(closing));
  for (const result of await Promise.all([writing, stream.closed, creating, accepting])) cancelled(result);
  for (const endpoint of [active, late]) {
    assert.equal(endpoint.readable.locked, false);
    assert.equal(endpoint.writable.locked, false);
    assert.equal(endpoint.events.filter(([kind]) => kind === "abort").length, 1);
  }
  assert.equal(host.incomingUnidirectionalStreams.locked, false);
  assert.equal(snapshot().tasks.total, 0);
});

test("WASM WT withScopeAsync preserves its result only after owned reliable cleanup", { timeout: 10000 }, async t => {
  const hold = gates(), writeStarted = hold.make(), writeRelease = hold.make();
  const abortStarted = hold.make(), abortRelease = hold.make();
  const { runtime, snapshot, open } = await fixture(t, {
    streamOptions: {
      write() { writeStarted.resolve(); return writeRelease.promise; },
      abort() { abortStarted.resolve(); return abortRelease.promise; },
    },
    release: () => hold.release(),
  });
  const result = Object.freeze({ outcome: "ok", value: "callback result" });
  let writing, stream;
  const bracket = runtime.withScopeAsync(async scope => {
    const { session } = await open(scope);
    stream = ok(await session.openStream());
    writing = stream.write(Uint8Array.of(7));
    await writeStarted.promise;
    return result;
  });
  const state = observer(bracket);
  await bounded(writeStarted.promise); await turn();
  assert.equal(state.settled, false, "callback completion does not release the WebTransport owner");
  assert.equal(snapshot().tasks.total, 1);
  writeRelease.resolve(); await bounded(abortStarted.promise); await turn();
  assert.equal(state.settled, false);
  abortRelease.resolve();
  assert.equal(await bounded(bracket), result);
  cancelled(await writing); cancelled(await stream.closed);
  assert.equal(snapshot().tasks.total, 0);
});

test("WASM WT withScopeAsync also drains a callback that explicitly closed its scope", { timeout: 10000 }, async t => {
  const hold = gates(), writeStarted = hold.make(), writeRelease = hold.make();
  const { runtime, snapshot, open } = await fixture(t, {
    streamOptions: { write() { writeStarted.resolve(); return writeRelease.promise; } },
    release: () => hold.release(),
  });
  const result = Object.freeze({ outcome: "ok", value: "explicit scope close" });
  let stream, writing, host;
  const bracket = runtime.withScopeAsync(async scope => {
    const opened = await open(scope);
    host = opened.host;
    stream = ok(await opened.session.openStream());
    writing = stream.write(Uint8Array.of(23));
    await writeStarted.promise;
    ok(scope.close());
    return result;
  });
  const state = observer(bracket);
  await bounded(writeStarted.promise); await turn();
  assert.equal(state.settled, false, "positive synchronous-close evidence does not prove native cleanup finished");
  assert.equal(host.wires[0].writable.locked, true);
  writeRelease.resolve();
  assert.equal(await bounded(bracket), result);
  cancelled(await writing); cancelled(await stream.closed);
  assert.equal(host.wires[0].readable.locked, false);
  assert.equal(host.wires[0].writable.locked, false);
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
  assert.equal(snapshot().tasks.total, 0);
});

test("WASM WT a self-closed scope retains an explicit cleanup retry after a lock release failure", { timeout: 10000 }, async t => {
  const endpoint = wire();
  let releaseCalls = 0;
  const acquire = endpoint.writable.getWriter.bind(endpoint.writable);
  endpoint.writable.getWriter = () => {
    const writer = acquire();
    const release = writer.releaseLock.bind(writer);
    writer.releaseLock = () => {
      if (++releaseCalls === 1) throw new Error("self-closed scope release failed");
      release();
    };
    return writer;
  };
  const { sdk, runtime, snapshot, open } = await fixture(t, { createBidirectional: () => Promise.resolve(endpoint) });
  const result = Object.freeze({ outcome: "ok", value: "retain callback completion" });
  let host;
  const completion = await runtime.withScopeAsync(async scope => {
    const opened = await open(scope);
    host = opened.host;
    ok(await opened.session.openStream());
    ok(scope.close());
    return result;
  }).then(value => ({ value }), error => ({ error }));
  const error = completion.error;
  assert.ok(error instanceof sdk.BrowserScopeCleanupError);
  assert.equal(error.cleanupOutcome.outcome, "err");
  assert.equal(error.bodyCompletion.kind, "returned");
  assert.equal(error.bodyCompletion.outcome, result);
  assert.equal(endpoint.writable.locked, true);
  assert.equal(releaseCalls, 1);
  ok(await bounded(error.scope.closeAsync()));
  assert.equal(endpoint.writable.locked, false);
  assert.equal(endpoint.readable.locked, false);
  assert.equal(releaseCalls, 2);
  assert.equal(endpoint.events.filter(([kind]) => kind === "abort").length, 1);
  assert.equal(endpoint.events.filter(([kind]) => kind === "cancel").length, 1);
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
  assert.equal(snapshot().tasks.total, 0);
});

test("WASM WT descendant closure preserves a sibling session and its native streams", { timeout: 10000 }, async t => {
  const { runtime, scope, snapshot, open } = await fixture(t);
  const child = ok(scope.enterScope("child"));
  const sibling = ok(runtime.enterScope("sibling"));
  const a = await open(child), b = await open(sibling);
  const stream = ok(await a.session.openStream());
  const reading = stream.read();
  ok(await bounded(scope.closeAsync()));
  cancelled(await bounded(reading)); cancelled(await bounded(stream.closed));
  assert.equal(snapshot().tasks.total, 1, "only the sibling task remains");
  assert.equal(a.host.events.filter(([kind]) => kind === "close").length, 1);
  assert.equal(b.host.events.filter(([kind]) => kind === "close").length, 0);
  ok(await b.session.sendDatagram(Uint8Array.of(9)));
  const survivor = ok(await b.session.openUnidirectionalStream());
  ok(await survivor.write(Uint8Array.of(8)));
  ok(await survivor.finish());
  ok(await bounded(sibling.closeAsync()));
  assert.equal(snapshot().tasks.total, 0);
});

test("WASM WT explicit closeAsync returns one cleanup receipt after the connection closes", { timeout: 10000 }, async t => {
  const { scope, snapshot, open } = await fixture(t, { holdConnectionClose: true });
  const { session, host } = await open();
  assert.equal(typeof session.closeAsync, "function");
  const first = session.closeAsync({ reason: "finished" });
  const second = session.closeAsync({ reason: "duplicate" });
  const state = observer(first);
  await bounded(host.closeStarted.promise); await turn();
  assert.equal(state.settled, false);
  assert.equal(snapshot().tasks.total, 1);
  host.connection.resolve();
  ok(await bounded(first)); ok(await bounded(second));
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
  assert.equal(snapshot().tasks.total, 0);
  ok(await bounded(scope.closeAsync()));
});

for (const token of [false, true]) {
  test(`WASM WT cancelAsync preserves ${token ? "CancellationToken" : "custom kind"} attribution and waits for cleanup`, { timeout: 10000 }, async t => {
    const { sdk, scope, snapshot, open } = await fixture(t, { holdConnectionClose: true });
    const { session, host } = await open();
    const stream = ok(await session.openStream());
    const receiving = session.recvDatagram();
    const reading = stream.read();
    const kind = "application_navigation", message = "switching workspace";
    const closing = token
      ? session.cancelAsync(new sdk.CancellationToken(kind, message))
      : session.cancelAsync(kind, message);
    const state = observer(closing);
    await bounded(host.closeStarted.promise); await turn();
    assert.equal(state.settled, false);
    assert.equal(snapshot().tasks.total, 1);
    for (const result of await Promise.all([receiving, reading, stream.closed])) {
      const cause = cancelled(result);
      assert.equal(cause.kind, kind);
      assert.equal(cause.message, message);
    }
    host.connection.resolve();
    ok(await bounded(closing));
    assert.equal(snapshot().tasks.total, 0);
    assert.equal(host.events.filter(([event]) => event === "close").length, 1);
    ok(await bounded(scope.closeAsync()));
  });
}

test("WASM WT a throwing native close retains ownership until an explicit successful retry", { timeout: 10000 }, async t => {
  let attempts = 0;
  const { scope, snapshot, open } = await fixture(t, {
    close() { if (++attempts === 1) throw new Error("native close temporarily refused"); },
  });
  const { session, host } = await open();
  const first = await bounded(session.closeAsync());
  assert.equal(first.outcome, "err", JSON.stringify(first));
  assert.match(first.failure.message, /native close temporarily refused/);
  await turn();
  assert.equal(attempts, 1, "failed host shutdown cannot silently retry itself into success");
  assert.equal(snapshot().tasks.total, 1);
  ok(await bounded(session.closeAsync()));
  assert.equal(attempts, 2);
  assert.equal(host.events.filter(([kind]) => kind === "datagram-cancel").length, 1);
  assert.equal(host.events.filter(([kind]) => kind === "datagram-abort").length, 1);
  assert.equal(snapshot().tasks.total, 0);
  ok(await bounded(scope.closeAsync()));
});

test("WASM WT asynchronous owner close also drains an earlier synchronous session close", { timeout: 10000 }, async t => {
  const hold = gates(), writeStarted = hold.make(), writeRelease = hold.make();
  const { scope, open } = await fixture(t, {
    streamOptions: { write() { writeStarted.resolve(); return writeRelease.promise; } },
    release: () => hold.release(),
  });
  const { session, host } = await open();
  const stream = ok(await session.openStream());
  const writing = stream.write(Uint8Array.of(4));
  await bounded(writeStarted.promise);
  const synchronous = session.close({ reason: "legacy synchronous close" });
  assert.ok(["ok", "cancelled"].includes(synchronous.outcome), JSON.stringify(synchronous));
  const closing = scope.closeAsync(), state = observer(closing);
  await turn();
  assert.equal(state.settled, false, "a synchronous API cannot erase unfinished native cleanup from async ownership");
  writeRelease.resolve();
  ok(await bounded(closing));
  cancelled(await writing); cancelled(await stream.closed);
  assert.equal(host.wires[0].writable.locked, false);
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
});

test("WASM WT runtime close retains unfinished cleanup from a synchronously closed descendant", { timeout: 10000 }, async t => {
  const hold = gates(), writeStarted = hold.make(), writeRelease = hold.make();
  const { runtime, scope, snapshot, open } = await fixture(t, {
    streamOptions: { write() { writeStarted.resolve(); return writeRelease.promise; } },
    release: () => hold.release(),
  });
  const child = ok(scope.enterScope("legacy child"));
  const { session, host } = await open(child);
  const stream = ok(await session.openStream());
  const writing = stream.write(Uint8Array.of(17));
  await bounded(writeStarted.promise);
  ok(child.close());
  const closing = runtime.closeAsync(), state = observer(closing);
  await turn();
  assert.equal(state.settled, false, "deleting a child ledger entry cannot detach its native cleanup from the runtime");
  writeRelease.resolve();
  ok(await bounded(closing));
  cancelled(await writing); cancelled(await stream.closed);
  assert.equal(host.wires[0].writable.locked, false);
  assert.equal(host.wires[0].readable.locked, false);
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
  assert.equal(snapshot().tasks.total, 0);
});

test("WASM WT closeAsync preserves the task on ABI refusal and permits an explicit retry", { timeout: 10000 }, async t => {
  const { sdk, scope, snapshot, open } = await fixture(t);
  const { session, host } = await open();
  assert.equal(typeof session.closeAsync, "function");
  const current = sdk.abiVersion();
  const incompatible = { major: current.major + 1, minor: 0 };
  const first = await bounded(session.closeAsync({}, incompatible));
  assert.equal(first.outcome, "err", JSON.stringify(first));
  assert.equal(snapshot().tasks.total, 1, "a refused ABI transition must retain the original task");
  ok(await bounded(session.closeAsync()));
  assert.equal(snapshot().tasks.total, 0);
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1, "publication retry must not repeat host shutdown");
  ok(await bounded(scope.closeAsync()));
});

test("WASM WT one injected publication refusal retains the real ledger task after host drain", { timeout: 10000 }, async t => {
  const hold = gates(), writeStarted = hold.make(), writeRelease = hold.make();
  const { scope, snapshot, open, abiCalls } = await fixture(t, {
    refuseFirstJoin: true,
    holdConnectionClose: true,
    streamOptions: { write() { writeStarted.resolve(); return writeRelease.promise; } },
    release: () => hold.release(),
  });
  const { session, host } = await open();
  const stream = ok(await session.openStream());
  const writing = stream.write(Uint8Array.of(31));
  await bounded(writeStarted.promise);
  const closing = session.closeAsync();
  await bounded(host.closeStarted.promise); await turn();
  assert.equal(abiCalls.join, 0, "terminal publication cannot start while native write is parked");
  assert.equal(snapshot().tasks.total, 1);
  writeRelease.resolve();
  cancelled(await bounded(writing)); cancelled(await bounded(stream.closed));
  assert.equal(abiCalls.join, 0, "terminal publication must also await connection closure");
  host.connection.resolve();
  const refused = await bounded(closing);
  assert.equal(refused.outcome, "err");
  assert.equal(refused.failure.message, "injected terminal publication refusal");
  assert.deepEqual(abiCalls, { join: 1, forwardedJoins: 0, cancel: 1 });
  assert.equal(snapshot().tasks.total, 1, "the injected refusal did not remove the actual WASM task");
  assert.equal(host.wires[0].readable.locked, false);
  assert.equal(host.wires[0].writable.locked, false);
  ok(await bounded(session.closeAsync()));
  assert.deepEqual(abiCalls, { join: 2, forwardedJoins: 1, cancel: 1 });
  assert.equal(snapshot().tasks.total, 0, "the retry's genuine WASM join retires the retained task");
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
  assert.equal(host.events.filter(([kind]) => kind === "datagram-cancel").length, 1);
  assert.equal(host.events.filter(([kind]) => kind === "datagram-abort").length, 1);
  ok(await bounded(scope.closeAsync()));
});

test("WASM WT owner closure after actual task admission retains a refused task-only retirement", { timeout: 10000 }, async t => {
  let owner, closing;
  const { scope, snapshot, hosts, abiCalls } = await fixture(t, {
    refuseFirstJoin: true,
    afterTaskSpawn() { closing = owner.closeAsync(); },
  });
  owner = scope;
  cancelled(scope.openWebTransport("https://transport.example.test/admission-race"));
  assert.equal(hosts.length, 0, "closing admission cannot construct a connection");
  const first = await bounded(closing);
  assert.equal(first.outcome, "err", JSON.stringify(first));
  assert.equal(first.failure.message, "injected terminal publication refusal");
  assert.equal(snapshot().tasks.total, 1, "a task with no host resource still needs an accepted terminal join");
  assert.deepEqual(abiCalls, { join: 1, forwardedJoins: 0, cancel: 1 });
  ok(await bounded(scope.closeAsync()));
  assert.equal(snapshot().tasks.total, 0);
  assert.deepEqual(abiCalls, { join: 2, forwardedJoins: 1, cancel: 1 });
});

test("WASM WT owner-close ABI refusal is retryable after host cleanup without replaying effects", { timeout: 10000 }, async t => {
  const { sdk, scope, snapshot, open } = await fixture(t);
  const { host } = await open();
  const current = sdk.abiVersion();
  const first = await bounded(scope.closeAsync({ major: current.major + 1, minor: 0 }));
  assert.equal(first.outcome, "err", JSON.stringify(first));
  ok(await bounded(scope.closeAsync()));
  assert.equal(snapshot().tasks.total, 0);
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
});

test("WASM WT failed reliable lock release retains its real task until explicit cleanup retry", { timeout: 10000 }, async t => {
  const endpoint = wire();
  let releaseCalls = 0;
  const acquire = endpoint.writable.getWriter.bind(endpoint.writable);
  endpoint.writable.getWriter = () => {
    const writer = acquire();
    const release = writer.releaseLock.bind(writer);
    writer.releaseLock = () => {
      if (++releaseCalls === 1) throw new Error("temporary native release failure");
      release();
    };
    return writer;
  };
  const { scope, snapshot, open } = await fixture(t, { createBidirectional: () => Promise.resolve(endpoint) });
  const { session, host } = await open();
  ok(await session.openStream());
  const first = await bounded(session.closeAsync());
  assert.equal(first.outcome, "err", JSON.stringify(first));
  assert.equal(snapshot().tasks.total, 1, "unreleased native ownership cannot be reported as a retired ABI task");
  assert.equal(endpoint.writable.locked, true);
  assert.equal(releaseCalls, 1, "the first receipt must expose failure before a caller retries");
  ok(await bounded(session.closeAsync()));
  assert.equal(releaseCalls, 2);
  assert.equal(endpoint.readable.locked, false);
  assert.equal(endpoint.writable.locked, false);
  assert.equal(endpoint.events.filter(([kind]) => kind === "abort").length, 1);
  assert.equal(endpoint.events.filter(([kind]) => kind === "cancel").length, 1);
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
  assert.equal(snapshot().tasks.total, 0);
  ok(await bounded(scope.closeAsync()));
});

test("WASM WT native reliable abort failure is exposed once and does not replay cancellation", { timeout: 10000 }, async t => {
  const endpoint = wire({ abort() { return Promise.reject(new Error("native reliable abort failed")); } });
  const { scope, snapshot, open } = await fixture(t, { createBidirectional: () => Promise.resolve(endpoint) });
  const { session, host } = await open();
  const stream = ok(await session.openStream());
  const first = await bounded(scope.closeAsync());
  assert.equal(first.outcome, "err", JSON.stringify(first));
  assert.match(first.failure.message, /abort|cleanup/i);
  assert.equal(endpoint.readable.locked, false);
  assert.equal(endpoint.writable.locked, false);
  cancelled(await stream.closed);
  ok(await bounded(scope.closeAsync()));
  assert.equal(endpoint.events.filter(([kind]) => kind === "abort").length, 1);
  assert.equal(endpoint.events.filter(([kind]) => kind === "cancel").length, 1);
  assert.equal(host.events.filter(([kind]) => kind === "close").length, 1);
  assert.equal(snapshot().tasks.total, 0);
});
