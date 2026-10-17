/** Header-level structured concurrency for existing, scope-owned fetches. */
import type { Outcome } from "@asupersync/browser-core";
import { BROWSER_FETCH_LIMITS, type BrowserFetchResponse, type FetchStreamHandle } from "./fetch.js";

export interface FetchResponseWinner {
  readonly index: number;
  readonly response: BrowserFetchResponse;
  /** The original scope-owned fetch. Its manual read() has been transferred. */
  readonly fetch: FetchStreamHandle;
  /** Remaining native body; also returned by fetch.toReadableStream(). */
  readonly body: ReadableStream<Uint8Array>;
}

export interface FetchResponseRace {
  /** Resolves only after losing fetches have settled owned cleanup. */
  readonly result: Promise<Outcome<FetchResponseWinner>>;
  /** Before transfer, cancels every member and joins cleanup. After transfer, no effect. */
  cancel(reason?: string): Promise<Outcome<void>>;
}

export interface FetchResponseJoin {
  /** All response headers in input order, or failure after every member drains. */
  readonly result: Promise<Outcome<readonly FetchResponseWinner[]>>;
  /** Before transfer, cancels every member and joins cleanup. After transfer, no effect. */
  cancel(reason?: string): Promise<Outcome<void>>;
}

export interface FetchResponseGroupOptions {
  /** Borrowed unmodified same-realm signal, observed until ownership transfers. */
  signal?: AbortSignal | null;
}

type Selection = FetchResponseWinner | readonly FetchResponseWinner[];
interface ResponseGroup {
  readonly result: Promise<Outcome<Selection>>;
  cancel(reason?: string): Promise<Outcome<void>>;
}

type Failure = Exclude<Outcome<never>, { outcome: "ok" }>;
// Match the native Outcome lattice. Expected loser cancellation is filtered by
// drain(), but an observed owner cancellation must dominate an ordinary error.
const severity = (outcome: Failure): number => outcome.outcome === "panicked" ? 3 : outcome.outcome === "cancelled" ? 2 : 1;
const STREAM = typeof ReadableStream === "undefined" ? undefined : ReadableStream;
const LOCKED = STREAM && Object.getOwnPropertyDescriptor(STREAM.prototype, "locked")?.get;
const GET_READER = STREAM?.prototype.getReader;
const READER = typeof ReadableStreamDefaultReader === "undefined" ? undefined : ReadableStreamDefaultReader;
const CANCEL = READER?.prototype.cancel;
const RELEASE = READER?.prototype.releaseLock;
const READER_CLOSED = READER && Object.getOwnPropertyDescriptor(READER.prototype, "closed")?.get;
const SIGNAL = typeof AbortSignal === "undefined" ? undefined : AbortSignal;
const ANY_SIGNAL = SIGNAL?.any;
const ABORTED = SIGNAL && Object.getOwnPropertyDescriptor(SIGNAL.prototype, "aborted")?.get;
const TARGET = typeof EventTarget === "undefined" ? undefined : EventTarget;
const ADD_LISTENER = TARGET?.prototype.addEventListener;
const REMOVE_LISTENER = TARGET?.prototype.removeEventListener;
const ok = <T>(value: T): Outcome<T> => Object.freeze({ outcome: "ok", value });
const fail = (message: string): Failure => Object.freeze({ outcome: "err", failure: Object.freeze({
  code: "compatibility_rejected", recoverability: "permanent", message,
}) });
const internal = (message: string): Failure => Object.freeze({ outcome: "err", failure: Object.freeze({
  code: "internal_failure", recoverability: "unknown", message,
}) });

function checked<T>(value: unknown): Outcome<T> {
  try {
    if (!value || typeof value !== "object") return internal("invalid fetch group outcome");
    const outcome = value as Outcome<T>;
    switch (outcome.outcome) {
      case "ok": return ok(outcome.value);
      case "err": {
        const { code, recoverability, message } = outcome.failure;
        if (!["capability_denied", "invalid_handle", "decode_failure", "compatibility_rejected", "internal_failure"].includes(code)
            || !["transient", "permanent", "unknown"].includes(recoverability) || typeof message !== "string") break;
        return Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability, message }) });
      }
      case "panicked": {
        const message = outcome.message;
        if (typeof message === "string") return Object.freeze({ outcome: "panicked", message });
        break;
      }
      case "cancelled": {
        const { kind, phase, origin_region, origin_task, timestamp_nanos, message, truncated } = outcome.cancellation;
        if (typeof kind !== "string" || !["requested", "cancelling", "finalizing", "completed"].includes(phase)
            || typeof origin_region !== "string" || !(origin_task === null || typeof origin_task === "string")
            || !(typeof timestamp_nanos === "bigint" || typeof timestamp_nanos === "number" && Number.isFinite(timestamp_nanos))
            || !(message === null || typeof message === "string") || typeof truncated !== "boolean") break;
        return Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
          kind, phase, origin_region, origin_task, timestamp_nanos, message, truncated,
        }) });
      }
    }
  } catch { /* Reject presentation hooks and malformed envelopes without echoing them. */ }
  return internal("invalid fetch group outcome");
}

function cancellation(reason: string, join: boolean, signal = false): Failure {
  // A composite outcome, not a new task or a claim about a member's ABI receipt.
  return Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
    kind: join ? (signal ? "fetch_join_signal" : "fetch_join_cancel")
      : (signal ? "fetch_race_signal" : "fetch_race_cancel"), phase: "completed",
    origin_region: join ? "browser-fetch-join" : "browser-fetch-race",
    origin_task: null, timestamp_nanos: 0, message: reason, truncated: false,
  }) });
}

interface Member {
  fetch: FetchStreamHandle;
  body: ReadableStream<Uint8Array>;
  reader: ReadableStreamDefaultReader<Uint8Array>;
  response: () => Promise<Outcome<BrowserFetchResponse>>;
  closed: Promise<Outcome<void>>;
  retire?: () => Promise<Outcome<void>>;
  terminal?: Outcome<void>;
  head?: Outcome<BrowserFetchResponse>;
  draining?: Promise<Outcome<void>>;
}

/**
 * Race the headers of 1..64 already-started owned fetches. The first observed
 * response OR failure wins; HTTP error statuses remain ordinary responses.
 * Losers are cancelled in parallel and drained before result resolves. Any
 * cleanup/publication refusal fails the race and drains the proposed winner.
 * Winner failure or caller cancellation during that drain also drains all work.
 * Failures strengthen as Panicked > Cancelled > Err; successful loser
 * cancellation is cleanup, not an owner cancellation.
 * When a member supplies retire(), its independent cleanup receipt is joined
 * alongside native reader cancellation and closed. A failed retirement prevents
 * ownership transfer even when closed preserves an earlier cancellation. An ok
 * retirement never suppresses an operation failure. Older handles retain their
 * native-cancellation/closed boundary; no stronger task-ABI receipt is implied.
 *
 * An optional AbortSignal also cancels and drains every member, including a
 * proposed winner still waiting for loser cleanup. A pre-aborted signal skips
 * response methods after acquiring the inputs. Native AbortSignal.any is
 * required only when a signal is supplied. A private dependent signal prevents
 * earlier caller listeners from suppressing cancellation. The caller's signal
 * is not mutated, its reason is not inspected, and the observer is removed at
 * settlement. Callers may supply their own timeout signal; no timer is created.
 *
 * No request, timer, runtime task, retry or additional authority is created.
 * Requests (including POSTs) have already been explicitly admitted by their
 * scopes; cancelling cannot undo transmitted effects. This is not a body race.
 *
 * A pre-existing member failure is not suppressed in favor of a live response.
 * Body consumption transfers to native streams without reading ahead. Earlier
 * manual reads are not undone; the winner receives the remaining body. Do not
 * consume the original handles concurrently. Duplicate or locked bodies are
 * refused; partial setup releases acquired locks without cancelling fetches.
 * A conversion already performed during refused setup cannot be undone: use
 * that fetch's toReadableStream(), not read(), to resume consumption.
 *
 * After successful result delivery, the caller owns the winner's body/cleanup.
 * Race.cancel() then does nothing; scope shutdown and winner.fetch.cancel()
 * still work. A nonsettling host keeps result/cancel pending. Input ordering
 * breaks ties between responses already ready at registration, not network races.
 */
export function raceFetchResponses(
  fetches: readonly FetchStreamHandle[], options: FetchResponseGroupOptions = {},
): Outcome<FetchResponseRace> {
  return responseGroup(fetches, false, options);
}

/**
 * Join the headers of 0..64 existing owned fetches without reading their bodies.
 * Success transfers all remaining bodies in input order, independently of
 * response completion order. Any member failure (including an already-ready
 * body's failure while another header is pending) cancels and drains all work.
 * HTTP error statuses are responses, not automatic failures. Empty input is an
 * immediate successful identity, even on hosts without native stream readers.
 *
 * Shares raceFetchResponses' exclusive reader ownership, refusal/cleanup rules,
 * signal cancellation, original scope authority and no-read-ahead bounds.
 * Empty input remains successful even with a valid pre-aborted signal.
 * Does not buffer responses,
 * start requests, or join body EOF: callers must consume/cancel every returned
 * body and await each original fetch.closed after successful transfer.
 */
export function joinFetchResponses(
  fetches: readonly FetchStreamHandle[], options: FetchResponseGroupOptions = {},
): Outcome<FetchResponseJoin> {
  return responseGroup(fetches, true, options);
}

function responseGroup(fetches: readonly FetchStreamHandle[], join: false, options: FetchResponseGroupOptions): Outcome<FetchResponseRace>;
function responseGroup(fetches: readonly FetchStreamHandle[], join: true, options: FetchResponseGroupOptions): Outcome<FetchResponseJoin>;
function responseGroup(fetches: readonly FetchStreamHandle[], join: boolean, options: FetchResponseGroupOptions): Outcome<ResponseGroup> {
  const members: Member[] = [];
  let signal: AbortSignal | undefined;
  try {
    if (!Array.isArray(fetches)) return fail("fetch group members must be an array");
    const count = fetches.length;
    if (!Number.isInteger(count) || count < (join ? 0 : 1) || count > BROWSER_FETCH_LIMITS.maxRequestsPerRuntime) {
      return fail(`fetch groups require ${join ? 0 : 1}..${BROWSER_FETCH_LIMITS.maxRequestsPerRuntime} members`);
    }
    const suppliedSignal = options.signal;
    if (suppliedSignal != null) {
      if (!SIGNAL || !ANY_SIGNAL || !ABORTED || !ADD_LISTENER || !REMOVE_LISTENER) {
        return fail("fetch group signals require native AbortSignal.any and EventTarget");
      }
      // Native any() may inspect public accessors. Reject customized signals
      // without invoking those accessors, then brand-check through the intrinsic.
      if (Object.getPrototypeOf(suppliedSignal) !== SIGNAL.prototype
          || Object.getOwnPropertyDescriptor(suppliedSignal, "aborted")
          || Object.getOwnPropertyDescriptor(suppliedSignal, "reason")) {
        return fail("fetch groups require an unmodified same-realm native signal");
      }
      Reflect.apply(ABORTED, suppliedSignal, []);
      signal = Reflect.apply(ANY_SIGNAL, SIGNAL, [[suppliedSignal]]) as AbortSignal;
      Reflect.apply(ABORTED, signal, []);
    }
    if (count && (!GET_READER || !LOCKED || !CANCEL || !RELEASE || !READER_CLOSED)) {
      return fail("fetch groups require native ReadableStream readers");
    }
    const inputs: { fetch: FetchStreamHandle; response: Member["response"]; closed: Member["closed"]; convert: FetchStreamHandle["toReadableStream"]; retire: FetchStreamHandle["retire"] }[] = [];
    const seen = new Set<FetchStreamHandle>();
    // Read all caller properties before taking a native reader lock.
    for (let index = 0; index < count; index += 1) {
      const fetch = fetches[index];
      if (!fetch || seen.has(fetch)) return fail("fetch group members must be distinct owned fetch handles");
      seen.add(fetch);
      const response = fetch.response, closed = fetch.closed, convert = fetch.toReadableStream, retire = fetch.retire;
      if (typeof response !== "function" || typeof convert !== "function" || !closed) return fail("invalid fetch group member");
      if (retire !== undefined && typeof retire !== "function") return fail("invalid fetch retirement method");
      inputs.push({ fetch, response, closed, convert, retire });
    }
    const bodies = new Set<ReadableStream<Uint8Array>>();
    for (const input of inputs) {
      const converted = Reflect.apply(input.convert, input.fetch, []);
      if (converted.outcome !== "ok") throw converted;
      const body = converted.value as ReadableStream<Uint8Array>;
      if (bodies.has(body) || Reflect.apply(LOCKED!, body, [])) throw new Error("body already owned");
      bodies.add(body);
      const reader = Reflect.apply(GET_READER!, body, []) as ReadableStreamDefaultReader<Uint8Array>;
      // Releasing an unfinished lock rejects this promise, including on rollback.
      void Promise.resolve(Reflect.apply(READER_CLOSED!, reader, [])).catch(() => {});
      members.push({ fetch: input.fetch, body, reader, response: () => Reflect.apply(input.response, input.fetch, []),
        closed: Promise.resolve(input.closed).then((value) => checked<void>(value), () => internal("fetch group member completion rejected")),
        retire: input.retire ? () => Reflect.apply(input.retire!, input.fetch, ["fetch group member retired"]) : undefined,
      });
    }
  } catch {
    for (const member of members) { try { Reflect.apply(RELEASE!, member.reader, []); } catch { /* Already released. */ } }
    return fail("fetch group setup refused: invalid, duplicate, or already consumed body");
  }

  if (!members.length) {
    const result = Promise.resolve(ok(Object.freeze([]) as readonly FetchResponseWinner[]));
    const settlement = Promise.resolve(ok(undefined));
    return ok(Object.freeze({ result, cancel(reason = "fetch join cancelled by caller") {
      return typeof reason === "string" ? settlement : Promise.resolve(fail("fetch group cancellation reason must be a string"));
    } }));
  }
  let resolveResult!: (outcome: Outcome<Selection>) => void;
  const result = new Promise<Outcome<Selection>>((resolve) => { resolveResult = resolve; });
  const settlement = result.then((outcome): Outcome<void> => outcome.outcome === "ok" ? ok(undefined) : outcome);
  let decide!: () => void;
  const decided = new Promise<void>((resolve) => { decide = resolve; });
  let selected: { index: number; outcome: Outcome<BrowserFetchResponse> } | undefined;
  let stopped: Failure | undefined;
  let finished = false;
  let readyCount = 0;
  const cleanupErrors = new Map<number, Failure>();
  let onAbort: (() => void) | undefined;

  function drain(index: number): Promise<Outcome<void>> {
    const member = members[index];
    if (member.draining) return member.draining;
    // Install before native cancellation calls arbitrary producer cleanup.
    let resolve!: (outcome: Outcome<void>) => void;
    member.draining = new Promise<Outcome<void>>((done) => { resolve = done; });
    void (async () => {
      // Reader cancellation can settle with the operation's original Outcome
      // even when its owner reports failed cleanup. Start both independent
      // barriers, and react to a retirement failure without waiting for other
      // members' host cleanup. The installed drain protects reentrant calls.
      const retirement = member.retire ? Promise.resolve().then(member.retire).then(value => {
        const receipt = checked<void>(value);
        return receipt.outcome === "ok" && receipt.value !== undefined
          ? internal("fetch retirement returned a non-void success") : receipt;
      }, () => internal("fetch retirement rejected")) : Promise.resolve(ok(undefined));
      const joinedRetirement = retirement.then(receipt => {
        if (receipt.outcome !== "ok") stop(receipt);
        return receipt;
      });
      let rejected = false;
      try { await Reflect.apply(CANCEL!, member.reader, ["fetch group member retired"]); }
      catch { rejected = true; }
      let terminal: Outcome<void>;
      try { terminal = await member.closed; }
      catch { terminal = internal("fetch group member cleanup rejected"); }
      member.terminal = terminal;
      const outcome = rejected
        ? terminal.outcome !== "ok" ? terminal : internal("fetch group cancellation or terminal publication refused")
        : terminal.outcome === "err" || terminal.outcome === "panicked" ? terminal : ok(undefined);
      if (outcome.outcome !== "ok") noteCleanup(index, outcome);
      // Recorded after the terminal: an equally severe operation failure keeps
      // its own, more specific cause.
      const retired = await joinedRetirement;
      if (retired.outcome !== "ok") noteCleanup(index, retired);
      resolve(cleanupErrors.get(index) ?? ok(undefined));
    })();
    return member.draining;
  }
  function noteCleanup(index: number, outcome: Failure): void {
    const previous = cleanupErrors.get(index);
    if (!previous || severity(outcome) > severity(previous)) cleanupErrors.set(index, outcome);
    // A later ordinary terminal error must not overwrite a retirement panic.
    // Do not keep the selected body alive behind another slow loser.
    stop(outcome);
  }
  function stop(outcome: Failure) {
    if (finished) return;
    if (stopped) {
      if (severity(outcome) > severity(stopped)) stopped = outcome;
      return;
    }
    stopped = outcome;
    decide();
    for (let index = 0; index < members.length; index += 1) void drain(index);
  }
  function observe(index: number, outcome: Outcome<BrowserFetchResponse>) {
    if (finished || stopped || (!join && selected)) return;
    if (outcome.outcome !== "ok") { stop(outcome); return; }
    if (join) {
      readyCount += 1;
      if (readyCount === members.length) decide();
    } else {
      selected = { index, outcome };
      decide();
    }
  }
  function release() {
    if (signal && onAbort) {
      Reflect.apply(REMOVE_LISTENER!, signal, ["abort", onAbort]);
      onAbort = undefined;
    }
    for (const member of members) { try { Reflect.apply(RELEASE!, member.reader, []); } catch { /* Already released. */ } }
  }
  if (signal) {
    onAbort = () => stop(cancellation("fetch group aborted by caller signal", join, true));
    try {
      Reflect.apply(ADD_LISTENER!, signal, ["abort", onAbort, { once: true }]);
      if (Reflect.apply(ABORTED!, signal, [])) onAbort();
    } catch { stop(internal("fetch group signal observer failed")); }
  }
  // Register every observer before calling any member's response method.
  for (let index = 0; index < members.length; index += 1) {
    const member = members[index];
    void member.closed.then((terminal) => {
      member.terminal = terminal;
      if (terminal.outcome !== "ok" && !member.draining && (join || !selected || selected.index === index)) stop(terminal);
    }, () => stop(internal("fetch group member completion rejected")));
  }
  for (let index = 0; index < members.length; index += 1) {
    if (stopped) break;
    const member = members[index];
    try {
      void Promise.resolve(member.response()).then((outcome) => {
        const head = checked<BrowserFetchResponse>(outcome);
        member.head = head;
        observe(index, head);
      }, () => observe(index, internal("fetch group response rejected")));
    } catch { observe(index, internal("fetch group response threw")); }
  }
  void (async () => {
    await decided;
    const candidate = selected;
    const selectedIndexes = join ? members.map((_, index) => index)
      : candidate?.outcome.outcome === "ok" ? [candidate.index] : [];
    const keep = new Set(selectedIndexes);
    await Promise.all(members.map((_, index) => !stopped && keep.has(index)
      ? Promise.resolve(ok(undefined)) : drain(index)));
    for (const index of selectedIndexes) {
      const terminal = members[index].terminal;
      // A join includes drained members too. Their expected cancellation is
      // cleanup, not a new owner failure; drain() already records refusals.
      if (!members[index].draining && terminal && terminal.outcome !== "ok") stop(terminal);
    }
    if (stopped || cleanupErrors.size || (!join && !selectedIndexes.length)) {
      await Promise.all(members.map((_, index) => drain(index)));
      // Compare cleanup with the initiating failure as well as other cleanup.
      // Keep input-order cleanup ties, but never downgrade the stopped outcome.
      const cleanupFailure = [...cleanupErrors].sort(([a, x], [b, y]) => severity(y) - severity(x) || a - b)[0]?.[1];
      const failure = cleanupFailure && (!stopped || severity(cleanupFailure) >= severity(stopped))
        ? cleanupFailure : stopped;
      finished = true;
      release();
      resolveResult(failure ?? internal("fetch group ended without a response"));
    } else {
      const winners = selectedIndexes.map((index): FetchResponseWinner => {
        const member = members[index];
        const head = member.head as Extract<Outcome<BrowserFetchResponse>, { outcome: "ok" }>;
        return Object.freeze({ index, response: head.value, fetch: member.fetch, body: member.body });
      });
      finished = true;
      release();
      resolveResult(ok(join ? Object.freeze(winners) : winners[0]));
    }
  })();
  return ok(Object.freeze({ result, cancel(reason = join ? "fetch join cancelled by caller" : "fetch race cancelled by caller") {
    if (typeof reason !== "string") return Promise.resolve(fail("fetch group cancellation reason must be a string"));
    stop(cancellation(reason, join));
    return settlement;
  } }));
}
