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

type Failure = Exclude<Outcome<never>, { outcome: "ok" }>;
const STREAM = typeof ReadableStream === "undefined" ? undefined : ReadableStream;
const LOCKED = STREAM && Object.getOwnPropertyDescriptor(STREAM.prototype, "locked")?.get;
const GET_READER = STREAM?.prototype.getReader;
const READER = typeof ReadableStreamDefaultReader === "undefined" ? undefined : ReadableStreamDefaultReader;
const CANCEL = READER?.prototype.cancel;
const RELEASE = READER?.prototype.releaseLock;
const READER_CLOSED = READER && Object.getOwnPropertyDescriptor(READER.prototype, "closed")?.get;
const ok = <T>(value: T): Outcome<T> => Object.freeze({ outcome: "ok", value });
const fail = (message: string): Failure => Object.freeze({ outcome: "err", failure: Object.freeze({
  code: "compatibility_rejected", recoverability: "permanent", message,
}) });
const internal = (message: string): Failure => Object.freeze({ outcome: "err", failure: Object.freeze({
  code: "internal_failure", recoverability: "unknown", message,
}) });

function checked<T>(value: unknown): Outcome<T> {
  try {
    if (!value || typeof value !== "object") return internal("invalid fetch race outcome");
    const outcome = value as Outcome<T>;
    switch (outcome.outcome) {
      case "ok": return ok(outcome.value);
      case "err": {
        const { code, recoverability, message } = outcome.failure;
        if (!["capability_denied", "invalid_handle", "decode_failure", "compatibility_rejected", "internal_failure"].includes(code)
            || !["transient", "permanent", "unknown"].includes(recoverability) || typeof message !== "string") break;
        return Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability, message }) });
      }
      case "panicked":
        if (typeof outcome.message === "string") return Object.freeze({ outcome: "panicked", message: outcome.message });
        break;
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
  return internal("invalid fetch race outcome");
}

function cancellation(reason: string): Failure {
  // A composite outcome, not a new task or a claim about a member's ABI receipt.
  return Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
    kind: "fetch_race_cancel", phase: "completed", origin_region: "browser-fetch-race",
    origin_task: null, timestamp_nanos: 0, message: reason, truncated: false,
  }) });
}

interface Member {
  fetch: FetchStreamHandle;
  body: ReadableStream<Uint8Array>;
  reader: ReadableStreamDefaultReader<Uint8Array>;
  response: () => Promise<Outcome<BrowserFetchResponse>>;
  closed: Promise<Outcome<void>>;
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
export function raceFetchResponses(fetches: readonly FetchStreamHandle[]): Outcome<FetchResponseRace> {
  if (!GET_READER || !LOCKED || !CANCEL || !RELEASE || !READER_CLOSED) {
    return fail("fetch races require native ReadableStream readers");
  }
  const members: Member[] = [];
  try {
    if (!Array.isArray(fetches)) return fail("fetch race members must be an array");
    const count = fetches.length;
    if (!Number.isInteger(count) || count < 1 || count > BROWSER_FETCH_LIMITS.maxRequestsPerRuntime) {
      return fail(`fetch races require 1..${BROWSER_FETCH_LIMITS.maxRequestsPerRuntime} members`);
    }
    const inputs: { fetch: FetchStreamHandle; response: Member["response"]; closed: Member["closed"]; convert: FetchStreamHandle["toReadableStream"] }[] = [];
    const seen = new Set<FetchStreamHandle>();
    // Read all caller properties before taking a native reader lock.
    for (let index = 0; index < count; index += 1) {
      const fetch = fetches[index];
      if (!fetch || seen.has(fetch)) return fail("fetch race members must be distinct owned fetch handles");
      seen.add(fetch);
      const response = fetch.response, closed = fetch.closed, convert = fetch.toReadableStream;
      if (typeof response !== "function" || typeof convert !== "function" || !closed) return fail("invalid fetch race member");
      inputs.push({ fetch, response, closed, convert });
    }
    const bodies = new Set<ReadableStream<Uint8Array>>();
    for (const input of inputs) {
      const converted = Reflect.apply(input.convert, input.fetch, []);
      if (converted.outcome !== "ok") throw converted;
      const body = converted.value as ReadableStream<Uint8Array>;
      if (bodies.has(body) || Reflect.apply(LOCKED, body, [])) throw new Error("body already owned");
      bodies.add(body);
      const reader = Reflect.apply(GET_READER, body, []) as ReadableStreamDefaultReader<Uint8Array>;
      // Releasing an unfinished lock rejects this promise, including on rollback.
      void Promise.resolve(Reflect.apply(READER_CLOSED, reader, [])).catch(() => {});
      members.push({ fetch: input.fetch, body, reader, response: () => Reflect.apply(input.response, input.fetch, []),
        closed: Promise.resolve(input.closed).then((value) => checked<void>(value), () => internal("fetch race member completion rejected")) });
    }
  } catch {
    for (const member of members) { try { Reflect.apply(RELEASE, member.reader, []); } catch { /* Already released. */ } }
    return fail("fetch race setup refused: invalid, duplicate, or already consumed body");
  }

  let resolveResult!: (outcome: Outcome<FetchResponseWinner>) => void;
  const result = new Promise<Outcome<FetchResponseWinner>>((resolve) => { resolveResult = resolve; });
  const settlement = result.then((outcome): Outcome<void> => outcome.outcome === "ok" ? ok(undefined) : outcome);
  let decide!: () => void;
  const decided = new Promise<void>((resolve) => { decide = resolve; });
  let selected: { index: number; outcome: Outcome<BrowserFetchResponse> } | undefined;
  let stopped: Failure | undefined;
  let finished = false;
  const cleanupErrors = new Map<number, Failure>();

  function drain(index: number): Promise<Outcome<void>> {
    const member = members[index];
    if (member.draining) return member.draining;
    // Install before native cancellation calls arbitrary producer cleanup.
    let resolve!: (outcome: Outcome<void>) => void;
    member.draining = new Promise<Outcome<void>>((done) => { resolve = done; });
    void (async () => {
      let rejected = false;
      try { await Reflect.apply(CANCEL!, member.reader, ["fetch race member retired"]); }
      catch { rejected = true; }
      let terminal: Outcome<void>;
      try { terminal = await member.closed; }
      catch { terminal = internal("fetch race member cleanup rejected"); }
      member.terminal = terminal;
      const outcome = rejected
        ? terminal.outcome !== "ok" ? terminal : internal("fetch race cancellation or terminal publication refused")
        : terminal.outcome === "err" || terminal.outcome === "panicked" ? terminal : ok(undefined);
      if (outcome.outcome !== "ok") {
        cleanupErrors.set(index, outcome);
        // Do not keep the selected body alive behind another slow loser.
        for (let other = 0; other < members.length; other += 1) if (other !== index) void drain(other);
      }
      resolve(outcome);
    })();
    return member.draining;
  }
  function stop(outcome: Failure) {
    if (finished || stopped) return;
    stopped = outcome;
    decide();
    for (let index = 0; index < members.length; index += 1) void drain(index);
  }
  function observe(index: number, outcome: Outcome<BrowserFetchResponse>) {
    if (finished || stopped || selected) return;
    selected = { index, outcome };
    decide();
    if (outcome.outcome !== "ok") stop(outcome);
  }
  function release() {
    for (const member of members) { try { Reflect.apply(RELEASE!, member.reader, []); } catch { /* Already released. */ } }
  }
  // Register every observer before calling any member's response method.
  for (let index = 0; index < members.length; index += 1) {
    const member = members[index];
    void member.closed.then((terminal) => {
      member.terminal = terminal;
      if (terminal.outcome !== "ok" && !member.draining && (!selected || selected.index === index)) stop(terminal);
    }, () => stop(internal("fetch race member completion rejected")));
  }
  for (let index = 0; index < members.length; index += 1) {
    const member = members[index];
    try {
      void Promise.resolve(member.response()).then((outcome) => {
        const head = checked<BrowserFetchResponse>(outcome);
        member.head = head;
        observe(index, head);
      }, () => observe(index, internal("fetch race response rejected")));
    } catch { observe(index, internal("fetch race response threw")); }
  }
  void (async () => {
    await decided;
    const candidate = selected;
    await Promise.all(members.map((_, index) => !stopped && candidate?.outcome.outcome === "ok" && index === candidate.index
      ? Promise.resolve(ok(undefined)) : drain(index)));
    const selectedFailure = candidate && members[candidate.index].terminal;
    if (selectedFailure && selectedFailure.outcome !== "ok") stopped ??= selectedFailure;
    if (stopped || cleanupErrors.size || !candidate || candidate.outcome.outcome !== "ok") {
      await Promise.all(members.map((_, index) => drain(index)));
      // Input-order precedence for multiple cleanup failures, never resolution order.
      const cleanupFailure = [...cleanupErrors].sort(([a], [b]) => a - b)[0]?.[1];
      finished = true;
      release();
      resolveResult(cleanupFailure ?? stopped ?? internal("fetch race ended without a response"));
    } else {
      const winner = members[candidate.index];
      finished = true;
      release();
      resolveResult(ok(Object.freeze({ index: candidate.index, response: candidate.outcome.value, fetch: winner.fetch, body: winner.body })));
    }
  })();
  return ok(Object.freeze({ result, cancel(reason = "fetch race cancelled by caller") {
    if (typeof reason !== "string") return Promise.resolve(fail("fetch race cancellation reason must be a string"));
    stop(cancellation(reason));
    return settlement;
  } }));
}
