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

type Selection = FetchResponseWinner | readonly FetchResponseWinner[];
interface ResponseGroup {
  readonly result: Promise<Outcome<Selection>>;
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
  return internal("invalid fetch group outcome");
}

function cancellation(reason: string, join: boolean): Failure {
  // A composite outcome, not a new task or a claim about a member's ABI receipt.
  return Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
    kind: join ? "fetch_join_cancel" : "fetch_race_cancel", phase: "completed",
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
  return responseGroup(fetches, false);
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
 * original scope authority and no-read-ahead bounds. Does not buffer responses,
 * start requests, or join body EOF: callers must consume/cancel every returned
 * body and await each original fetch.closed after successful transfer.
 */
export function joinFetchResponses(fetches: readonly FetchStreamHandle[]): Outcome<FetchResponseJoin> {
  return responseGroup(fetches, true);
}

function responseGroup(fetches: readonly FetchStreamHandle[], join: false): Outcome<FetchResponseRace>;
function responseGroup(fetches: readonly FetchStreamHandle[], join: true): Outcome<FetchResponseJoin>;
function responseGroup(fetches: readonly FetchStreamHandle[], join: boolean): Outcome<ResponseGroup> {
  const members: Member[] = [];
  try {
    if (!Array.isArray(fetches)) return fail("fetch group members must be an array");
    const count = fetches.length;
    if (!Number.isInteger(count) || count < (join ? 0 : 1) || count > BROWSER_FETCH_LIMITS.maxRequestsPerRuntime) {
      return fail(`fetch groups require ${join ? 0 : 1}..${BROWSER_FETCH_LIMITS.maxRequestsPerRuntime} members`);
    }
    if (count && (!GET_READER || !LOCKED || !CANCEL || !RELEASE || !READER_CLOSED)) {
      return fail("fetch groups require native ReadableStream readers");
    }
    const inputs: { fetch: FetchStreamHandle; response: Member["response"]; closed: Member["closed"]; convert: FetchStreamHandle["toReadableStream"] }[] = [];
    const seen = new Set<FetchStreamHandle>();
    // Read all caller properties before taking a native reader lock.
    for (let index = 0; index < count; index += 1) {
      const fetch = fetches[index];
      if (!fetch || seen.has(fetch)) return fail("fetch group members must be distinct owned fetch handles");
      seen.add(fetch);
      const response = fetch.response, closed = fetch.closed, convert = fetch.toReadableStream;
      if (typeof response !== "function" || typeof convert !== "function" || !closed) return fail("invalid fetch group member");
      inputs.push({ fetch, response, closed, convert });
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
        closed: Promise.resolve(input.closed).then((value) => checked<void>(value), () => internal("fetch group member completion rejected")) });
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

  function drain(index: number): Promise<Outcome<void>> {
    const member = members[index];
    if (member.draining) return member.draining;
    // Install before native cancellation calls arbitrary producer cleanup.
    let resolve!: (outcome: Outcome<void>) => void;
    member.draining = new Promise<Outcome<void>>((done) => { resolve = done; });
    void (async () => {
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
    for (const member of members) { try { Reflect.apply(RELEASE!, member.reader, []); } catch { /* Already released. */ } }
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
      if (terminal && terminal.outcome !== "ok") stopped ??= terminal;
    }
    if (stopped || cleanupErrors.size || (!join && !selectedIndexes.length)) {
      await Promise.all(members.map((_, index) => drain(index)));
      // Never hide a cleanup panic behind an ordinary error or cancellation.
      // Input order breaks same-severity ties, not completion timing.
      const severity = (outcome: Failure) => outcome.outcome === "panicked" ? 3 : outcome.outcome === "err" ? 2 : 1;
      const cleanupFailure = [...cleanupErrors].sort(([a, x], [b, y]) => severity(y) - severity(x) || a - b)[0]?.[1];
      finished = true;
      release();
      resolveResult(cleanupFailure ?? stopped ?? internal("fetch group ended without a response"));
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
