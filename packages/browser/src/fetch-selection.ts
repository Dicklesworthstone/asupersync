/** Predicate-based, drain-correct selection of existing scope-owned fetches. */
import type { Outcome } from "@asupersync/browser-core";
import type { BrowserFetchResponse, FetchStreamHandle } from "./fetch.js";

export interface SelectedFetchResponse {
  readonly index: number;
  readonly response: BrowserFetchResponse;
  readonly fetch: FetchStreamHandle;
  /** Remaining body. No body bytes are read by selection. */
  readonly body: ReadableStream<Uint8Array>;
}

export interface FetchSelection<T> {
  /** Success transfers ownership only after every non-selected fetch drains. */
  readonly result: Promise<Outcome<T>>;
  /** Idempotent cleanup barrier; inert after successful ownership transfer. */
  cancel(reason?: string): Promise<Outcome<void>>;
}

export interface FetchSelectionOptions {
  /** Synchronous header predicate; defaults to HTTP 200..299. Must return a boolean. */
  accept?: (response: BrowserFetchResponse, index: number) => boolean;
}

/** Independent selection bounds; selection never admits additional requests. */
export const FETCH_SELECTION_LIMITS = Object.freeze({ maxMembers: 64, maxHeaders: 128, maxHeaderChars: 65_536 });
type Failure = Exclude<Outcome<never>, { outcome: "ok" }>;
const ok = <T>(value: T): Outcome<T> => Object.freeze({ outcome: "ok", value });
const fail = (message: string): Failure => Object.freeze({ outcome: "err", failure: Object.freeze({
  code: "compatibility_rejected", recoverability: "permanent", message,
}) });
const internal = (message: string): Failure => Object.freeze({ outcome: "err", failure: Object.freeze({
  code: "internal_failure", recoverability: "unknown", message,
}) });
const STREAM = typeof ReadableStream === "undefined" ? undefined : ReadableStream;
const LOCKED = STREAM && Object.getOwnPropertyDescriptor(STREAM.prototype, "locked")?.get;
const GET_READER = STREAM?.prototype.getReader;
const READER = typeof ReadableStreamDefaultReader === "undefined" ? undefined : ReadableStreamDefaultReader;
const CANCEL = READER?.prototype.cancel;
const RELEASE = READER?.prototype.releaseLock;
const CLOSED = READER && Object.getOwnPropertyDescriptor(READER.prototype, "closed")?.get;

// Copy envelopes before retaining them. Never trust an exception's .cause or
// stringify caller-controlled exceptions, headers, or response bodies.
function checked<T>(value: unknown): Outcome<T> {
  try {
    if (!value || typeof value !== "object") return internal("invalid fetch selection outcome");
    const outcome = value as Outcome<T>;
    switch (outcome.outcome) {
      case "ok": return ok(outcome.value);
      case "err": {
        const { code, recoverability, message } = outcome.failure;
        if (["capability_denied", "invalid_handle", "decode_failure", "compatibility_rejected", "internal_failure"].includes(code)
            && ["transient", "permanent", "unknown"].includes(recoverability) && typeof message === "string") {
          return Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability, message }) });
        }
        break;
      }
      case "panicked":
        if (typeof outcome.message === "string") return Object.freeze({ outcome: "panicked", message: outcome.message });
        break;
      case "cancelled": {
        const { kind, phase, origin_region, origin_task, timestamp_nanos, message, truncated } = outcome.cancellation;
        if (typeof kind === "string" && ["requested", "cancelling", "finalizing", "completed"].includes(phase)
            && typeof origin_region === "string" && (origin_task === null || typeof origin_task === "string")
            && (typeof timestamp_nanos === "bigint" || typeof timestamp_nanos === "number" && Number.isFinite(timestamp_nanos))
            && (message === null || typeof message === "string") && typeof truncated === "boolean") {
          return Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
            kind, phase, origin_region, origin_task, timestamp_nanos, message, truncated,
          }) });
        }
        break;
      }
    }
  } catch { /* Malformed envelopes fail closed. */ }
  return internal("invalid fetch selection outcome");
}

function responseSnapshot(value: BrowserFetchResponse): BrowserFetchResponse {
  const { status, statusText, url, headers } = value;
  const count = Array.isArray(headers) ? headers.length : -1;
  if (!Number.isInteger(status) || status < 0 || status > 599 || typeof statusText !== "string"
      || typeof url !== "string" || !Number.isSafeInteger(count) || count < 0 || count > FETCH_SELECTION_LIMITS.maxHeaders) {
    throw new Error("invalid response metadata");
  }
  let chars = statusText.length + url.length;
  const copied: (readonly [string, string])[] = [];
  // Indexed iteration avoids an unbounded or overridden caller iterator.
  for (let index = 0; index < count; index += 1) {
    const pair = headers[index];
    if (!Array.isArray(pair) || pair.length !== 2) throw new Error("invalid response header");
    const name = pair[0], text = pair[1];
    if (typeof name !== "string" || typeof text !== "string") throw new Error("invalid response header");
    chars += name.length + text.length;
    if (chars > FETCH_SELECTION_LIMITS.maxHeaderChars) throw new Error("response metadata too large");
    copied.push(Object.freeze([name, text] as const));
  }
  if (chars > FETCH_SELECTION_LIMITS.maxHeaderChars) throw new Error("response metadata too large");
  return Object.freeze({ status, statusText, url, headers: Object.freeze(copied) });
}

interface Member {
  fetch: FetchStreamHandle;
  body: ReadableStream<Uint8Array>;
  reader: ReadableStreamDefaultReader<Uint8Array>;
  response: () => Promise<Outcome<BrowserFetchResponse>>;
  closed: Promise<Outcome<void>>;
  head?: BrowserFetchResponse;
  terminal?: Outcome<void>;
  draining?: Promise<void>;
}

/**
 * Select the first `required` acceptable headers from 1..64 existing fetches.
 * Return selected bodies in INPUT order (selection itself uses observation order).
 * The default predicate accepts HTTP 2xx. Rejected HTTP responses are cancelled
 * promptly; failure becomes decisive as soon as quorum is mathematically impossible.
 * Every non-selected member must settle cleanup before success can transfer bodies.
 *
 * This is a header quorum, NOT body validation, replica agreement, retry, or a
 * network-error-tolerant Promise.any. Transport failures, cancelled members,
 * malformed outcomes, predicate exceptions, and cleanup/publication refusals
 * fail the WHOLE group and drain it. The public fetch receipt does not separate
 * transport errors from cleanup failures, so suppressing them would be unsound.
 * Scope cancellation therefore cannot be mistaken for a rejected HTTP status.
 * A selected member failing during drain also fails the group; no replacement
 * requests are started. Cleanup panics outrank errors and cancellation.
 *
 * Input handles must be distinct, exclusively owned and unlocked. Refused setup
 * releases acquired locks without cancelling caller work. A conversion already
 * made by toReadableStream() cannot be undone: resume using the native stream.
 * Predicates receive a bounded frozen metadata snapshot and must return a boolean;
 * asynchronous predicates are refused. Do not use the original handles while
 * selection owns them. Earlier manual reads are not undone.
 *
 * No request, task, timer, or authority is created; original scopes still own
 * every fetch. No body is prefetched or buffered. Cancelling cannot undo remote
 * effects already transmitted. A nonsettling host keeps result/cancel pending.
 * After success the caller must consume/cancel every selected body and await its
 * original fetch.closed; later group cancellation does not reclaim transferred work.
 */
export function quorumFetchResponses(
  fetches: readonly FetchStreamHandle[], required: number, options: FetchSelectionOptions = {},
): Outcome<FetchSelection<readonly SelectedFetchResponse[]>> {
  const members: Member[] = [];
  let accept: NonNullable<FetchSelectionOptions["accept"]>;
  try {
    const count = Array.isArray(fetches) ? fetches.length : -1;
    if (!Number.isSafeInteger(count) || !Number.isSafeInteger(required) || required < 1
        || count < required || count > FETCH_SELECTION_LIMITS.maxMembers) {
      return fail("fetch selection requires 1 <= required <= member count <= 64");
    }
    accept = options.accept ?? ((head) => head.status >= 200 && head.status < 300);
    if (typeof accept !== "function") return fail("fetch selection accept must be a function");
    if (!GET_READER || !LOCKED || !CANCEL || !RELEASE || !CLOSED) return fail("fetch selection requires native stream readers");
    const inputs: { fetch: FetchStreamHandle; response: Member["response"]; closed: Member["closed"]; convert: FetchStreamHandle["toReadableStream"] }[] = [];
    const seen = new Set<FetchStreamHandle>();
    for (let index = 0; index < count; index += 1) {
      const fetch = fetches[index];
      if (!fetch || seen.has(fetch)) return fail("fetch selection requires distinct owned handles");
      seen.add(fetch);
      const response = fetch.response, closed = fetch.closed, convert = fetch.toReadableStream;
      if (typeof response !== "function" || typeof convert !== "function" || !closed) return fail("invalid fetch selection member");
      inputs.push({ fetch, response, closed, convert });
    }
    const bodies = new Set<ReadableStream<Uint8Array>>();
    for (const input of inputs) {
      const converted = Reflect.apply(input.convert, input.fetch, []);
      if (converted.outcome !== "ok") throw new Error("conversion refused");
      const body = converted.value as ReadableStream<Uint8Array>;
      if (bodies.has(body) || Reflect.apply(LOCKED, body, [])) throw new Error("body already owned");
      bodies.add(body);
      const reader = Reflect.apply(GET_READER, body, []) as ReadableStreamDefaultReader<Uint8Array>;
      void Promise.resolve(Reflect.apply(CLOSED, reader, [])).catch(() => {});
      members.push({ fetch: input.fetch, body, reader,
        response: () => Reflect.apply(input.response, input.fetch, []),
        closed: Promise.resolve(input.closed).then((value) => checked<void>(value), () => internal("fetch completion rejected")),
      });
    }
  } catch {
    for (const member of members) { try { Reflect.apply(RELEASE!, member.reader, []); } catch { /* Already released. */ } }
    return fail("fetch selection setup refused");
  }

  let resolveResult!: (outcome: Outcome<readonly SelectedFetchResponse[]>) => void;
  const result = new Promise<Outcome<readonly SelectedFetchResponse[]>>((resolve) => { resolveResult = resolve; });
  const settlement = result.then((outcome): Outcome<void> => outcome.outcome === "ok" ? ok(undefined) : outcome);
  let decide!: () => void;
  const decided = new Promise<void>((resolve) => { decide = resolve; });
  let finished = false;
  let stopped: Failure | undefined;
  let chosen: number[] | undefined;
  let waiting = members.length;
  const accepted: number[] = [];
  const cleanupErrors = new Map<number, Failure>();

  function stop(outcome: Failure): void {
    if (finished) return;
    // A later panic must not be hidden behind an earlier ordinary failure.
    if (!stopped || outcome.outcome === "panicked") stopped = outcome;
    decide();
    for (let index = 0; index < members.length; index += 1) void drain(index);
  }
  function drain(index: number): Promise<void> {
    const member = members[index];
    if (member.draining) return member.draining;
    let resolve!: () => void;
    member.draining = new Promise<void>((done) => { resolve = done; });
    void (async () => {
      let refused = false;
      try { await Reflect.apply(CANCEL!, member.reader, ["fetch selection member retired"]); }
      catch { refused = true; }
      const terminal = await member.closed;
      member.terminal = terminal;
      const failure = terminal.outcome === "err" || terminal.outcome === "panicked" ? terminal
        : refused ? terminal.outcome === "cancelled" ? terminal
          : internal("fetch cancellation or terminal publication refused") : undefined;
      if (failure) { cleanupErrors.set(index, failure); stop(failure); }
      resolve();
    })();
    return member.draining;
  }
  // Register completion observers before invoking caller methods.
  for (const member of members) {
    void member.closed.then((terminal) => {
      member.terminal = terminal;
      if (!member.draining && terminal.outcome !== "ok") stop(terminal);
    });
  }
  for (let index = 0; index < members.length; index += 1) {
    const member = members[index];
    const observe = (value: unknown) => {
      if (finished || stopped || chosen) return;
      const outcome = checked<BrowserFetchResponse>(value);
      if (outcome.outcome !== "ok") { stop(outcome); return; }
      let matches: boolean;
      try {
        member.head = responseSnapshot(outcome.value);
        matches = accept(member.head, index);
        if (typeof matches !== "boolean") {
          // Observe a rejected async predicate without accepting its result.
          if (matches && typeof (matches as unknown as { then?: unknown }).then === "function") {
            void Promise.resolve(matches).catch(() => {});
          }
          throw new Error("predicate must be synchronous");
        }
      } catch { stop(fail("fetch selection requires valid metadata and a synchronous boolean predicate")); return; }
      // A predicate may re-enter cancellation through caller-owned handles.
      if (finished || stopped || chosen) return;
      waiting -= 1;
      if (matches) accepted.push(index); else void drain(index);
      if (accepted.length === required) {
        chosen = [...accepted].sort((a, b) => a - b);
        decide();
        for (let other = 0; other < members.length; other += 1) if (!chosen.includes(other)) void drain(other);
      } else if (accepted.length + waiting < required) {
        stop(fail("not enough acceptable fetch responses to reach quorum"));
      }
    };
    try { void Promise.resolve(member.response()).then(observe, () => stop(internal("fetch response rejected"))); }
    catch { stop(internal("fetch response threw")); }
  }
  void (async () => {
    await decided;
    await Promise.all(members.map((_, index) => !stopped && chosen?.includes(index) ? undefined : drain(index)));
    if (chosen) for (const index of chosen) {
      const terminal = members[index].terminal;
      if (terminal && terminal.outcome !== "ok") stop(terminal);
    }
    if (stopped || !chosen) {
      await Promise.all(members.map((_, index) => drain(index)));
    }
    const severity = (outcome: Failure) => outcome.outcome === "panicked" ? 3 : outcome.outcome === "err" ? 2 : 1;
    const cleanupFailure = [...cleanupErrors].sort(([a, x], [b, y]) => severity(y) - severity(x) || a - b)[0]?.[1];
    const failure = stopped?.outcome === "panicked" && cleanupFailure?.outcome !== "panicked" ? stopped
      : cleanupFailure ?? stopped;
    finished = true;
    for (const member of members) { try { Reflect.apply(RELEASE!, member.reader, []); } catch { /* Already released. */ } }
    if (failure) resolveResult(failure);
    else if (!chosen) resolveResult(internal("fetch selection ended without quorum"));
    else resolveResult(ok(Object.freeze(chosen.map((index) => {
      const member = members[index];
      return Object.freeze({ index, response: member.head!, fetch: member.fetch, body: member.body });
    }))));
  })();
  return ok(Object.freeze({ result, cancel(reason = "fetch selection cancelled by caller") {
    if (typeof reason !== "string") return Promise.resolve(fail("fetch selection cancellation reason must be a string"));
    if (!finished && !stopped) stop(Object.freeze({ outcome: "cancelled", cancellation: Object.freeze({
      kind: "fetch_selection_cancel", phase: "completed", origin_region: "browser-fetch-selection",
      origin_task: null, timestamp_nanos: 0, message: reason, truncated: false,
    }) }));
    return settlement;
  } }));
}

/** First acceptable HTTP response, sharing quorumFetchResponses' fail-closed boundaries. */
export function firstAcceptableFetchResponse(
  fetches: readonly FetchStreamHandle[], options: FetchSelectionOptions = {},
): Outcome<FetchSelection<SelectedFetchResponse>> {
  const group = quorumFetchResponses(fetches, 1, options);
  if (group.outcome !== "ok") return group;
  return ok(Object.freeze({ result: group.value.result.then((outcome) => outcome.outcome === "ok" ? ok(outcome.value[0]) : outcome),
    cancel: group.value.cancel,
  }));
}
