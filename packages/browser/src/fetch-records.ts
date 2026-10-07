/** Internal pull-driven record owner. No connection, task or timer is created. */
import type { Outcome } from "@asupersync/browser-core";
import { BROWSER_FETCH_LIMITS, type BrowserFetchResponse, type FetchStreamHandle } from "./fetch.js";

export interface FetchRecordStream<T> {
  readonly readable: ReadableStream<T>;
  /** Parsing completion AND owned fetch cleanup, not merely response headers. */
  readonly closed: Promise<Outcome<void>>;
  /** Also works while a consumer holds the readable's lock. Idempotent. */
  cancel(reason?: string): Promise<Outcome<void>>;
}

type Failure = Exclude<Outcome<never>, { outcome: "ok" }>;
const LOCAL_ERRORS = new WeakMap<object, Failure>();
const STREAM = typeof ReadableStream === "undefined" ? undefined : ReadableStream;
const GET_READER = STREAM?.prototype.getReader;
const READER = typeof ReadableStreamDefaultReader === "undefined" ? undefined : ReadableStreamDefaultReader;
const READ = READER?.prototype.read;
const CANCEL = READER?.prototype.cancel;
const RELEASE = READER?.prototype.releaseLock;
const READER_CLOSED = READER && Object.getOwnPropertyDescriptor(READER.prototype, "closed")?.get;
const DECODER = typeof TextDecoder === "undefined" ? undefined : TextDecoder;
const DECODE = DECODER?.prototype.decode;
const VIEW = Object.getPrototypeOf(Uint8Array.prototype) as object;
const TAG = Object.getOwnPropertyDescriptor(VIEW, Symbol.toStringTag)!.get!;
const BUFFER = Object.getOwnPropertyDescriptor(VIEW, "buffer")!.get!;
const OFFSET = Object.getOwnPropertyDescriptor(VIEW, "byteOffset")!.get!;
const LENGTH = Object.getOwnPropertyDescriptor(VIEW, "byteLength")!.get!;
const VALUES = (VIEW as { values: () => unknown }).values;

export function recordFailure(message: string, code: "decode_failure" | "compatibility_rejected" = "decode_failure"): Failure {
  return Object.freeze({ outcome: "err", failure: Object.freeze({ code, recoverability: "permanent", message }) });
}

export function recordError(outcome: Failure): Error {
  const text = outcome.outcome === "err" ? outcome.failure.message
    : outcome.outcome === "cancelled" ? outcome.cancellation.message ?? "fetch cancelled" : outcome.message;
  const error = Object.defineProperty(new Error(text), "cause", { value: outcome });
  LOCAL_ERRORS.set(error, outcome);
  return error;
}

function localOutcome(error: unknown): Failure | undefined {
  return error !== null && (typeof error === "object" || typeof error === "function")
    ? LOCAL_ERRORS.get(error) : undefined;
}

export function recordException(error: unknown, message: string): Failure {
  // Do not trust a thrown object's cause/outcome or invoke presentation hooks.
  return localOutcome(error) ?? recordFailure(message, "compatibility_rejected");
}

export function positiveLimit(value: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw recordError(recordFailure(`${name} must be an integer between 1 and ${maximum}`, "compatibility_rejected"));
  }
  return value;
}

export interface RecordParser<T> {
  line(text: string): T | null;
  end(tail: string | undefined): T | null;
  clear(): void;
}

export interface RecordConfig<T> {
  maxLineBytes: number;
  crLines: boolean;
  fatalUtf8: boolean;
  validate(response: BrowserFetchResponse): void;
  parser: RecordParser<T>;
}

/**
 * Takes exclusive ownership only after validation and native construction.
 * Bounds retained input by one fetch chunk plus maxLineBytes; never queues an
 * array of parsed records. Parser-specific state has its own advertised bound.
 */
export function createFetchRecordStream<T>(fetch: FetchStreamHandle, config: RecordConfig<T>): Outcome<FetchRecordStream<T>> {
  if (!STREAM || !GET_READER || !READ || !CANCEL || !RELEASE || !READER_CLOSED || !DECODER || !DECODE) {
    return recordFailure("fetch record streams require native ReadableStream readers and TextDecoder", "compatibility_rejected");
  }
  const getReader = GET_READER, read = READ, cancel = CANCEL, release = RELEASE, readerClosed = READER_CLOSED, decode = DECODE;
  let reader: ReadableStreamDefaultReader<Uint8Array>;
  let controller: ReadableStreamDefaultController<T>;
  let resolveClosed!: (outcome: Outcome<void>) => void;
  const closed = new Promise<Outcome<void>>((resolve) => { resolveClosed = resolve; });
  let ended = false;
  let stopping = false;
  let consumerCancelled = false;
  let readiness: Promise<void>;
  let pending: Uint8Array | null = null;
  let offset = 0;
  let skipLF = false;
  let firstLine = true;
  let lineBuffer = new Uint8Array(0);
  let lineLength = 0;
  let decoder: TextDecoder;

  function clear() {
    pending = null;
    lineBuffer = new Uint8Array(0);
    lineLength = 0;
    config.parser.clear();
  }
  function finish(outcome: Outcome<void>) {
    if (ended) return;
    ended = true;
    clear();
    // Releasing intentionally rejects reader.closed on an unfinished stream.
    // Publish ended first so that observer cannot start a second termination.
    try { Reflect.apply(release, reader, []); } catch { /* Already released. */ }
    if (!consumerCancelled) {
      if (outcome.outcome === "ok") controller.close();
      else controller.error(recordError(outcome));
    }
    resolveClosed(outcome);
  }
  function stop(failure: Failure | undefined, reason: unknown, unexpected = false): Promise<Outcome<void>> {
    if (ended || stopping) return closed;
    stopping = true;
    clear();
    void (async () => {
      let outcome = failure;
      let cleanupFailed = false;
      // Native reader cancellation reaches the fetch adapter's implicit
      // cancellation path, including fail-closed ABI refusal and slow cleanup.
      try { await Reflect.apply(cancel, reader, [reason]); }
      catch { cleanupFailed = true; }
      try {
        // The fetch's terminal receipt, not an arbitrary rejection's .cause,
        // is authoritative for source cancellation and publication failures.
        const terminal = await fetch.closed;
        if (terminal.outcome === "err" || terminal.outcome === "panicked"
            || (!outcome && terminal.outcome === "cancelled")) outcome = terminal;
        if (!outcome && (cleanupFailed || unexpected)) outcome = recordFailure("fetch record stream failed");
      } catch { outcome = recordFailure("fetch record cleanup failed"); }
      finish(outcome ?? Object.freeze({ outcome: "ok", value: undefined }));
    })();
    return closed;
  }
  function append(bytes: Uint8Array) {
    const required = lineLength + bytes.byteLength;
    if (required > config.maxLineBytes) throw recordError(recordFailure("fetch record line exceeds maxLineBytes"));
    if (required > lineBuffer.length) {
      const grown = new Uint8Array(Math.min(config.maxLineBytes, Math.max(required, 256, lineBuffer.length * 2)));
      grown.set(lineBuffer.subarray(0, lineLength));
      lineBuffer = grown;
    }
    lineBuffer.set(bytes, lineLength);
    lineLength = required;
  }
  function text(bytes: Uint8Array): string {
    let value: string;
    try { value = Reflect.apply(decode, decoder, [bytes]); }
    catch { throw recordError(recordFailure("fetch record stream contains invalid UTF-8")); }
    // Decode individual byte-delimited lines. Only the stream's first BOM is
    // ignored; a later BOM is ordinary data. Invalid SSE UTF-8 uses replacement.
    if (firstLine) {
      firstLine = false;
      if (value.charCodeAt(0) === 0xfeff) value = value.slice(1);
    }
    return value;
  }
  async function nextLine(): Promise<{ line: string } | { tail: string | undefined }> {
    for (;;) {
      if (stopping || ended) return { tail: undefined };
      if (pending && offset < pending.length) {
        if (skipLF) {
          skipLF = false;
          if (pending[offset] === 10) offset += 1;
        }
        const start = offset;
        while (offset < pending.length && pending[offset] !== 10 && !(config.crLines && pending[offset] === 13)) offset += 1;
        const end = offset;
        append(pending.subarray(start, end));
        if (offset < pending.length) {
          skipLF = config.crLines && pending[offset] === 13;
          offset += 1;
          // LF-only protocols allow CRLF but do not split on bare CR.
          const length = !config.crLines && lineLength && lineBuffer[lineLength - 1] === 13 ? lineLength - 1 : lineLength;
          const line = text(lineBuffer.subarray(0, length));
          lineLength = 0;
          return { line };
        }
      }
      pending = null;
      const result = await Reflect.apply(read, reader, []);
      if (stopping || ended) return { tail: undefined };
      if (result.done) {
        const tail = lineLength ? text(lineBuffer.subarray(0, lineLength)) : undefined;
        lineLength = 0;
        return { tail };
      }
      const value: unknown = result.value;
      if (Reflect.apply(TAG, value, []) !== "Uint8Array") throw recordError(recordFailure("fetch record stream requires byte chunks"));
      Reflect.apply(VALUES, value, []); // Reject detached/out-of-bounds views.
      const length = Reflect.apply(LENGTH, value, []) as number;
      if (length > BROWSER_FETCH_LIMITS.maxChunkBytes) throw recordError(recordFailure("fetch record chunk exceeds maxChunkBytes"));
      pending = new Uint8Array(Reflect.apply(BUFFER, value, []), Reflect.apply(OFFSET, value, []), length);
      offset = 0;
    }
  }

  try {
    decoder = new DECODER("utf-8", { fatal: config.fatalUtf8, ignoreBOM: true });
    // Construct before taking the byte reader. A refusal leaves the fetch body
    // unconsumed; the caller still owns and must drain that fetch.
    const readable = new STREAM<T>({
      start(value) { controller = value; },
      async pull() {
        await readiness;
        while (!stopping && !ended) {
          try {
            const next = await nextLine();
            if (stopping || ended) return;
            if ("tail" in next) {
              const final = config.parser.end(next.tail);
              const terminal = await fetch.closed;
              if (stopping || ended) return;
              if (terminal.outcome !== "ok") { await stop(terminal, "fetch terminated"); return; }
              if (final !== null) controller.enqueue(final);
              finish(terminal);
              return;
            }
            const record = config.parser.line(next.line);
            if (record !== null) { controller.enqueue(record); return; }
          } catch (error) { await stop(localOutcome(error), "fetch record decoding failed", true); }
        }
      },
      async cancel(reason) {
        consumerCancelled = true;
        const outcome = await stop(undefined, reason ?? "fetch record consumer cancelled");
        if (outcome.outcome !== "ok" && outcome.outcome !== "cancelled") throw recordError(outcome);
      },
    }, { highWaterMark: 0 });
    const body = fetch.toReadableStream();
    if (body.outcome !== "ok") return body;
    try { reader = Reflect.apply(getReader, body.value, []) as ReadableStreamDefaultReader<Uint8Array>; }
    catch { return recordFailure("fetch body is already locked or unavailable", "compatibility_rejected"); }

    readiness = Promise.resolve().then(async () => {
      try {
        const response = await fetch.response();
        if (stopping || ended) return;
        if (response.outcome !== "ok") { await stop(response, "fetch response failed"); return; }
        config.validate(response.value);
      } catch (error) { await stop(recordException(error, "fetch response rejected"), "fetch response rejected"); }
    });
    // Observe idle network errors and external cancellation; successful reader
    // closure is NOT parser EOF, since an unconsumed chunk can still be owned.
    void Promise.resolve(Reflect.apply(readerClosed, reader, [])).catch(() => {
      if (!ended && !stopping) void stop(undefined, "fetch terminated", true);
    });
    return { outcome: "ok", value: Object.freeze({ readable, closed,
      cancel(reason = "fetch record stream cancelled by caller") {
        if (typeof reason !== "string") return Promise.resolve(recordFailure("record cancellation reason must be a string", "compatibility_rejected"));
        return stop(undefined, reason);
      },
    }) };
  } catch (error) { return recordException(error, "fetch record stream setup failed"); }
}

export function requireMediaType(response: BrowserFetchResponse, accepted: readonly string[]): void {
  if (response.status !== 200) throw recordError(recordFailure("fetch record stream requires HTTP status 200"));
  const contentTypes = response.headers.filter(([name]) => name.toLowerCase() === "content-type");
  const mime = contentTypes.length === 1 ? contentTypes[0][1].split(";", 1)[0].trim().toLowerCase() : "";
  if (!accepted.includes(mime)) throw recordError(recordFailure(`fetch record stream requires Content-Type ${accepted.join(" or ")}`));
}
