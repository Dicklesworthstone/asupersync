/** Structured response decoding for an already-authorized, scope-owned fetch. */
import type { Outcome } from "@asupersync/browser-core";
import type { FetchStreamHandle } from "./fetch.js";
import { createFetchRecordStream, positiveLimit, recordError, recordException, recordFailure, requireMediaType,
  type FetchRecordStream } from "./fetch-records.js";
export type { FetchRecordStream } from "./fetch-records.js";

export const SERVER_SENT_EVENT_LIMITS = Object.freeze({
  maxLineBytes: 65_536,
  maxEventChars: 1_048_576,
  maxConfiguredLineBytes: 1_048_576,
  maxConfiguredEventChars: 16_777_216,
});

export interface ServerSentEvent {
  readonly type: string;
  readonly data: string;
  readonly lastEventId: string;
}

export interface ServerSentEventOptions {
  /** Raw UTF-8 bytes in a line, excluding its delimiter. */
  maxLineBytes?: number;
  /** Decoded UTF-16 code units in accumulated data, including appended LFs. */
  maxEventChars?: number;
}

export interface ServerSentEventStream extends FetchRecordStream<ServerSentEvent> {
  /** Last ID committed by a blank-line dispatch boundary, including ID-only blocks. */
  readonly lastEventId: string;
  /** Last valid retry field. Decimal text avoids truncating unbounded integers. */
  readonly retry: string | null;
}

/**
 * Transfer an owned fetch body into pull-driven Server-Sent Events.
 *
 * HTTP 200 and text/event-stream are required. Follows WHATWG SSE wire parsing:
 * UTF-8 replacement, one leading BOM, CR/LF/CRLF, data folding, default event
 * types, persistent/resettable IDs, ignored NUL IDs, and digit-only retry.
 * Incomplete events are discarded at EOF, never dispatched speculatively.
 * https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream
 *
 * This is NOT a browser EventSource: no ambient connection, automatic retry,
 * redirect, Last-Event-ID header, callback task or task-ABI owner is created.
 * GET/POST, credentials, request headers, deadlines, signals, total response
 * bytes and scope closure stay governed by the original fetch. A caller may
 * explicitly use lastEventId/retry for a separately authorized next request.
 *
 * At most one fetch chunk, one bounded line and one bounded event are retained.
 * There is no parsed-event backlog or read-ahead after producing one event.
 * Caller/downstream/tee buffers are outside that bound. Consumer cancellation
 * and parse/protocol errors await host cleanup; error.cause is the Outcome.
 * Await this handle's closed for parser completion, not just fetch.closed.
 * Native cancellation closes the consumer immediately; its initiating promise
 * and this handle's closed are the cleanup barriers. A nonsettling host cannot
 * be forcibly drained. Setup refusal leaves cleanup with the fetch's caller.
 */
export function serverSentEvents(fetch: FetchStreamHandle, options: ServerSentEventOptions = {}): Outcome<ServerSentEventStream> {
  try {
    const maxLineBytes = positiveLimit(options.maxLineBytes ?? SERVER_SENT_EVENT_LIMITS.maxLineBytes,
      SERVER_SENT_EVENT_LIMITS.maxConfiguredLineBytes, "maxLineBytes");
    const maxEventChars = positiveLimit(options.maxEventChars ?? SERVER_SENT_EVENT_LIMITS.maxEventChars,
      SERVER_SENT_EVENT_LIMITS.maxConfiguredEventChars, "maxEventChars");
    let data: string[] = [];
    let chars = 0;
    let type = "";
    let id = "";
    let lastEventId = "";
    let retry: string | null = null;
    const clearEvent = () => { data = []; chars = 0; type = ""; };
    const result = createFetchRecordStream<ServerSentEvent>(fetch, {
      maxLineBytes, crLines: true, fatalUtf8: false,
      validate: (head) => requireMediaType(head, ["text/event-stream"]),
      parser: {
        line(line) {
          if (!line) {
            lastEventId = id;
            const event = data.length ? Object.freeze({ type: type || "message", data: data.join("\n"), lastEventId }) : null;
            clearEvent();
            return event;
          }
          if (line[0] === ":") return null;
          const colon = line.indexOf(":");
          const field = colon === -1 ? line : line.slice(0, colon);
          let value = colon === -1 ? "" : line.slice(colon + 1);
          if (value[0] === " ") value = value.slice(1);
          if (field === "data") {
            if (value.length + 1 > maxEventChars - chars) throw recordError(recordFailure("server-sent event exceeds maxEventChars"));
            chars += value.length + 1;
            data.push(value);
          } else if (field === "event") type = value;
          else if (field === "id" && !value.includes("\0")) id = value;
          else if (field === "retry" && /^[0-9]+$/.test(value)) retry = value;
          return null;
        },
        end() { clearEvent(); return null; },
        clear() { clearEvent(); id = lastEventId; },
      },
    });
    if (result.outcome !== "ok") return result;
    return { outcome: "ok", value: Object.freeze({ ...result.value,
      get lastEventId() { return lastEventId; }, get retry() { return retry; },
    }) };
  } catch (error) {
    return recordException(error, "invalid server-sent event options");
  }
}
