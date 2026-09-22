import type {
  ErrorCode,
  Outcome,
  Recoverability,
  WebTransportByteStream,
  WebTransportReadableStream,
  WebTransportWritableStream,
} from "./index.js";

/** Adapter-owned admission/copy bounds; browser and network buffers are separate. */
export declare const WEBTRANSPORT_STREAM_LIMITS: Readonly<{
  maxStreamsPerSession: 64;
  maxWriteBytes: 1048576;
}>;

export type ReliableStreamDirection = "bidirectional" | "unidirectional";

/** Stable identity supplied by the facade that already owns session authority. */
export interface ReliableStreamSessionState {
  readonly transport: object;
  readonly sessionOrigin: string | null;
  readonly closed: boolean;
}

export interface ReliableStreamRequest<Session> {
  session: Session;
}

export interface ReliableStreamManagerOptions<
  Session,
  State extends ReliableStreamSessionState,
> {
  /** Resolve an existing authorized session; unknown handles may throw. */
  lookup(session: Session): State | null | undefined;
  ok<Value>(value: Value): Outcome<Value>;
  fail(code: ErrorCode, recoverability: Recoverability, message: string): Outcome<never>;
  cancelled(reason: string, origin: State["sessionOrigin"]): Outcome<never>;
}

/**
 * Reliable stream ownership for existing sessions, without creating tasks or
 * transport authority. Pending opens/accepts and live streams share 64 slots.
 * Each direction admits at most one pending accept and never prefetches streams.
 */
export interface ReliableStreamManager<
  Session,
  State extends ReliableStreamSessionState = ReliableStreamSessionState,
> {
  open(
    request: ReliableStreamRequest<Session>,
    direction?: "bidirectional",
  ): Promise<Outcome<WebTransportByteStream>>;
  open(
    request: ReliableStreamRequest<Session>,
    direction: "unidirectional",
  ): Promise<Outcome<WebTransportWritableStream>>;
  open(
    request: ReliableStreamRequest<Session>,
    direction?: ReliableStreamDirection,
  ): Promise<Outcome<WebTransportByteStream | WebTransportWritableStream>>;

  /** Collection EOF is successful null, including repeated accepts after EOF. */
  accept(
    request: ReliableStreamRequest<Session>,
    direction?: "bidirectional",
  ): Promise<Outcome<WebTransportByteStream | null>>;
  accept(
    request: ReliableStreamRequest<Session>,
    direction: "unidirectional",
  ): Promise<Outcome<WebTransportReadableStream | null>>;
  accept(
    request: ReliableStreamRequest<Session>,
    direction?: ReliableStreamDirection,
  ): Promise<Outcome<WebTransportByteStream | WebTransportReadableStream | null>>;

  /**
   * Latch owner termination and initiate all host cleanup. Await stream.closed
   * and pending open/accept receipts to observe their cleanup settlement. Host
   * promises that never settle cannot be converted into a deadline guarantee.
   */
  closeSession(state: State, outcome: Outcome<never>): void;

  /**
   * Observe the single reliable-stream drain promise. It stays pending until
   * closeSession is called, then waits for all active/admitting streams and
   * acquired incoming readers to settle cleanup and release locks. It preserves
   * the first owner outcome, not an aggregate of child failures. This excludes
   * datagrams, the transport connection, unaccepted browser-owned endpoints,
   * and arbitrary caller work, and cannot force host promises to settle.
   */
  whenClosed(state: State): Promise<Outcome<never>>;

  /** Latch closure and return the same barrier, without changing closeSession. */
  closeSessionAndDrain(state: State, outcome: Outcome<never>): Promise<Outcome<never>>;
}

/** Create a manager using only the provided session lookup and Outcome helpers. */
export declare function createReliableStreamManager<
  Session,
  State extends ReliableStreamSessionState,
>(options: ReliableStreamManagerOptions<Session, State>): ReliableStreamManager<Session, State>;
