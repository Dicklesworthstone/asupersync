/**
 * @asupersync/react — React adapter layer for Browser Edition.
 *
 * Re-exports the SDK surface from @asupersync/browser and adds
 * StrictMode-safe provider/hook utilities for React applications.
 */

import {
  type AbiFailure,
  type AbiVersion,
  BROWSER_UNSUPPORTED_RUNTIME_CODE,
  type BrowserRuntime,
  type BrowserRuntimeOptions,
  type BrowserRuntimeSupportDiagnostics,
  createBrowserRuntime,
  detectBrowserRuntimeSupport,
  formatOutcomeFailure,
  type Outcome,
  Outcome as OutcomeFactory,
  type RegionHandle,
} from "@asupersync/browser";
import {
  createContext,
  createElement,
  type ReactElement,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

export * from "@asupersync/browser";

export interface ReactRuntimeSupportDiagnostics
  extends Omit<BrowserRuntimeSupportDiagnostics, "packageName"> {
  packageName: "@asupersync/react";
}

export type ReactRuntimeStatus = "idle" | "initializing" | "ready" | "failed";

export interface ReactRuntimeContextValue {
  status: ReactRuntimeStatus;
  diagnostics: ReactRuntimeSupportDiagnostics;
  runtime: BrowserRuntime | null;
  error: Error | null;
  reload(): void;
}

type BrowserOutcome<T> = Outcome<T, AbiFailure>;

/** The actual close result. A refusal retains its exact owners for retry. */
export interface ReactCleanupReport {
  readonly outcome: BrowserOutcome<void>;
  readonly retainedOwners: number;
  /** Retry only this cleanup snapshot, never a newer runtime or scope. */
  retry(): Promise<ReactCleanupReport>;
}

export type ReactCleanupObserver = (report: ReactCleanupReport) => void;

export interface ReactRuntimeLifecycleContextValue extends ReactRuntimeContextValue {
  /** Stop this provider's current generation and await its owned fetch cleanup. */
  closeAsync(): Promise<ReactCleanupReport>;
}

export interface ReactRuntimeProviderProps {
  children: ReactNode;
  runtimeOptions?: BrowserRuntimeOptions;
  /** Receives automatic teardown results, including after unmount. */
  onCleanup?: ReactCleanupObserver;
}

export interface ReactScopeOptions {
  label?: string;
  consumerVersion?: AbiVersion | null;
  /** Receives automatic teardown results, including after unmount. */
  onCleanup?: ReactCleanupObserver;
}

export interface ReactScopeState {
  status: "idle" | "opening" | "ready" | "failed";
  scope: RegionHandle | null;
  error: Error | null;
  close(): void;
}

export interface ReactScopeLifecycleState extends ReactScopeState {
  /** Detach the scope immediately and await the real SDK close result. */
  closeAsync(): Promise<ReactCleanupReport>;
}

export const REACT_UNSUPPORTED_RUNTIME_CODE = "ASUPERSYNC_REACT_UNSUPPORTED_RUNTIME";

export function detectReactRuntimeSupport(
  globalObject: Record<string, unknown> | undefined = undefined,
): ReactRuntimeSupportDiagnostics {
  const browserDiagnostics = detectBrowserRuntimeSupport(globalObject);
  return {
    ...browserDiagnostics,
    packageName: "@asupersync/react",
    guidance: browserDiagnostics.supported
      ? []
      : [
          "Use @asupersync/react from client-rendered React trees only.",
          ...browserDiagnostics.guidance,
        ],
  };
}

export function createReactUnsupportedRuntimeError(
  diagnostics: ReactRuntimeSupportDiagnostics = detectReactRuntimeSupport(),
): Error & {
  code: typeof REACT_UNSUPPORTED_RUNTIME_CODE;
  diagnostics: ReactRuntimeSupportDiagnostics;
} {
  const error = new Error(
    `${diagnostics.packageName}: ${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  ) as Error & {
    code: typeof REACT_UNSUPPORTED_RUNTIME_CODE;
    diagnostics: ReactRuntimeSupportDiagnostics;
  };
  error.code = REACT_UNSUPPORTED_RUNTIME_CODE;
  error.diagnostics = diagnostics;
  return error;
}

export function assertReactRuntimeSupport(
  diagnostics: ReactRuntimeSupportDiagnostics = detectReactRuntimeSupport(),
): ReactRuntimeSupportDiagnostics {
  if (!diagnostics.supported) {
    throw createReactUnsupportedRuntimeError(diagnostics);
  }
  return diagnostics;
}

const ReactRuntimeContext = createContext<ReactRuntimeContextValue | null>(null);

interface ReactCleanupOwner {
  readonly consumerVersion: AbiVersion | null;
  closeAsync(consumerVersion?: AbiVersion | null): Promise<BrowserOutcome<void>>;
}

interface ReactOwnerEntry {
  owner: ReactCleanupOwner | null;
  initialized: Promise<void>;
  initializedDone: boolean;
  closing: boolean;
  closed: boolean;
  attempt: Promise<BrowserOutcome<void>> | null;
  children: Set<ReactOwnerEntry>;
  forget(): void;
}

interface ReactOwnerGeneration<T> {
  entry: ReactOwnerEntry;
  ready: Promise<BrowserOutcome<T>>;
}

interface ReactRuntimeContextInternal extends ReactRuntimeLifecycleContextValue {
  owner: ReactOwnerEntry | null;
}

function reactLifecycleFailure(error: unknown): BrowserOutcome<never> {
  let message: string;
  try {
    message = String(error).slice(0, 1024);
  } catch {
    message = "React owner lifecycle threw an unprintable value";
  }
  return OutcomeFactory.err("internal_failure", "unknown", message);
}

function reactOwnerReplaced(): BrowserOutcome<never> {
  return OutcomeFactory.cancelled({
    kind: "react_owner_replaced",
    phase: "completed",
    origin_region: "react-adapter",
    origin_task: null,
    timestamp_nanos: 0,
    message: "The React owner was replaced before initialization.",
    truncated: false,
  });
}

function cleanupOutcome(outcomes: readonly BrowserOutcome<void>[]): BrowserOutcome<void> {
  const severity = { ok: 0, err: 1, cancelled: 2, panicked: 3 };
  return outcomes.reduce<BrowserOutcome<void>>(
    (result, next) => severity[next.outcome] > severity[result.outcome] ? next : result,
    OutcomeFactory.ok(undefined),
  );
}

function retainedOwners(entries: readonly ReactOwnerEntry[]): number {
  const visited = new Set<ReactOwnerEntry>();
  let count = 0;
  const visit = (entry: ReactOwnerEntry) => {
    if (visited.has(entry)) return;
    visited.add(entry);
    if (entry.owner) count += 1;
    for (const child of entry.children) visit(child);
  };
  for (const entry of entries) visit(entry);
  return count;
}

function closeReactOwner(entry: ReactOwnerEntry): Promise<BrowserOutcome<void>> {
  entry.closing = true;
  if (entry.closed) return Promise.resolve(OutcomeFactory.ok(undefined));
  if (entry.attempt) return entry.attempt;

  let resolve!: (outcome: BrowserOutcome<void>) => void;
  const attempt = new Promise<BrowserOutcome<void>>((done) => { resolve = done; });
  // Publish before closeAsync can abort a host request and reenter cleanup.
  entry.attempt = attempt;
  void (async () => {
    let outcome: BrowserOutcome<void>;
    try {
      if (!entry.initializedDone) await entry.initialized;
      const children = [...entry.children];
      outcome = children.length === 0 ? OutcomeFactory.ok(undefined)
        : cleanupOutcome(await Promise.all(children.map(closeReactOwner)));
      if (outcome.outcome === "ok" && entry.owner) {
        outcome = await entry.owner.closeAsync(entry.owner.consumerVersion);
      }
      if (outcome.outcome === "ok") {
        entry.owner = null;
        entry.closed = true;
        entry.forget();
      }
    } catch (error) {
      outcome = reactLifecycleFailure(error);
    }
    // Refusal keeps the owner and permits an explicit retry. Other attempts
    // must not be cleared if host callbacks have already started a new one.
    if (entry.attempt === attempt) entry.attempt = null;
    resolve(outcome);
  })();
  return attempt;
}

async function closeReactOwners(entries: readonly ReactOwnerEntry[]): Promise<ReactCleanupReport> {
  const snapshot = [...entries];
  // Fence every sibling before the first host callback can run.
  for (const entry of snapshot) entry.closing = true;
  const outcome = cleanupOutcome(await Promise.all(snapshot.map(closeReactOwner)));
  return {
    outcome,
    retainedOwners: retainedOwners(snapshot),
    retry: () => closeReactOwners(snapshot),
  };
}

function observeReactCleanup(
  completion: Promise<ReactCleanupReport>,
  observer: ReactCleanupObserver | undefined,
): void {
  if (!observer) return;
  void completion.then((report) => {
    try {
      observer(report);
    } catch {
      // An observer is not an owner and cannot interrupt or rewrite cleanup.
    }
  });
}

/** Forward completion to the latest committed observer, without owner churn. */
function useReactCleanupObserver(observer: ReactCleanupObserver | undefined): ReactCleanupObserver {
  const observerRef = useRef(observer);
  useEffect(() => {
    observerRef.current = observer;
  }, [observer]);
  return useCallback((report: ReactCleanupReport) => {
    observerRef.current?.(report);
  }, []);
}

/** One hook/provider's owners, including refused and pending old generations. */
class ReactOwnerLifecycle {
  private readonly entries = new Set<ReactOwnerEntry>();
  private active: ReactOwnerEntry | null = null;

  isCurrent(entry: ReactOwnerEntry): boolean {
    return this.active === entry && !entry.closing;
  }

  start<T extends ReactCleanupOwner>(
    create: () => BrowserOutcome<T> | Promise<BrowserOutcome<T>>,
    parent: ReactOwnerEntry | null = null,
  ): ReactOwnerGeneration<T> {
    const previous = [...this.entries];
    for (const entry of previous) entry.closing = true;
    let initialized!: () => void;
    let resolve!: (outcome: BrowserOutcome<T>) => void;
    const ready = new Promise<BrowserOutcome<T>>((done) => { resolve = done; });
    const entry: ReactOwnerEntry = {
      owner: null,
      initialized: new Promise<void>((done) => { initialized = done; }),
      initializedDone: false,
      closing: false,
      closed: false,
      attempt: null,
      children: new Set(),
      forget: () => {
        this.entries.delete(entry);
        parent?.children.delete(entry);
      },
    };
    this.entries.add(entry);
    parent?.children.add(entry);
    this.active = entry;
    // The record is visible before any prior close or factory callback runs.
    void (async () => {
      let outcome: BrowserOutcome<T>;
      try {
        const retired = await closeReactOwners(previous);
        if (retired.outcome.outcome !== "ok") {
          outcome = retired.outcome;
        } else if (!this.isCurrent(entry) || parent?.closing || parent?.closed) {
          outcome = reactOwnerReplaced();
        } else {
          outcome = await create();
          if (outcome.outcome === "ok") entry.owner = outcome.value;
        }
      } catch (error) {
        outcome = reactLifecycleFailure(error);
      }
      entry.initializedDone = true;
      initialized();
      resolve(outcome);
    })();
    return { entry, ready };
  }

  retire(entry: ReactOwnerEntry): Promise<ReactCleanupReport> {
    if (this.active === entry) this.active = null;
    return closeReactOwners([entry]);
  }

  close(): Promise<ReactCleanupReport> {
    const snapshot = [...this.entries];
    this.active = null;
    return closeReactOwners(snapshot);
  }
}

export function ReactRuntimeProvider({
  children,
  runtimeOptions,
  onCleanup,
}: ReactRuntimeProviderProps): ReactElement {
  const reportCleanup = useReactCleanupObserver(onCleanup);
  const consumerVersionMajor = runtimeOptions?.consumerVersion?.major ?? null;
  const consumerVersionMinor = runtimeOptions?.consumerVersion?.minor ?? null;
  const eagerInit = runtimeOptions?.eagerInit;
  const fetchAuthority = runtimeOptions?.fetchAuthority;
  const globalObject = runtimeOptions?.globalObject;
  const healthPolicyCooldownMs = runtimeOptions?.healthPolicy?.cooldownMs ?? null;
  const healthPolicyMaxConsecutiveFailures =
    runtimeOptions?.healthPolicy?.maxConsecutiveFailures ?? null;
  const healthScopeKey = runtimeOptions?.healthScopeKey ?? null;
  const now = runtimeOptions?.now;
  const preferredLane = runtimeOptions?.preferredLane ?? null;
  const wasmInput = runtimeOptions?.wasmInput;
  const [status, setStatus] = useState<ReactRuntimeStatus>("idle");
  const [runtime, setRuntime] = useState<BrowserRuntime | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [reloadNonce, setReloadNonce] = useState(0);
  const [diagnostics, setDiagnostics] = useState<ReactRuntimeSupportDiagnostics>(() =>
    detectReactRuntimeSupport(globalObject),
  );
  const lifecycleRef = useRef<ReactOwnerLifecycle | null>(null);
  if (!lifecycleRef.current) lifecycleRef.current = new ReactOwnerLifecycle();
  const lifecycle = lifecycleRef.current;
  const generationRef = useRef<ReactOwnerGeneration<BrowserRuntime> | null>(null);
  const epochRef = useRef(0);
  const effectRef = useRef<object | null>(null);
  const [publishedRequest, setPublishedRequest] = useState<object | null>(null);
  const requested = useMemo(() => ({
    options: {
      wasmInput,
      consumerVersion: runtimeOptions?.consumerVersion == null
        ? runtimeOptions?.consumerVersion
        : { major: consumerVersionMajor as number, minor: consumerVersionMinor as number },
      eagerInit,
      fetchAuthority,
      globalObject,
      preferredLane,
      healthPolicy: runtimeOptions?.healthPolicy === undefined ? undefined : {
        cooldownMs: healthPolicyCooldownMs ?? undefined,
        maxConsecutiveFailures: healthPolicyMaxConsecutiveFailures ?? undefined,
      },
      healthScopeKey,
      now,
    } satisfies BrowserRuntimeOptions,
  }), [
    consumerVersionMajor,
    consumerVersionMinor,
    eagerInit,
    fetchAuthority,
    globalObject,
    healthPolicyCooldownMs,
    healthPolicyMaxConsecutiveFailures,
    healthScopeKey,
    now,
    preferredLane,
    reloadNonce,
    wasmInput,
  ]);

  const reload = useCallback(() => {
    setReloadNonce((value) => value + 1);
  }, []);

  const closeAsync = useCallback((): Promise<ReactCleanupReport> => {
    const epoch = ++epochRef.current;
    const effect = effectRef.current;
    generationRef.current = null;
    if (effect) {
      setRuntime(null);
      setStatus("idle");
      setError(null);
    }
    const completion = lifecycle.close();
    void completion.then((report) => {
      if (!effect || effectRef.current !== effect || epoch !== epochRef.current) return;
      if (report.outcome.outcome !== "ok") {
        setStatus("failed");
        setError(new Error(formatOutcomeFailure(report.outcome)));
      }
    });
    observeReactCleanup(completion, reportCleanup);
    return completion;
  }, [lifecycle, reportCleanup]);

  useEffect(() => {
    let disposed = false;
    const epoch = ++epochRef.current;
    const effect = {};
    effectRef.current = effect;
    setPublishedRequest(requested);
    setRuntime(null);
    setStatus("initializing");
    setError(null);
    let supportError: Error | null = null;
    // StrictMode replacement waits for the old generation's actual retirement.
    const generation: ReactOwnerGeneration<BrowserRuntime> = lifecycle.start(async () => {
      const diagnosticsSnapshot = detectReactRuntimeSupport(globalObject);
      if (!disposed && epoch === epochRef.current) setDiagnostics(diagnosticsSnapshot);
      if (!lifecycle.isCurrent(generation.entry)) return reactOwnerReplaced();
      if (!diagnosticsSnapshot.supported) {
        supportError = createReactUnsupportedRuntimeError(diagnosticsSnapshot);
        return OutcomeFactory.err("capability_denied", "permanent", supportError.message);
      }
      return createBrowserRuntime(requested.options);
    });
    generationRef.current = generation;

    void generation.ready.then((created) => {
      if (disposed || epoch !== epochRef.current || !lifecycle.isCurrent(generation.entry)) return;
      if (created.outcome !== "ok") {
        setStatus("failed");
        setError(supportError ?? new Error(formatOutcomeFailure(created)));
        return;
      }
      setRuntime(created.value);
      setStatus("ready");
      setError(null);
    });

    return () => {
      disposed = true;
      if (effectRef.current === effect) effectRef.current = null;
      if (generationRef.current === generation) generationRef.current = null;
      observeReactCleanup(lifecycle.retire(generation.entry), reportCleanup);
    };
  }, [requested]);

  const generation = generationRef.current;
  const requestMatches = publishedRequest === requested;
  // Hide the old capability during the render-to-effect gap on prop changes.
  const visibleRuntime = requestMatches && generation && lifecycle.isCurrent(generation.entry)
    ? runtime : null;
  const visibleStatus = !requestMatches
    ? (status === "idle" ? "idle" : "initializing")
    : runtime && !visibleRuntime ? "idle" : status;
  const visibleError = requestMatches ? error : null;
  const owner = visibleRuntime ? generation?.entry ?? null : null;
  const value = useMemo<ReactRuntimeContextInternal>(
    () => ({
      status: visibleStatus,
      diagnostics,
      runtime: visibleRuntime,
      error: visibleError,
      reload,
      closeAsync,
      owner,
    }),
    [visibleStatus, diagnostics, visibleRuntime, visibleError, reload, closeAsync, owner],
  );

  return createElement(ReactRuntimeContext.Provider, { value }, children);
}

export function useReactRuntimeContext(): ReactRuntimeContextValue {
  const context = useContext(ReactRuntimeContext);
  if (!context) {
    throw new Error("ReactRuntimeProvider is required before calling useReactRuntimeContext().");
  }
  return context;
}

/** The existing runtime context plus an awaitable, retryable cleanup boundary. */
export function useReactRuntimeLifecycle(): ReactRuntimeLifecycleContextValue {
  return useReactRuntimeContext() as ReactRuntimeContextInternal;
}

export function useReactRuntime(): BrowserRuntime {
  const { runtime, status, error } = useReactRuntimeContext();
  if (runtime) {
    return runtime;
  }

  if (error) {
    throw error;
  }

  throw new Error(
    `Browser runtime is not ready (status=${status}). Wrap the tree in ReactRuntimeProvider and wait for initialization.`,
  );
}

export function useReactRuntimeDiagnostics(): ReactRuntimeSupportDiagnostics {
  return useReactRuntimeContext().diagnostics;
}

export function useReactScope(options: ReactScopeOptions = {}): ReactScopeState {
  return useReactScopeLifecycle(options);
}

/** Scope ownership with explicit observation of asynchronous teardown. */
export function useReactScopeLifecycle(options: ReactScopeOptions = {}): ReactScopeLifecycleState {
  const reportCleanup = useReactCleanupObserver(options.onCleanup);
  const context = useReactRuntimeContext() as ReactRuntimeContextInternal;
  const { runtime, status: runtimeStatus, error: runtimeError } = context;
  const parent = context.owner;
  const consumerVersionMajor = options.consumerVersion?.major ?? null;
  const consumerVersionMinor = options.consumerVersion?.minor ?? null;
  const requested = useMemo(() => ({
    runtime,
    parent,
    label: options.label,
    consumerVersion: options.consumerVersion == null ? options.consumerVersion
      : { major: consumerVersionMajor as number, minor: consumerVersionMinor as number },
  }), [runtime, parent, options.label, consumerVersionMajor, consumerVersionMinor]);
  const [status, setStatus] = useState<ReactScopeState["status"]>("idle");
  const [scope, setScope] = useState<RegionHandle | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [publishedRequest, setPublishedRequest] = useState<object | null>(null);
  const lifecycleRef = useRef<ReactOwnerLifecycle | null>(null);
  if (!lifecycleRef.current) lifecycleRef.current = new ReactOwnerLifecycle();
  const lifecycle = lifecycleRef.current;
  const generationRef = useRef<ReactOwnerGeneration<RegionHandle> | null>(null);
  const epochRef = useRef(0);
  const effectRef = useRef<object | null>(null);

  const closeAsync = useCallback((): Promise<ReactCleanupReport> => {
    const epoch = ++epochRef.current;
    const effect = effectRef.current;
    generationRef.current = null;
    if (effect) {
      setScope(null);
      setStatus("idle");
      setError(null);
    }
    const completion = lifecycle.close();
    void completion.then((report) => {
      if (!effect || effectRef.current !== effect || epoch !== epochRef.current) return;
      if (report.outcome.outcome !== "ok") {
        setStatus("failed");
        setError(new Error(formatOutcomeFailure(report.outcome)));
      }
    });
    observeReactCleanup(completion, reportCleanup);
    return completion;
  }, [lifecycle, reportCleanup]);

  const close = useCallback((): void => {
    void closeAsync();
  }, [closeAsync]);

  useEffect(() => {
    let disposed = false;
    const epoch = ++epochRef.current;
    const effect = {};
    effectRef.current = effect;
    setPublishedRequest(requested);
    setScope(null);
    setError(null);
    if (runtimeStatus !== "ready") {
      setStatus(runtimeError ? "failed" : "idle");
      setError(runtimeError);
      return () => {
        disposed = true;
        if (effectRef.current === effect) effectRef.current = null;
      };
    }
    if (!runtime || !parent) {
      setStatus("failed");
      setError(new Error("Runtime status is ready but runtime handle is missing."));
      return () => {
        disposed = true;
        if (effectRef.current === effect) effectRef.current = null;
      };
    }

    setStatus("opening");
    const generation = lifecycle.start(() => {
      const opened = runtime.enterScope(
        requested.label,
        requested.consumerVersion ?? runtime.consumerVersion,
      );
      return opened;
    }, parent);
    generationRef.current = generation;
    void generation.ready.then((opened) => {
      if (disposed || epoch !== epochRef.current || !lifecycle.isCurrent(generation.entry)) return;
      if (opened.outcome !== "ok") {
        setStatus("failed");
        setError(new Error(formatOutcomeFailure(opened)));
        return;
      }
      setScope(opened.value);
      setStatus("ready");
      setError(null);
    });

    return () => {
      disposed = true;
      if (effectRef.current === effect) effectRef.current = null;
      if (generationRef.current === generation) generationRef.current = null;
      observeReactCleanup(lifecycle.retire(generation.entry), reportCleanup);
    };
  }, [requested, runtimeStatus, runtimeError]);

  const generation = generationRef.current;
  const requestMatches = publishedRequest === requested;
  const visibleScope = requestMatches && runtimeStatus === "ready" && generation
    && lifecycle.isCurrent(generation.entry) && !parent?.closing ? scope : null;
  const visibleStatus = !requestMatches
    ? (runtimeError ? "failed" : runtimeStatus === "ready" ? "opening" : "idle")
    : scope && !visibleScope ? "idle" : status;
  const visibleError = requestMatches ? error : runtimeError;
  return useMemo(
    () => ({
      status: visibleStatus,
      scope: visibleScope,
      error: visibleError,
      close,
      closeAsync,
    }),
    [visibleStatus, visibleScope, visibleError, close, closeAsync],
  );
}

export { BROWSER_UNSUPPORTED_RUNTIME_CODE };
