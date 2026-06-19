/**
 * @asupersync/react — React adapter layer for Browser Edition.
 *
 * Re-exports the SDK surface from @asupersync/browser and adds
 * StrictMode-safe provider/hook utilities for React applications.
 */

import {
  BROWSER_UNSUPPORTED_RUNTIME_CODE,
  createBrowserRuntime,
  formatOutcomeFailure,
  detectBrowserRuntimeSupport,
  type AbiVersion,
  type BrowserRuntime,
  type BrowserRuntimeOptions,
  type BrowserRuntimeSupportDiagnostics,
  type RegionHandle,
} from "@asupersync/browser";
import {
  createElement,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactElement,
  type ReactNode,
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

export interface ReactRuntimeProviderProps {
  children: ReactNode;
  runtimeOptions?: BrowserRuntimeOptions;
}

export interface ReactScopeOptions {
  label?: string;
  consumerVersion?: AbiVersion | null;
}

export interface ReactScopeState {
  status: "idle" | "opening" | "ready" | "failed";
  scope: RegionHandle | null;
  error: Error | null;
  close(): void;
}

export const REACT_UNSUPPORTED_RUNTIME_CODE =
  "ASUPERSYNC_REACT_UNSUPPORTED_RUNTIME";

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

function closeRuntime(runtime: BrowserRuntime | null): void {
  if (!runtime) {
    return;
  }
  runtime.close(runtime.consumerVersion);
}

function closeScope(scope: RegionHandle | null, consumerVersion?: AbiVersion | null): void {
  if (!scope) {
    return;
  }
  scope.close(consumerVersion ?? scope.consumerVersion);
}

export function ReactRuntimeProvider({
  children,
  runtimeOptions,
}: ReactRuntimeProviderProps): ReactElement {
  const consumerVersionMajor = runtimeOptions?.consumerVersion?.major ?? null;
  const consumerVersionMinor = runtimeOptions?.consumerVersion?.minor ?? null;
  const eagerInit = runtimeOptions?.eagerInit;
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
  const [diagnostics, setDiagnostics] = useState<ReactRuntimeSupportDiagnostics>(
    () => detectReactRuntimeSupport(globalObject),
  );
  const runtimeRef = useRef<BrowserRuntime | null>(null);
  const epochRef = useRef(0);

  const reload = useCallback(() => {
    setReloadNonce((value) => value + 1);
  }, []);

  useEffect(() => {
    const diagnosticsSnapshot = detectReactRuntimeSupport(globalObject);
    setDiagnostics(diagnosticsSnapshot);

    const previousRuntime = runtimeRef.current;
    if (previousRuntime) {
      closeRuntime(previousRuntime);
      runtimeRef.current = null;
    }
    setRuntime(null);

    if (!diagnosticsSnapshot.supported) {
      setStatus("failed");
      setError(createReactUnsupportedRuntimeError(diagnosticsSnapshot));
      return () => {};
    }

    setStatus("initializing");
    setError(null);

    // StrictMode-safe init: stale bootstrap completions are ignored/closed.
    let disposed = false;
    const epoch = ++epochRef.current;

    void createBrowserRuntime(runtimeOptions).then((created) => {
      if (disposed || epoch !== epochRef.current) {
        if (created.outcome === "ok") {
          closeRuntime(created.value);
        }
        return;
      }

      if (created.outcome !== "ok") {
        setStatus("failed");
        setError(new Error(formatOutcomeFailure(created)));
        return;
      }

      runtimeRef.current = created.value;
      setRuntime(created.value);
      setStatus("ready");
      setError(null);
    });

    return () => {
      disposed = true;
      if (epoch === epochRef.current) {
        const activeRuntime = runtimeRef.current;
        runtimeRef.current = null;
        setRuntime(null);
        closeRuntime(activeRuntime);
      }
    };
  }, [
    consumerVersionMajor,
    consumerVersionMinor,
    eagerInit,
    globalObject,
    healthPolicyCooldownMs,
    healthPolicyMaxConsecutiveFailures,
    healthScopeKey,
    now,
    preferredLane,
    reloadNonce,
    wasmInput,
  ]);

  const value = useMemo<ReactRuntimeContextValue>(
    () => ({
      status,
      diagnostics,
      runtime,
      error,
      reload,
    }),
    [status, diagnostics, runtime, error, reload],
  );

  return createElement(ReactRuntimeContext.Provider, { value }, children);
}

export function useReactRuntimeContext(): ReactRuntimeContextValue {
  const context = useContext(ReactRuntimeContext);
  if (!context) {
    throw new Error(
      "ReactRuntimeProvider is required before calling useReactRuntimeContext().",
    );
  }
  return context;
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
  const { runtime, status: runtimeStatus, error: runtimeError } = useReactRuntimeContext();
  const [status, setStatus] = useState<ReactScopeState["status"]>("idle");
  const [scope, setScope] = useState<RegionHandle | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const scopeRef = useRef<RegionHandle | null>(null);

  const close = useCallback(() => {
    const activeScope = scopeRef.current;
    scopeRef.current = null;
    closeScope(activeScope, options.consumerVersion);
    setScope(null);
    setStatus("idle");
    setError(null);
  }, [options.consumerVersion]);

  useEffect(() => {
    close();

    if (runtimeStatus !== "ready") {
      if (runtimeError) {
        setStatus("failed");
        setError(runtimeError);
      }
      return () => {};
    }

    if (!runtime) {
      setStatus("failed");
      setError(new Error("Runtime status is ready but runtime handle is missing."));
      return () => {};
    }

    setStatus("opening");
    const opened = runtime.enterScope(
      options.label,
      options.consumerVersion ?? runtime.consumerVersion,
    );
    if (opened.outcome !== "ok") {
      setStatus("failed");
      setError(new Error(formatOutcomeFailure(opened)));
      return () => {};
    }

    scopeRef.current = opened.value;
    setScope(opened.value);
    setStatus("ready");
    setError(null);

    return () => {
      close();
    };
  }, [
    close,
    options.consumerVersion,
    options.label,
    runtime,
    runtimeError,
    runtimeStatus,
  ]);

  return useMemo(
    () => ({
      status,
      scope,
      error,
      close,
    }),
    [status, scope, error, close],
  );
}

export {
  BROWSER_UNSUPPORTED_RUNTIME_CODE,
};
