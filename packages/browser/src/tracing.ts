/**
 * @asupersync/browser/tracing
 *
 * Diagnostics-facing helpers for framework adapters and host integrations.
 * This subpath is intentionally side-effect-free so it remains tree-shake-safe.
 */

export type BrowserTraceSeverity = "trace" | "debug" | "info" | "warn" | "error";

export interface BrowserTraceRecord {
  category: string;
  message: string;
  severity: BrowserTraceSeverity;
  fields?: Record<string, string | number | boolean | null>;
}

export interface BrowserTraceSink {
  emit(record: BrowserTraceRecord): void;
}

/**
 * No-op sink used by adapters that need a deterministic fallback.
 */
export const NOOP_TRACE_SINK: BrowserTraceSink = {
  emit() {
    // Intentionally empty.
  },
};

/**
 * Emit a record into a sink if one is configured.
 */
export function emitTraceRecord(
  sink: BrowserTraceSink | undefined,
  record: BrowserTraceRecord,
): void {
  (sink ?? NOOP_TRACE_SINK).emit(record);
}
