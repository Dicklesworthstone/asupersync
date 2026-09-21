/**
 * Public type surface for `@asupersync/browser-core/types`.
 *
 * This file is intentionally declaration-only and side-effect-free so it can
 * be consumed from adapter packages without importing runtime code paths.
 */

export interface Outcome<T = unknown, E = unknown> {
  kind: "ok" | "err" | "cancelled" | "panicked";
  value?: T;
  error?: E;
}

export interface Budget {
  deadlineMs?: number;
  pollQuota?: number;
  costQuota?: number;
  priority?: number;
}
