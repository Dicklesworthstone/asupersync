/**
 * @asupersync/next — Next.js adapter layer for Browser Edition.
 *
 * Re-exports the SDK surface from @asupersync/browser.
 * Next.js-specific boundary detection and fallback logic will be added here.
 */

import {
  detectBrowserRuntimeSupport,
  type BrowserRuntimeSupportDiagnostics,
} from "@asupersync/browser";

export * from "@asupersync/browser";

export type NextRuntimeTarget = "client" | "server" | "edge";

export interface NextRuntimeSupportDiagnostics
  extends Omit<BrowserRuntimeSupportDiagnostics, "packageName"> {
  packageName: "@asupersync/next";
  target: NextRuntimeTarget;
}

export const NEXT_UNSUPPORTED_RUNTIME_CODE =
  "ASUPERSYNC_NEXT_UNSUPPORTED_RUNTIME";

export function detectNextRuntimeSupport(
  target: NextRuntimeTarget = "client",
): NextRuntimeSupportDiagnostics {
  const browserDiagnostics = detectBrowserRuntimeSupport();
  if (target !== "client") {
    return {
      ...browserDiagnostics,
      supported: false,
      packageName: "@asupersync/next",
      target,
      reason: "missing_browser_dom",
      message: `Direct Browser Edition runtime execution is unsupported in Next ${target} runtimes.`,
      guidance: [
        "Move BrowserRuntime creation into a client component or browser-only module.",
        `Use bridge-only adapters rather than direct @asupersync/browser runtime calls in Next ${target} code.`,
      ],
    };
  }

  return {
    ...browserDiagnostics,
    packageName: "@asupersync/next",
    target,
    guidance: browserDiagnostics.supported
      ? []
      : [
          "Import @asupersync/next from client components only.",
          ...browserDiagnostics.guidance,
        ],
  };
}

export function createNextUnsupportedRuntimeError(
  diagnostics: NextRuntimeSupportDiagnostics = detectNextRuntimeSupport(),
): Error & {
  code: typeof NEXT_UNSUPPORTED_RUNTIME_CODE;
  diagnostics: NextRuntimeSupportDiagnostics;
} {
  const error = new Error(
    `${diagnostics.packageName}: ${diagnostics.message} ${diagnostics.guidance.join(" ")}`.trim(),
  ) as Error & {
    code: typeof NEXT_UNSUPPORTED_RUNTIME_CODE;
    diagnostics: NextRuntimeSupportDiagnostics;
  };
  error.code = NEXT_UNSUPPORTED_RUNTIME_CODE;
  error.diagnostics = diagnostics;
  return error;
}

export function assertNextRuntimeSupport(
  target: NextRuntimeTarget = "client",
  diagnostics: NextRuntimeSupportDiagnostics = detectNextRuntimeSupport(target),
): NextRuntimeSupportDiagnostics {
  if (!diagnostics.supported) {
    throw createNextUnsupportedRuntimeError(diagnostics);
  }
  return diagnostics;
}
