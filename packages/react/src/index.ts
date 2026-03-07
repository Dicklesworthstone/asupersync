/**
 * @asupersync/react — React adapter layer for Browser Edition.
 *
 * Re-exports the SDK surface from @asupersync/browser.
 * React-specific hooks and providers will be added here.
 */

import {
  BROWSER_UNSUPPORTED_RUNTIME_CODE,
  detectBrowserRuntimeSupport,
  type BrowserRuntimeSupportDiagnostics,
} from "@asupersync/browser";

export * from "@asupersync/browser";

export interface ReactRuntimeSupportDiagnostics
  extends BrowserRuntimeSupportDiagnostics {
  packageName: "@asupersync/react";
}

export const REACT_UNSUPPORTED_RUNTIME_CODE =
  "ASUPERSYNC_REACT_UNSUPPORTED_RUNTIME";

export function detectReactRuntimeSupport(): ReactRuntimeSupportDiagnostics {
  const browserDiagnostics = detectBrowserRuntimeSupport();
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

export {
  BROWSER_UNSUPPORTED_RUNTIME_CODE,
};
