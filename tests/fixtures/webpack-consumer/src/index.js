import { abiFingerprint, abiVersion, detectBrowserRuntimeSupport } from "@asupersync/browser";

const payload = {
  support: detectBrowserRuntimeSupport(),
  abiVersion: abiVersion(),
  abiFingerprint: abiFingerprint(),
};

if (typeof globalThis !== "undefined") {
  globalThis.__asupersyncWebpackSmoke = payload;
}

console.log(JSON.stringify(payload));
