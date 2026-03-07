/**
 * @asupersync/browser — High-level Browser Edition SDK surface.
 *
 * Re-exports the low-level runtime bindings from @asupersync/browser-core
 * and adds SDK-level ergonomics (init helpers, diagnostics, lifecycle).
 */

// Re-export all public symbols from browser-core
export {
  default as init,
  runtime_create,
  runtime_close,
  scope_enter,
  scope_close,
  task_spawn,
  task_join,
  task_cancel,
  fetch_request,
  websocket_open,
  websocket_send,
  websocket_recv,
  websocket_close,
  websocket_cancel,
  abi_version,
  abi_fingerprint,
} from "@asupersync/browser-core";

/** ABI metadata re-exported for diagnostics. */
export { default as abiMetadata } from "@asupersync/browser-core/abi-metadata.json";

export type { InitInput } from "@asupersync/browser-core";
