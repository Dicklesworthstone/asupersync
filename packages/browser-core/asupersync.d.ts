/* tslint:disable */
/* eslint-disable */

/**
 * `abi_fingerprint` ABI symbol.
 */
export function abi_fingerprint(): bigint;

/**
 * `abi_version` ABI symbol.
 */
export function abi_version(): string;

/**
 * `fetch_request` ABI symbol.
 */
export function fetch_request(request_json: string, consumer_version_json?: string | null): string;

/**
 * `runtime_close` ABI symbol.
 */
export function runtime_close(handle_json: string, consumer_version_json?: string | null): string;

/**
 * `runtime_create` ABI symbol.
 */
export function runtime_create(consumer_version_json?: string | null): string;

/**
 * `scope_close` ABI symbol.
 */
export function scope_close(handle_json: string, consumer_version_json?: string | null): string;

/**
 * `scope_enter` ABI symbol.
 */
export function scope_enter(request_json: string, consumer_version_json?: string | null): string;

/**
 * `task_cancel` ABI symbol.
 */
export function task_cancel(request_json: string, consumer_version_json?: string | null): string;

/**
 * `task_join` ABI symbol.
 */
export function task_join(handle_json: string, outcome_json: string, consumer_version_json?: string | null): string;

/**
 * `task_spawn` ABI symbol.
 */
export function task_spawn(request_json: string, consumer_version_json?: string | null): string;

/**
 * `websocket_cancel` bridge symbol.
 */
export function websocket_cancel(request_json: string, consumer_version_json?: string | null): string;

/**
 * `websocket_close` bridge symbol.
 */
export function websocket_close(request_json: string, consumer_version_json?: string | null): string;

/**
 * `websocket_open` bridge symbol.
 */
export function websocket_open(request_json: string, consumer_version_json?: string | null): string;

/**
 * `websocket_recv` bridge symbol.
 */
export function websocket_recv(request_json: string, consumer_version_json?: string | null): string;

/**
 * `websocket_send` bridge symbol.
 */
export function websocket_send(request_json: string, consumer_version_json?: string | null): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly abi_fingerprint: () => bigint;
    readonly abi_version: (a: number) => void;
    readonly fetch_request: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly runtime_close: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly runtime_create: (a: number, b: number, c: number) => void;
    readonly scope_close: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly scope_enter: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly task_cancel: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly task_join: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
    readonly task_spawn: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly websocket_cancel: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly websocket_close: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly websocket_open: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly websocket_recv: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly websocket_send: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly __wasm_bindgen_func_elem_389: (a: number, b: number) => void;
    readonly __wasm_bindgen_func_elem_82: (a: number, b: number) => void;
    readonly __wasm_bindgen_func_elem_394: (a: number, b: number, c: number, d: number) => void;
    readonly __wasm_bindgen_func_elem_101: (a: number, b: number, c: number) => void;
    readonly __wasm_bindgen_func_elem_101_2: (a: number, b: number, c: number) => void;
    readonly __wasm_bindgen_func_elem_101_3: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
