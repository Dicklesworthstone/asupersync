/* @ts-self-types="./asupersync.d.ts" */

/**
 * `abi_fingerprint` ABI symbol.
 * @returns {bigint}
 */
export function abi_fingerprint() {
    const ret = wasm.abi_fingerprint();
    return BigInt.asUintN(64, ret);
}

/**
 * `abi_version` ABI symbol.
 * @returns {string}
 */
export function abi_version() {
    let deferred2_0;
    let deferred2_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.abi_version(retptr);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr1 = r0;
        var len1 = r1;
        if (r3) {
            ptr1 = 0; len1 = 0;
            throw takeObject(r2);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred2_0, deferred2_1, 1);
    }
}

/**
 * `fetch_request` ABI symbol.
 * @param {string} request_json
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function fetch_request(request_json, consumer_version_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(request_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len1 = WASM_VECTOR_LEN;
        wasm.fetch_request(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

/**
 * `runtime_close` ABI symbol.
 * @param {string} handle_json
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function runtime_close(handle_json, consumer_version_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(handle_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len1 = WASM_VECTOR_LEN;
        wasm.runtime_close(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

/**
 * `runtime_create` ABI symbol.
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function runtime_create(consumer_version_json) {
    let deferred3_0;
    let deferred3_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        var ptr0 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len0 = WASM_VECTOR_LEN;
        wasm.runtime_create(retptr, ptr0, len0);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr2 = r0;
        var len2 = r1;
        if (r3) {
            ptr2 = 0; len2 = 0;
            throw takeObject(r2);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred3_0, deferred3_1, 1);
    }
}

/**
 * `scope_close` ABI symbol.
 * @param {string} handle_json
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function scope_close(handle_json, consumer_version_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(handle_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len1 = WASM_VECTOR_LEN;
        wasm.scope_close(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

/**
 * `scope_enter` ABI symbol.
 * @param {string} request_json
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function scope_enter(request_json, consumer_version_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(request_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len1 = WASM_VECTOR_LEN;
        wasm.scope_enter(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

/**
 * `task_cancel` ABI symbol.
 * @param {string} request_json
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function task_cancel(request_json, consumer_version_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(request_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len1 = WASM_VECTOR_LEN;
        wasm.task_cancel(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

/**
 * `task_join` ABI symbol.
 * @param {string} handle_json
 * @param {string} outcome_json
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function task_join(handle_json, outcome_json, consumer_version_json) {
    let deferred5_0;
    let deferred5_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(handle_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(outcome_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len2 = WASM_VECTOR_LEN;
        wasm.task_join(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr4 = r0;
        var len4 = r1;
        if (r3) {
            ptr4 = 0; len4 = 0;
            throw takeObject(r2);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred5_0, deferred5_1, 1);
    }
}

/**
 * `task_spawn` ABI symbol.
 * @param {string} request_json
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function task_spawn(request_json, consumer_version_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(request_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len1 = WASM_VECTOR_LEN;
        wasm.task_spawn(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

/**
 * `websocket_cancel` bridge symbol.
 * @param {string} request_json
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function websocket_cancel(request_json, consumer_version_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(request_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len1 = WASM_VECTOR_LEN;
        wasm.websocket_cancel(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

/**
 * `websocket_close` bridge symbol.
 * @param {string} request_json
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function websocket_close(request_json, consumer_version_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(request_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len1 = WASM_VECTOR_LEN;
        wasm.websocket_close(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

/**
 * `websocket_open` bridge symbol.
 * @param {string} request_json
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function websocket_open(request_json, consumer_version_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(request_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len1 = WASM_VECTOR_LEN;
        wasm.websocket_open(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

/**
 * `websocket_recv` bridge symbol.
 * @param {string} request_json
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function websocket_recv(request_json, consumer_version_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(request_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len1 = WASM_VECTOR_LEN;
        wasm.websocket_recv(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

/**
 * `websocket_send` bridge symbol.
 * @param {string} request_json
 * @param {string | null} [consumer_version_json]
 * @returns {string}
 */
export function websocket_send(request_json, consumer_version_json) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(request_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(consumer_version_json) ? 0 : passStringToWasm0(consumer_version_json, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len1 = WASM_VECTOR_LEN;
        wasm.websocket_send(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_is_function_3c846841762788c1: function(arg0) {
            const ret = typeof(getObject(arg0)) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_undefined_52709e72fb9f179c: function(arg0) {
            const ret = getObject(arg0) === undefined;
            return ret;
        },
        __wbg___wbindgen_string_get_395e606bd0ee4427: function(arg0, arg1) {
            const obj = getObject(arg1);
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_6ddd609b62940d55: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_6b5b6b8576d35cb1: function(arg0) {
            getObject(arg0)._wbg_cb_unref();
        },
        __wbg_close_a86fff250f8aa14f: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            getObject(arg0).close(arg1, getStringFromWasm0(arg2, arg3));
        }, arguments); },
        __wbg_close_af26905c832a88cb: function() { return handleError(function (arg0) {
            getObject(arg0).close();
        }, arguments); },
        __wbg_code_aea376e2d265a64f: function(arg0) {
            const ret = getObject(arg0).code;
            return ret;
        },
        __wbg_data_a3d9ff9cdd801002: function(arg0) {
            const ret = getObject(arg0).data;
            return addHeapObject(ret);
        },
        __wbg_fetch_b967ec80e0e1eff8: function(arg0, arg1, arg2, arg3) {
            const ret = getObject(arg0).fetch(getStringFromWasm0(arg1, arg2), getObject(arg3));
            return addHeapObject(ret);
        },
        __wbg_fetch_fbe46fb035a696c9: function(arg0, arg1, arg2, arg3) {
            const ret = getObject(arg0).fetch(getStringFromWasm0(arg1, arg2), getObject(arg3));
            return addHeapObject(ret);
        },
        __wbg_get_3ef1eba1850ade27: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(getObject(arg0), getObject(arg1));
            return addHeapObject(ret);
        }, arguments); },
        __wbg_instanceof_ArrayBuffer_101e2bf31071a9f6: function(arg0) {
            let result;
            try {
                result = getObject(arg0) instanceof ArrayBuffer;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Response_9b4d9fd451e051b1: function(arg0) {
            let result;
            try {
                result = getObject(arg0) instanceof Response;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Window_23e677d2c6843922: function(arg0) {
            let result;
            try {
                result = getObject(arg0) instanceof Window;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_WorkerGlobalScope_de6976d00cb213c6: function(arg0) {
            let result;
            try {
                result = getObject(arg0) instanceof WorkerGlobalScope;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_length_ea16607d7b61445b: function(arg0) {
            const ret = getObject(arg0).length;
            return ret;
        },
        __wbg_new_5f486cdf45a04d78: function(arg0) {
            const ret = new Uint8Array(getObject(arg0));
            return addHeapObject(ret);
        },
        __wbg_new_a70fbab9066b301f: function() {
            const ret = new Array();
            return addHeapObject(ret);
        },
        __wbg_new_ab79df5bd7c26067: function() {
            const ret = new Object();
            return addHeapObject(ret);
        },
        __wbg_new_c518c60af666645b: function() { return handleError(function () {
            const ret = new AbortController();
            return addHeapObject(ret);
        }, arguments); },
        __wbg_new_dd50bcc3f60ba434: function() { return handleError(function (arg0, arg1) {
            const ret = new WebSocket(getStringFromWasm0(arg0, arg1));
            return addHeapObject(ret);
        }, arguments); },
        __wbg_new_from_slice_22da9388ac046e50: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return addHeapObject(ret);
        },
        __wbg_new_with_str_sequence_82c04ad794ead10e: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = new WebSocket(getStringFromWasm0(arg0, arg1), getObject(arg2));
            return addHeapObject(ret);
        }, arguments); },
        __wbg_prototypesetcall_d62e5099504357e6: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), getObject(arg2));
        },
        __wbg_push_e87b0e732085a946: function(arg0, arg1) {
            const ret = getObject(arg0).push(getObject(arg1));
            return ret;
        },
        __wbg_queueMicrotask_0c399741342fb10f: function(arg0) {
            const ret = getObject(arg0).queueMicrotask;
            return addHeapObject(ret);
        },
        __wbg_queueMicrotask_a082d78ce798393e: function(arg0) {
            queueMicrotask(getObject(arg0));
        },
        __wbg_reason_cbcb9911796c4714: function(arg0, arg1) {
            const ret = getObject(arg1).reason;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg_resolve_ae8d83246e5bcc12: function(arg0) {
            const ret = Promise.resolve(getObject(arg0));
            return addHeapObject(ret);
        },
        __wbg_send_4a1dc66e8653e5ed: function() { return handleError(function (arg0, arg1, arg2) {
            getObject(arg0).send(getStringFromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_send_d31a693c975dea74: function() { return handleError(function (arg0, arg1, arg2) {
            getObject(arg0).send(getArrayU8FromWasm0(arg1, arg2));
        }, arguments); },
        __wbg_set_binaryType_3dcf8281ec100a8f: function(arg0, arg1) {
            getObject(arg0).binaryType = __wbindgen_enum_BinaryType[arg1];
        },
        __wbg_set_body_a3d856b097dfda04: function(arg0, arg1) {
            getObject(arg0).body = getObject(arg1);
        },
        __wbg_set_method_8c015e8bcafd7be1: function(arg0, arg1, arg2) {
            getObject(arg0).method = getStringFromWasm0(arg1, arg2);
        },
        __wbg_set_onclose_8da801226bdd7a7b: function(arg0, arg1) {
            getObject(arg0).onclose = getObject(arg1);
        },
        __wbg_set_onerror_901ca711f94a5bbb: function(arg0, arg1) {
            getObject(arg0).onerror = getObject(arg1);
        },
        __wbg_set_onmessage_6f80ab771bf151aa: function(arg0, arg1) {
            getObject(arg0).onmessage = getObject(arg1);
        },
        __wbg_set_signal_0cebecb698f25d21: function(arg0, arg1) {
            getObject(arg0).signal = getObject(arg1);
        },
        __wbg_signal_166e1da31adcac18: function(arg0) {
            const ret = getObject(arg0).signal;
            return addHeapObject(ret);
        },
        __wbg_static_accessor_GLOBAL_8adb955bd33fac2f: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_ad356e0db91c7913: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_SELF_f207c857566db248: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_static_accessor_WINDOW_bb9f1ba69d61b386: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addHeapObject(ret);
        },
        __wbg_status_318629ab93a22955: function(arg0) {
            const ret = getObject(arg0).status;
            return ret;
        },
        __wbg_stringify_5ae93966a84901ac: function() { return handleError(function (arg0) {
            const ret = JSON.stringify(getObject(arg0));
            return addHeapObject(ret);
        }, arguments); },
        __wbg_then_098abe61755d12f6: function(arg0, arg1) {
            const ret = getObject(arg0).then(getObject(arg1));
            return addHeapObject(ret);
        },
        __wbg_then_9e335f6dd892bc11: function(arg0, arg1, arg2) {
            const ret = getObject(arg0).then(getObject(arg1), getObject(arg2));
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { dtor_idx: 106, function: Function { arguments: [Externref], shim_idx: 107, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm.__wasm_bindgen_func_elem_389, __wasm_bindgen_func_elem_394);
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { dtor_idx: 5, function: Function { arguments: [NamedExternref("CloseEvent")], shim_idx: 6, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm.__wasm_bindgen_func_elem_82, __wasm_bindgen_func_elem_101);
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { dtor_idx: 5, function: Function { arguments: [NamedExternref("Event")], shim_idx: 6, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm.__wasm_bindgen_func_elem_82, __wasm_bindgen_func_elem_101_2);
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { dtor_idx: 5, function: Function { arguments: [NamedExternref("MessageEvent")], shim_idx: 6, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm.__wasm_bindgen_func_elem_82, __wasm_bindgen_func_elem_101_3);
            return addHeapObject(ret);
        },
        __wbindgen_cast_0000000000000005: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_object_clone_ref: function(arg0) {
            const ret = getObject(arg0);
            return addHeapObject(ret);
        },
        __wbindgen_object_drop_ref: function(arg0) {
            takeObject(arg0);
        },
    };
    return {
        __proto__: null,
        "./asupersync_bg.js": import0,
    };
}

function __wasm_bindgen_func_elem_101(arg0, arg1, arg2) {
    wasm.__wasm_bindgen_func_elem_101(arg0, arg1, addHeapObject(arg2));
}

function __wasm_bindgen_func_elem_101_2(arg0, arg1, arg2) {
    wasm.__wasm_bindgen_func_elem_101_2(arg0, arg1, addHeapObject(arg2));
}

function __wasm_bindgen_func_elem_101_3(arg0, arg1, arg2) {
    wasm.__wasm_bindgen_func_elem_101_3(arg0, arg1, addHeapObject(arg2));
}

function __wasm_bindgen_func_elem_394(arg0, arg1, arg2) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        wasm.__wasm_bindgen_func_elem_394(retptr, arg0, arg1, addHeapObject(arg2));
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        if (r1) {
            throw takeObject(r0);
        }
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}


const __wbindgen_enum_BinaryType = ["blob", "arraybuffer"];

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => state.dtor(state.a, state.b));

function dropObject(idx) {
    if (idx < 1028) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getObject(idx) { return heap[idx]; }

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_export3(addHeapObject(e));
    }
}

let heap = new Array(1024).fill(undefined);
heap.push(undefined, null, true, false);

let heap_next = heap.length;

function isLikeNone(x) {
    return x === undefined || x === null;
}

function makeMutClosure(arg0, arg1, dtor, f) {
    const state = { a: arg0, b: arg1, cnt: 1, dtor };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            state.dtor(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('asupersync_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
