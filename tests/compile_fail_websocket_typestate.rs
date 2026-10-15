//! Compile-fail contracts for the split WebSocket write typestate.
//!
//! br-asupersync-typed-protocol-surfaces-cgulql.2 (TYPED — typestate hardening).
//! `src/net/websocket/split.rs` narrows the local write lifecycle at compile
//! time: data-send methods (`send_text`/`send_binary`/`ping`) exist only for the
//! statically-open [`OpenWebSocketWrite`] state, and `close` consumes that state,
//! handing back a [`CloseSentWebSocketWrite`] that has no data-send surface.
//!
//! These trybuild cases pin the illegal-transition matrix and assert the exact
//! compiler diagnostics (AC2: illegal transitions fail to compile; AC6: error
//! messages asserted — agents read them). Legal flows stay covered by the inline
//! `#[test]` in `split.rs` and the dynamic write tests; this harness only proves
//! the negatives.
//!
//! Repro: `cargo test --test compile_fail_websocket_typestate -- --ignored`
//! Regenerate goldens after an intended diagnostic change: prefix with
//! `TRYBUILD=overwrite` and re-run on the gate toolchain.

#[test]
#[ignore = "cold trybuild compile-fail lane; run explicitly with `cargo test --test compile_fail_websocket_typestate -- --ignored`"]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    // close() consumes the open write half: a later send through the moved
    // handle is a use-after-move (E0382).
    t.compile_fail("tests/compile_fail/websocket_typed_write_send_after_close.rs");
    // the close-sent state has no data-send methods: send_text does not resolve
    // (E0599).
    t.compile_fail("tests/compile_fail/websocket_typed_write_no_send_on_close_sent.rs");
}
