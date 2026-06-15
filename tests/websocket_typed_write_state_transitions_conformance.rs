//! Conformance: split WebSocket write-half typestate lifecycle (bead cgulql.2).
//!
//! Durable integration coverage for the opt-in `TypedWebSocketWrite` narrowing
//! (`WebSocketWrite::into_typed_open` -> `OpenWebSocketWrite` -> `close` ->
//! `CloseSentWebSocketWrite`). It complements the in-module unit test
//! (`net::websocket::split::tests::typed_write_close_consumes_open_state`) and the
//! trybuild compile-fail matrix (`tests/compile_fail_websocket_typestate.rs`) by
//! pinning the PUBLIC runtime behaviors neither of those exercises:
//!
//!   * `send_binary` / `ping` on the statically-open wrapper (the unit test only
//!     drives `send_text`),
//!   * `into_dynamic` from the Open state — the escape hatch stays open and can
//!     still send data,
//!   * the defense-in-depth invariant: dropping back to the dynamic API from
//!     `CloseSent` STILL rejects data sends at runtime, so the compile-time
//!     narrowing and the runtime `connection is closing` guard agree,
//!   * `is_closed` / `close_state` delegation on the typed wrapper and
//!     `flush_close` idempotence (repeated flushes never reopen data sends).
//!
//! Public API only; `--features test-internals` is required for `Cx::for_testing`.

use asupersync::bytes::Bytes;
use asupersync::cx::Cx;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::net::websocket::{
    CloseReason, CloseState, Message, WebSocket, WebSocketConfig, WsError,
};
use futures_lite::future::block_on;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Minimal in-memory transport: accepts every write, reports EOF on read.
///
/// The write-half typestate lifecycle never reads, so a single immediate EOF is
/// sufficient and keeps every send a synchronous, reactor-free buffer write. The
/// written bytes are intentionally discarded — these tests assert on lifecycle
/// state, not on the wire encoding.
struct MemIo;

impl AsyncRead for MemIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // No bytes filled => EOF.
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn fresh_ws() -> WebSocket<MemIo> {
    WebSocket::from_upgraded(MemIo, WebSocketConfig::default())
}

#[test]
fn typed_open_send_text_binary_ping_then_close_consumes_state() {
    block_on(async {
        let (_read, write) = fresh_ws().split();
        let cx = Cx::for_testing();
        let mut open = write.into_typed_open();

        assert!(open.is_open(), "typed write starts statically open");
        assert!(!open.is_closed(), "a fresh handshake is not closed");

        open.send_text(&cx, "hello")
            .await
            .expect("send_text must succeed on the open wrapper");
        open.send_binary(&cx, Bytes::from_static(b"\x01\x02\x03"))
            .await
            .expect("send_binary must succeed on the open wrapper");
        open.ping(Bytes::from_static(b"pp"))
            .await
            .expect("ping must succeed on the open wrapper");

        let closing = open
            .close(&cx, CloseReason::normal())
            .await
            .expect("close must consume the open state and initiate the handshake");
        assert_eq!(
            closing.close_state(),
            CloseState::CloseSent,
            "close leaves the underlying handshake in CloseSent"
        );
        assert!(
            !closing.is_closed(),
            "close initiation is a half-close, not a finished handshake"
        );
    });
}

#[test]
fn into_dynamic_from_open_preserves_open_and_sends() {
    block_on(async {
        let (_read, write) = fresh_ws().split();
        let cx = Cx::for_testing();
        let open = write.into_typed_open();

        let mut dynamic = open.into_dynamic();
        assert!(
            dynamic.is_open(),
            "the Open escape hatch must remain open after into_dynamic"
        );
        dynamic
            .send(&cx, Message::text("via dynamic"))
            .await
            .expect("the dynamic escape hatch can still send data while open");
    });
}

#[test]
fn close_sent_into_dynamic_still_rejects_data_defense_in_depth() {
    block_on(async {
        let (_read, write) = fresh_ws().split();
        let cx = Cx::for_testing();
        let open = write.into_typed_open();

        let closing = open
            .close(&cx, CloseReason::normal())
            .await
            .expect("close must consume the open state");

        // The compile-time narrowing removes data-send methods on CloseSent; the
        // runtime guard underneath must independently reject data sends too, so
        // even the dynamic escape hatch cannot resurrect a closed lifecycle.
        let mut dynamic = closing.into_dynamic();
        assert!(
            !dynamic.is_open(),
            "the CloseSent escape hatch must not report open"
        );

        let err = dynamic
            .send(&cx, Message::text("late payload"))
            .await
            .expect_err("the runtime guard must reject data after close initiation");
        assert!(
            matches!(err, WsError::Io(ref e) if e.kind() == io::ErrorKind::NotConnected),
            "expected NotConnected from the runtime close guard, got {err:?}"
        );
    });
}

#[test]
fn typed_wrapper_close_state_and_is_closed_track_handshake() {
    block_on(async {
        let (_read, write) = fresh_ws().split();
        let cx = Cx::for_testing();
        let open = write.into_typed_open();

        assert_ne!(
            open.close_state(),
            CloseState::CloseSent,
            "a fresh open wrapper is not already CloseSent"
        );
        assert!(!open.is_closed(), "a fresh open wrapper is not closed");

        let closing = open
            .close(&cx, CloseReason::normal())
            .await
            .expect("close consumes the open state");
        assert_eq!(
            closing.close_state(),
            CloseState::CloseSent,
            "the typed wrapper reflects the underlying CloseSent state"
        );
        assert!(
            !closing.is_closed(),
            "the handshake is half-closed, not finished"
        );
    });
}

#[test]
fn flush_close_is_idempotent_and_keeps_close_sent() {
    block_on(async {
        let (_read, write) = fresh_ws().split();
        let cx = Cx::for_testing();
        let open = write.into_typed_open();

        let mut closing = open
            .close(&cx, CloseReason::normal())
            .await
            .expect("close consumes the open state");

        // Re-flushing a CloseSent handshake must never reopen data sends.
        closing
            .flush_close(&cx)
            .await
            .expect("first flush_close must succeed");
        closing
            .flush_close(&cx)
            .await
            .expect("repeated flush_close must be idempotent");
        assert_eq!(
            closing.close_state(),
            CloseState::CloseSent,
            "repeated flush_close stays in CloseSent"
        );

        let dynamic = closing.into_dynamic();
        assert!(
            !dynamic.is_open(),
            "flush_close keeps the connection closed through the escape hatch"
        );
    });
}
