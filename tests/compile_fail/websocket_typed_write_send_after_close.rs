//! WebSocket write typestate (br-asupersync-typed-protocol-surfaces-cgulql.2):
//! `OpenWebSocketWrite::close` consumes the open write half at the type level.
//! After the close handshake is initiated, the old open handle is moved away, so
//! any later data send through it is rejected by the borrow checker instead of
//! by the dynamic `connection is closing` runtime guard.

use asupersync::cx::Cx;
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::net::websocket::{CloseReason, OpenWebSocketWrite, WsError};

async fn send_after_close_does_not_compile<IO>(
    mut open: OpenWebSocketWrite<IO>,
    cx: &Cx,
) -> Result<(), WsError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    // `close` takes `self`, consuming the statically-open handle and handing
    // back a `CloseSentWebSocketWrite`.
    let _closing = open.close(cx, CloseReason::normal()).await?;
    // `open` was moved by the line above; a later data send must not compile.
    open.send_text(cx, "late payload").await?;
    Ok(())
}

fn main() {}
