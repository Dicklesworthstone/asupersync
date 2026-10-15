//! WebSocket write typestate (br-asupersync-typed-protocol-surfaces-cgulql.2):
//! the `CloseSentWebSocketWrite` state deliberately exposes no data-send
//! methods. Only `OpenWebSocketWrite` carries `send_text`/`send_binary`/`ping`,
//! so attempting a data send on a close-sent handle is a missing-method error at
//! compile time rather than a runtime rejection.

use asupersync::cx::Cx;
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::net::websocket::{CloseSentWebSocketWrite, WsError};

async fn data_send_on_close_sent_does_not_compile<IO>(
    mut closing: CloseSentWebSocketWrite<IO>,
    cx: &Cx,
) -> Result<(), WsError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    // `send_text` exists only for `OpenWebSocketWrite`; the close-sent state has
    // no data-send surface, so this call has no method to resolve.
    closing.send_text(cx, "late payload").await?;
    Ok(())
}

fn main() {}
