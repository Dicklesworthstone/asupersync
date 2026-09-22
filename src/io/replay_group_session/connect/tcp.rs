//! Concrete TCP target binding for the connection-result recorder/replayer.

use super::{ConnectionAttempt, GroupReplayIo, ReplayGroupSession};
#[cfg(not(target_arch = "wasm32"))]
use super::{RecordingConnection, RecordingGroupSession};
#[cfg(not(target_arch = "wasm32"))]
use crate::net::TcpStream;
#[cfg(not(target_arch = "wasm32"))]
use crate::time::TimeSource;
use std::io;
use std::net::SocketAddr;

// Fixed-width subtype of the opaque connection request key. All bytes are
// initialized. Family is explicit: IPv4 and mapped IPv6 must not alias. The
// IPv6 flow/scope fields are not preserved by ordinary SocketAddr formatting.
fn request_key(address: SocketAddr) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..8].copy_from_slice(b"ASUPTCP\0");
    key[8] = 1;
    key[10..12].copy_from_slice(&address.port().to_be_bytes());
    match address {
        SocketAddr::V4(address) => {
            key[9] = 4;
            key[12..16].copy_from_slice(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            key[9] = 6;
            key[12..28].copy_from_slice(&address.ip().octets());
            key[28..32].copy_from_slice(&address.flowinfo().to_be_bytes());
            key[32..36].copy_from_slice(&address.scope_id().to_be_bytes());
        }
    }
    key
}

#[cfg(not(target_arch = "wasm32"))]
impl<S: TimeSource + ?Sized> RecordingGroupSession<S> {
    /// Connect to one concrete TCP address and record its actual result.
    ///
    /// The exact IP family, address, port, IPv6 flow information and scope ID
    /// are bound automatically into the connection request. This invokes the
    /// maintained nonblocking TCP connector directly, without DNS, socket-option
    /// changes, implicit retries or TLS. Every retry needs a new attempt identity.
    ///
    /// Authorize the destination before calling, and use the existing runtime
    /// context and an owner-controlled deadline/cancellation. This adapter does
    /// not grant network authority or create a runtime/task. Its source obeys
    /// the existing TCP connector's cancellation semantics. Capture refusal
    /// preserves the live result, but invalidates the whole observation window.
    /// Return successful streams with `RecordingConnection::into_inner` after
    /// their users drain. Dropping an unfinished owner is not successful capture.
    ///
    /// Use `connect_with` instead for DNS, TLS, tunnels, authentication or custom
    /// options, binding those policies into the opaque request key. This method
    /// records TCP connection results and bytes, not handshake internals, OS
    /// readiness timing, local/peer-address queries or live socket options.
    pub async fn connect_tcp(
        &self,
        attempt: ConnectionAttempt,
        address: SocketAddr,
    ) -> io::Result<RecordingConnection<TcpStream>> {
        let key = request_key(address);
        self.connect_with(attempt, &key, key.len(), move || {
            TcpStream::connect_socket_addr(address)
        }).await
    }
}

impl ReplayGroupSession {
    /// Replay a recorded concrete TCP attempt, without opening any socket.
    ///
    /// This pairs with `RecordingGroupSession::connect_tcp`. Changed destination
    /// fields fail through the same fingerprint/timeline checks as other altered
    /// requests. Even identical textual IPv6 addresses with different flow/scope
    /// values cannot alias. The resulting byte stream contains no TCP provider.
    /// No DNS, connection retry, wall clock or random source is consulted.
    /// Native error kind/code and recorded byte-I/O semantics are unchanged;
    /// the existing tape's OS import restriction still applies.
    pub async fn connect_tcp(
        &self,
        attempt: ConnectionAttempt,
        address: SocketAddr,
    ) -> io::Result<GroupReplayIo> {
        let key = request_key(address);
        self.connect(attempt, &key).await
    }
}

#[cfg(test)]
mod tests;
