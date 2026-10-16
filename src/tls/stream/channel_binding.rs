//! RFC 9266 and RFC 5929 channel bindings for an established TLS stream.

use super::{TlsConnection, TlsError, TlsStream};
use std::io;

impl<IO> TlsStream<IO> {
    /// Returns the RFC 9266 `tls-exporter` channel-binding data for TLS 1.3.
    ///
    /// Both endpoints of a successfully established connection obtain the
    /// same 32 bytes. These are the raw binding bytes, without a binding-type
    /// prefix or application-protocol encoding. This uses rustls's normal
    /// exporter, never the early-data exporter, with the exact RFC inputs:
    /// label `EXPORTER-Channel-Binding` (without a terminating NUL), an empty
    /// context, and a 32-byte output.
    ///
    /// The stream handshake must have completed, including flushing its final
    /// flight to the transport. Merely having negotiated TLS 1.3 is not enough.
    /// This synchronous operation performs no I/O and does not alter the
    /// stream. Repeated calls on the same open connection return the same data.
    ///
    /// This API deliberately supports **TLS 1.3 only**. RFC 9266 permits legacy
    /// TLS only with additional safeguards (including extended master secrets
    /// and no renegotiation); this API does not establish those safeguards for
    /// TLS 1.2 and therefore rejects it, even after a successful handshake.
    /// It does not fall back to another channel-binding type.
    ///
    /// # Security
    ///
    /// Use the result only for channel binding, not as an encryption key or
    /// other secret. It does not replace peer-certificate verification. As
    /// required by RFC 9266 section 4.1, applications must not use this binding
    /// for more than one authentication mechanism instance on a TLS connection
    /// and must close that connection when the upper-layer protocol concludes.
    /// See <https://www.rfc-editor.org/rfc/rfc9266.html> for the full contract.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Rustls`] with [`rustls::Error::HandshakeNotComplete`]
    /// before the stream handshake completes, [`TlsError::Configuration`] if
    /// TLS 1.3 was not negotiated, or [`TlsError::Io`] with
    /// [`io::ErrorKind::NotConnected`] after a failure, shutdown, or read EOF.
    /// Other exporter failures are preserved as [`TlsError::Rustls`]. No
    /// partial binding data is returned on error.
    pub fn tls_exporter_channel_binding(&self) -> Result<[u8; 32], TlsError> {
        self.ensure_channel_binding_ready("tls-exporter")?;
        if self.conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(TlsError::Configuration(
                "tls-exporter channel binding requires TLS 1.3; TLS 1.2 is not supported".into(),
            ));
        }

        // Keep these parameters fixed: exposing label/context/length choices
        // here would allow callers to derive a different, incompatible binding.
        // Taking the output by value also prevents exposing partial output on
        // error. Some(empty), rather than None, spells out the RFC's context.
        match &self.conn {
            TlsConnection::Client(conn) => {
                conn.export_keying_material([0_u8; 32], b"EXPORTER-Channel-Binding", Some(b""))
            }
            TlsConnection::Server(conn) => {
                conn.export_keying_material([0_u8; 32], b"EXPORTER-Channel-Binding", Some(b""))
            }
        }
        .map_err(TlsError::from)
    }

    /// Returns RFC 5929 `tls-server-end-point` data for an open TLS client.
    ///
    /// Uses the authenticated peer's leaf certificate from this connection,
    /// not a configured root, public key, or TLS cipher-suite hash. The result
    /// is raw digest bytes with the certificate-signature-dependent length;
    /// see [`crate::tls::Certificate::tls_server_end_point_channel_binding`].
    /// Unlike `tls-exporter`, the result is certificate-specific: connections
    /// authenticated by the same certificate normally have the same binding.
    /// There is no implicit fallback between these distinct binding types.
    ///
    /// Supports TLS 1.2 and TLS 1.3. The handshake, including the final transport
    /// flush, must have completed. This synchronous operation performs no I/O
    /// and does not change the stream or its normal certificate verification.
    ///
    /// Server-role streams are rejected, even with mutual TLS: their peer's
    /// certificate belongs to the client and is NOT the server-end-point
    /// binding. A server must instead use the certificate API with the exact
    /// server leaf selected for that connection (accounting for SNI/rotation).
    ///
    /// # Errors
    ///
    /// Returns [`TlsError::Rustls`] with [`rustls::Error::HandshakeNotComplete`]
    /// until the stream handshake completes, or [`TlsError::Io`] with
    /// [`io::ErrorKind::NotConnected`] after failure, shutdown, or read EOF.
    /// Unsupported protocols, server-role use, and unsupported certificate
    /// signature hashes return [`TlsError::Configuration`]. A missing or
    /// malformed server certificate returns [`TlsError::Certificate`].
    pub fn tls_server_end_point_channel_binding(&self) -> Result<Vec<u8>, TlsError> {
        self.ensure_channel_binding_ready("tls-server-end-point")?;
        if !matches!(
            self.conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2 | rustls::ProtocolVersion::TLSv1_3)
        ) {
            return Err(TlsError::Configuration(
                "tls-server-end-point requires TLS 1.2 or TLS 1.3".into(),
            ));
        }
        let TlsConnection::Client(conn) = &self.conn else {
            return Err(TlsError::Configuration(
                "server streams must bind their selected server certificate, not the client certificate"
                    .into(),
            ));
        };
        let leaf = conn
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or_else(|| {
                TlsError::Certificate("TLS connection has no server leaf certificate".into())
            })?;
        crate::tls::channel_binding::server_end_point(leaf.as_ref())
    }

    fn ensure_channel_binding_ready(&self, binding: &str) -> Result<(), TlsError> {
        if self.state.is_terminal()
            || self.state.shutdown_pending()
            || self.read_closed
            || self.read_error.is_some()
        {
            return Err(TlsError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("{binding} channel binding requires an open TLS stream"),
            )));
        }
        if !self.state.allows_application_io() || self.conn.is_handshaking() {
            return Err(TlsError::Rustls(rustls::Error::HandshakeNotComplete));
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "tls-ring"))]
#[path = "channel_binding_tests.rs"]
mod tests;

#[cfg(all(test, feature = "tls-ring"))]
#[path = "server_end_point_tests.rs"]
mod server_end_point_tests;
