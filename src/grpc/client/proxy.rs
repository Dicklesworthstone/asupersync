//! Explicit HTTP CONNECT routing for native channel transports.

use super::{Status, channel_target_is_loopback};
use crate::cx::Cx;
use crate::http::h1::codec::validate_header_field;
use crate::http::h1::http_client::{
    ClientError, ClientIo, HttpClient, HttpConnectTunnel, ParsedUrl, Scheme,
};
use std::fmt;

/// An explicit HTTP/1.1 CONNECT proxy for a native gRPC channel.
///
/// Both plaintext HTTP and TLS-protected HTTPS proxies are supported. Each
/// fresh RPC connection first establishes a tunnel to its destination, then
/// performs the channel's ordinary HTTP/2 setup. HTTPS origins still require
/// the channel's explicit TLS connector and `h2` ALPN; proxy TLS trust is
/// configured separately with [`Self::with_http_client`].
///
/// Proxy credentials belong in [`Self::with_authorization`], never RPC
/// metadata. Only that field is sent as `Proxy-Authorization` on CONNECT.
/// RPC metadata, cookies, and the HTTP client's default headers are not copied
/// into CONNECT headers. Refusals and redirects are returned without retrying the
/// request or connecting directly to the origin.
///
/// The channel's existing connection/call deadline and cancellation cover
/// tunnel negotiation. The HTTP client's request timeout can tighten that
/// setup bound. After setup, the existing gRPC owner drives the connection;
/// no extra runtime task or thread is spawned. A channel's opt-in unary pool
/// can reuse completed connections through its fixed proxy route.
#[derive(Clone)]
pub struct HttpConnectProxy {
    client: HttpClient,
    url: String,
    authorization: Option<String>,
}

impl fmt::Debug for HttpConnectProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpConnectProxy")
            .field("url", &self.url)
            .field("authorization_configured", &self.authorization.is_some())
            .finish_non_exhaustive()
    }
}

impl HttpConnectProxy {
    /// Select an HTTP or HTTPS proxy without opening a connection.
    ///
    /// The URL must identify only an endpoint, for example
    /// `http://proxy.example:3128`. Userinfo, query strings, fragments, and
    /// non-root paths are refused. Supply credentials separately. HTTPS
    /// proxies require the `tls` feature and the HTTP client's trust policy.
    /// Invalid input is refused before DNS or socket creation.
    pub fn new(url: impl Into<String>) -> Result<Self, Status> {
        let url = url.into();
        let parsed = ParsedUrl::parse(&url)
            .map_err(|_| Status::invalid_argument("invalid gRPC HTTP CONNECT proxy URL"))?;
        if parsed.port == 0 || parsed.path != "/" || url.contains(['?', '#', '@']) {
            return Err(Status::invalid_argument(
                "gRPC HTTP CONNECT proxy URL must contain only a host and port",
            ));
        }
        #[cfg(not(feature = "tls"))]
        if parsed.scheme == Scheme::Https {
            return Err(Status::failed_precondition(
                "HTTPS gRPC proxies require the tls feature",
            ));
        }
        // Keep one normalized endpoint; paths and credentials never reach
        // CONNECT routing or Debug output.
        let scheme = match parsed.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        let host = if parsed.host.contains(':') && !parsed.host.starts_with('[') {
            format!("[{}]", parsed.host)
        } else {
            parsed.host
        };
        Ok(Self {
            client: HttpClient::new(),
            url: format!("{scheme}://{host}:{}", parsed.port),
            authorization: None,
        })
    }

    /// Set the complete proxy authorization field, such as `Basic ...`.
    ///
    /// The field is bounded to 16 KiB, validated as an HTTP header, and
    /// redacted from `Debug`. It is sent only to the selected proxy during
    /// CONNECT, including when the origin uses plaintext HTTP/2.
    pub fn with_authorization(mut self, value: impl Into<String>) -> Result<Self, Status> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 16 * 1024
            || validate_header_field("Proxy-Authorization", &value).is_err()
        {
            return Err(Status::invalid_argument(
                "invalid gRPC HTTP CONNECT proxy authorization",
            ));
        }
        self.authorization = Some(value);
        Ok(self)
    }

    /// Configure proxy-side DNS, TLS roots, user agent, and setup timeout.
    ///
    /// This uses [`HttpClient::connect_tunnel`], which opens the explicit
    /// endpoint without its connection pool, redirect/retry policy, cookie
    /// jar, default headers, or configured forwarding proxy. Origin TLS
    /// continues to use [`super::ChannelBuilder::tls_connector`].
    #[must_use]
    pub fn with_http_client(mut self, client: HttpClient) -> Self {
        self.client = client;
        self
    }

    pub(super) fn validate_channel(&self, uri: &str) -> Result<(), Status> {
        if channel_target_is_loopback(uri) || uri.starts_with("unix:") {
            return Err(Status::invalid_argument(
                "HTTP CONNECT proxies require a native TCP gRPC channel",
            ));
        }
        Ok(())
    }

    pub(crate) async fn connect(
        &self,
        cx: &Cx,
        target_authority: &str,
    ) -> Result<Box<HttpConnectTunnel<ClientIo>>, Status> {
        let headers = self.authorization.as_ref().map_or_else(Vec::new, |value| {
            vec![("Proxy-Authorization".to_owned(), value.clone())]
        });
        self.client
            .connect_tunnel(cx, &self.url, target_authority, headers)
            .await
            .map(Box::new)
            .map_err(|error| match error {
                ClientError::Cancelled => Status::cancelled("gRPC proxy setup cancelled"),
                ClientError::DeadlineExceeded => {
                    Status::deadline_exceeded("gRPC proxy setup deadline exceeded")
                }
                ClientError::ConnectTunnelRefused { status, .. } => Status::unavailable(format!(
                    "gRPC proxy refused CONNECT with HTTP status {status}"
                )),
                // Proxy-controlled reason phrases and transport errors may
                // contain credentials. Preserve the failure class only.
                ClientError::TlsError(_) => Status::unavailable("gRPC proxy TLS setup failed"),
                _ => Status::unavailable("gRPC proxy connection setup failed"),
            })
    }
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
