//! Explicit HTTP CONNECT routes for native WebSocket connections.

use super::{
    Cx, HandshakeError, WebSocket, WebSocketConnectOptions, WsConnectError, WsConnectSetup, WsUrl,
    connect_options, missing_connect_setup_authority, perform_client_handshake,
};
#[cfg(feature = "tls")]
use super::{TlsConnector, TlsStream, map_tls_connect_error};
use crate::http::h1::http_client::{
    ClientError, ClientIo, HttpClient, HttpConnectTunnel, ParsedUrl, Scheme,
};
use std::fmt;
use std::io;
use std::net::Ipv6Addr;

/// An explicit HTTP or HTTPS CONNECT proxy for native WebSocket setup.
///
/// Use [`WebSocket::connect_via_proxy`] for `ws://`, or
/// `WebSocket::connect_tls_via_proxy` with `tls` enabled for `wss://`.
/// The proxy connects to the URL's origin; the client resolves only the proxy.
/// Each call owns one fresh tunnel. Refusals and redirects end setup without
/// following another route or falling back to a direct origin connection.
///
/// Proxy credentials belong in [`Self::with_authorization`]. Origin headers
/// belong in [`WebSocketConnectOptions`] and are sent only after CONNECT
/// succeeds, and after origin TLS succeeds for `wss://`. The supplied HTTP
/// client's cookies and default headers are not included in CONNECT.
///
/// HTTPS proxy trust is configured through [`Self::with_http_client`]. WSS
/// origin trust is configured separately through the connection method's TLS
/// connector. Debug output contains no endpoints, credentials, or HTTP client
/// configuration. No runtime, thread, or background connection driver is
/// created by this configuration.
///
/// ```no_run
/// use asupersync::net::websocket::{
///     WebSocket, WebSocketConnectOptions, WebSocketHttpProxy,
/// };
/// # async fn example(cx: &asupersync::Cx) -> Result<(), Box<dyn std::error::Error>> {
/// let proxy = WebSocketHttpProxy::new("http://proxy.example:3128")?
///     .with_authorization("Bearer proxy-access-token")?;
/// let options = WebSocketConnectOptions::default()
///     .try_header("Origin", "https://app.example")?;
/// let socket = WebSocket::connect_via_proxy(
///     cx, "ws://service.example/events", options, &proxy,
/// ).await?;
/// # drop(socket);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct WebSocketHttpProxy {
    client: HttpClient,
    url: String,
    authorization: Option<String>,
}

impl fmt::Debug for WebSocketHttpProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketHttpProxy")
            .field("tls", &self.url.starts_with("https://"))
            .field("authorization_configured", &self.authorization.is_some())
            .finish_non_exhaustive()
    }
}

impl WebSocketHttpProxy {
    /// Maximum bytes in a supplied proxy endpoint URL, checked before copying.
    pub const MAX_URL_BYTES: usize = 2048;
    /// Maximum bytes in the complete `Proxy-Authorization` value.
    pub const MAX_AUTHORIZATION_BYTES: usize = 16 * 1024;

    /// Validate an HTTP(S) proxy endpoint without performing I/O.
    ///
    /// Only an endpoint with an optional root slash is accepted. Userinfo,
    /// query strings, fragments, non-root paths, port zero, malformed IPv6,
    /// and control characters are refused. DNS names must use ASCII; encode
    /// internationalized names as punycode. Credentials are configured
    /// separately. HTTPS requires the `tls` feature.
    pub fn new(url: impl AsRef<str>) -> Result<Self, WsConnectError> {
        let url = url.as_ref();
        if url.is_empty()
            || url.len() > Self::MAX_URL_BYTES
            || url.contains(['?', '#', '@'])
            || url.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
        {
            return Err(invalid_proxy_url());
        }
        let parsed = ParsedUrl::parse(url).map_err(|_| invalid_proxy_url())?;
        if parsed.path != "/" || parsed.port == 0 {
            return Err(invalid_proxy_url());
        }
        let host = if parsed.host.starts_with('[') {
            let address = parsed
                .host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .and_then(|host| host.parse::<Ipv6Addr>().ok())
                .ok_or_else(invalid_proxy_url)?;
            format!("[{address}]")
        } else if parsed.host.contains(':') {
            let address = parsed
                .host
                .parse::<Ipv6Addr>()
                .map_err(|_| invalid_proxy_url())?;
            format!("[{address}]")
        } else {
            if !parsed
                .host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            {
                return Err(invalid_proxy_url());
            }
            parsed.host.to_ascii_lowercase()
        };
        #[cfg(not(feature = "tls"))]
        if parsed.scheme == Scheme::Https {
            return Err(WsConnectError::TlsRequired);
        }
        let scheme = match parsed.scheme {
            Scheme::Http => "http",
            Scheme::Https => "https",
        };
        Ok(Self {
            client: HttpClient::new(),
            url: format!("{scheme}://{host}:{}", parsed.port),
            authorization: None,
        })
    }

    /// Set the complete proxy authorization field, such as `Basic ...`.
    ///
    /// The value must be nonblank visible ASCII with optional horizontal tabs
    /// and must fit [`Self::MAX_AUTHORIZATION_BYTES`]. Validation precedes
    /// allocation. Repeated calls replace the prior value; exactly one field
    /// is sent, only to the selected proxy during CONNECT. Errors never include
    /// the rejected value.
    pub fn with_authorization(mut self, value: impl AsRef<str>) -> Result<Self, WsConnectError> {
        let value = value.as_ref();
        if value.trim().is_empty()
            || value.len() > Self::MAX_AUTHORIZATION_BYTES
            || !value
                .bytes()
                .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
        {
            return Err(WsConnectError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid WebSocket proxy authorization",
            )));
        }
        self.authorization = Some(value.to_owned());
        Ok(self)
    }

    /// Supply the HTTP client's proxy-side DNS, TLS roots, and setup limits.
    ///
    /// Its user agent is included in CONNECT. Its cookies, default headers,
    /// configured forwarding proxy, pool, redirects, and retries are unused.
    /// Its request timeout can tighten CONNECT setup but cannot extend the
    /// WebSocket's whole-setup deadline. Origin TLS still uses the explicit
    /// connector supplied to `WebSocket::connect_tls_via_proxy`.
    ///
    /// TCP socket behavior belongs to this HTTP transport. In particular,
    /// `WebSocketConfig::nodelay` applies only to the direct TCP entry points.
    #[must_use]
    pub fn with_http_client(mut self, client: HttpClient) -> Self {
        self.client = client;
        self
    }

    async fn connect(
        &self,
        cx: &Cx,
        target: &str,
    ) -> Result<HttpConnectTunnel<ClientIo>, WsConnectError> {
        let headers = self.authorization.as_ref().map_or_else(Vec::new, |value| {
            vec![("Proxy-Authorization".to_owned(), value.clone())]
        });
        self.client
            .connect_tunnel(cx, &self.url, target, headers)
            .await
            .map_err(map_proxy_error)
    }
}

impl WebSocket<HttpConnectTunnel<ClientIo>> {
    /// Connect to `ws://` through an explicit HTTP(S) CONNECT proxy.
    ///
    /// One `connect_timeout` budget covers proxy DNS/TCP/TLS, CONNECT, and
    /// the WebSocket upgrade, tightened by caller and ambient deadlines.
    /// The explicit and ambient contexts must have I/O and timer authority on
    /// the same native clock. Cancellation wakes every parked setup phase;
    /// dropping setup closes any acquired tunnel. No background task is spawned.
    /// Successful setup releases this deadline; subsequent messages use their
    /// supplied contexts and the existing WebSocket configuration.
    /// A resolver call already executing off-thread may finish after its
    /// cancelled wait. Proxy TCP options belong to the HTTP transport;
    /// `WebSocketConfig::nodelay` applies only to direct TCP connection methods.
    ///
    /// Origin headers and negotiated compression use [`WebSocketConnectOptions`].
    /// Proxy credentials come only from [`WebSocketHttpProxy`]. Redirects and
    /// refusals never trigger another route or a direct connection. A proxy
    /// refusal preserves its HTTP status as [`HandshakeError::Rejected`]. All
    /// other peer-controlled error text is redacted. For `wss://`, use
    /// `WebSocket::connect_tls_via_proxy` with the `tls` feature instead.
    pub async fn connect_via_proxy(
        cx: &Cx,
        url: &str,
        options: WebSocketConnectOptions,
        proxy: &WebSocketHttpProxy,
    ) -> Result<Self, WsConnectError> {
        let connect = async {
            let (parsed, target) = proxy_origin(url, false)?;
            let (config, headers, compression) = options.into_parts();
            let ambient = Cx::current().ok_or_else(missing_connect_setup_authority)?;
            let mut setup = WsConnectSetup::new(cx, &ambient, config.connect_timeout)?;
            let tunnel = setup.run(proxy.connect(cx, &target)).await?;
            setup
                .run(perform_client_handshake(
                    cx,
                    tunnel,
                    &parsed,
                    &config,
                    compression,
                    None,
                    &headers,
                ))
                .await
        };
        connect.await.map_err(connect_options::redact_connect_error)
    }
}

#[cfg(feature = "tls")]
impl WebSocket<TlsStream<HttpConnectTunnel<ClientIo>>> {
    /// Connect to `wss://` through an explicit HTTP(S) CONNECT proxy.
    ///
    /// `connector` authenticates the origin hostname or IP and must enable SNI
    /// for DNS names. Offer `http/1.1` ALPN or none; a different negotiated
    /// protocol is refused before any origin upgrade headers are written.
    /// HTTPS proxy trust is independently configured on [`WebSocketHttpProxy`].
    ///
    /// The single setup budget, explicit cancellation, tunnel ownership, and
    /// redacted errors match [`WebSocket::connect_via_proxy`]. It also covers
    /// origin TLS, without resetting the budget after CONNECT. Proxy credentials
    /// are never included in the encrypted origin upgrade. `ws://` is refused
    /// before dialing; setup never falls back to plaintext or a direct route.
    pub async fn connect_tls_via_proxy(
        cx: &Cx,
        url: &str,
        options: WebSocketConnectOptions,
        proxy: &WebSocketHttpProxy,
        connector: &TlsConnector,
    ) -> Result<Self, WsConnectError> {
        let connect = async {
            let (parsed, target) = proxy_origin(url, true)?;
            TlsConnector::validate_domain(&parsed.host).map_err(map_tls_connect_error)?;
            if parsed.host.parse::<std::net::IpAddr>().is_err() && !connector.config().enable_sni {
                return Err(WsConnectError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "secure WebSocket DNS connections require TLS SNI",
                )));
            }
            let (config, headers, compression) = options.into_parts();
            let ambient = Cx::current().ok_or_else(missing_connect_setup_authority)?;
            let mut setup = WsConnectSetup::new(cx, &ambient, config.connect_timeout)?;
            let tunnel = setup.run(proxy.connect(cx, &target)).await?;
            let tls = setup
                .run(async {
                    connector
                        .connect(&parsed.host, tunnel)
                        .await
                        .map_err(map_tls_connect_error)
                })
                .await?;
            if tls
                .alpn_protocol()
                .is_some_and(|protocol| protocol != b"http/1.1")
            {
                return Err(WsConnectError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "secure WebSocket peer negotiated a protocol other than HTTP/1.1",
                )));
            }
            setup
                .run(perform_client_handshake(
                    cx,
                    tls,
                    &parsed,
                    &config,
                    compression,
                    None,
                    &headers,
                ))
                .await
        };
        connect.await.map_err(connect_options::redact_connect_error)
    }
}

fn invalid_proxy_url() -> WsConnectError {
    WsConnectError::InvalidUrl(HandshakeError::InvalidUrl(
        "invalid WebSocket HTTP CONNECT proxy endpoint".into(),
    ))
}

fn proxy_origin(url: &str, tls: bool) -> Result<(WsUrl, String), WsConnectError> {
    let parsed = WsUrl::parse(url).map_err(WsConnectError::InvalidUrl)?;
    if parsed.tls != tls {
        return Err(if parsed.tls {
            WsConnectError::TlsRequired
        } else {
            WsConnectError::InvalidUrl(HandshakeError::InvalidUrl(
                "connect_tls_via_proxy requires a wss:// URL".into(),
            ))
        });
    }
    if parsed.port == 0 {
        return Err(WsConnectError::InvalidUrl(HandshakeError::InvalidUrl(
            "WebSocket CONNECT target requires a nonzero port".into(),
        )));
    }
    // CONNECT authority-form always includes the port, even for ws:80/wss:443.
    let target = if parsed.host.contains(':') {
        let address = parsed.host.parse::<Ipv6Addr>().map_err(|_| {
            WsConnectError::InvalidUrl(HandshakeError::InvalidUrl(
                "invalid WebSocket CONNECT IPv6 target".into(),
            ))
        })?;
        format!("[{address}]:{}", parsed.port)
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };
    Ok((parsed, target))
}

fn map_proxy_error(error: ClientError) -> WsConnectError {
    match error {
        ClientError::Cancelled => WsConnectError::Cancelled,
        ClientError::DeadlineExceeded => WsConnectError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "WebSocket proxy setup deadline exceeded",
        )),
        ClientError::ConnectTunnelRefused { status, .. } => {
            WsConnectError::Handshake(HandshakeError::Rejected {
                status,
                reason: "<redacted>".into(),
            })
        }
        ClientError::Io(error)
        | ClientError::DnsError(error)
        | ClientError::ConnectError(error) => WsConnectError::Io(io::Error::new(
            error.kind(),
            "WebSocket proxy connection failed (details redacted)",
        )),
        ClientError::TlsError(_) | ClientError::HttpError(_) => WsConnectError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "WebSocket proxy negotiation failed (details redacted)",
        )),
        _ => WsConnectError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "WebSocket proxy configuration failed (details redacted)",
        )),
    }
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
