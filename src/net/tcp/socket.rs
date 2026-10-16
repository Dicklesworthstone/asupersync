//! TCP socket configuration.
//!
//! Socket options are opt-in per handle: unset options defer to operating-system
//! defaults, while explicit keepalive `None` disables probes without relying on
//! ambient process-wide state.

use crate::net::tcp::listener::TcpListener;
use crate::net::tcp::stream::{KeepaliveConfig, TcpKeepaliveConfig, TcpStream};
use parking_lot::Mutex;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

/// A TCP socket used for configuring options before connect/listen.
#[derive(Debug)]
pub struct TcpSocket {
    state: Mutex<TcpSocketState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpSocketFamily {
    V4,
    V6,
}

#[derive(Debug)]
struct TcpSocketState {
    family: TcpSocketFamily,
    bound: Option<SocketAddr>,
    reuseaddr: bool,
    nodelay: Option<bool>,
    keepalive: KeepaliveConfig,
    /// `TCP_USER_TIMEOUT`; `None` leaves the kernel default.
    user_timeout: Option<Duration>,
    #[cfg(unix)]
    reuseport: bool,
}

impl TcpSocket {
    /// Creates a new IPv4 TCP socket.
    #[inline]
    pub fn new_v4() -> io::Result<Self> {
        Ok(Self {
            state: Mutex::new(TcpSocketState {
                family: TcpSocketFamily::V4,
                bound: None,
                reuseaddr: false,
                nodelay: None,
                keepalive: KeepaliveConfig::Default,
                user_timeout: None,
                #[cfg(unix)]
                reuseport: false,
            }),
        })
    }

    /// Creates a new IPv6 TCP socket.
    #[inline]
    pub fn new_v6() -> io::Result<Self> {
        Ok(Self {
            state: Mutex::new(TcpSocketState {
                family: TcpSocketFamily::V6,
                bound: None,
                reuseaddr: false,
                nodelay: None,
                keepalive: KeepaliveConfig::Default,
                user_timeout: None,
                #[cfg(unix)]
                reuseport: false,
            }),
        })
    }

    /// Sets the SO_REUSEADDR option on this socket.
    pub fn set_reuseaddr(&self, reuseaddr: bool) -> io::Result<()> {
        self.state.lock().reuseaddr = reuseaddr;
        Ok(())
    }

    /// Enables or disables TCP_NODELAY for sockets created from this handle.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.state.lock().nodelay = Some(nodelay);
        Ok(())
    }

    /// Configures TCP keepalive for sockets created from this handle.
    ///
    /// Pass `Some(duration)` to enable keepalive with the requested idle time,
    /// or `None` to explicitly disable keepalive.
    pub fn set_keepalive(&self, keepalive: Option<Duration>) -> io::Result<()> {
        self.set_keepalive_config(keepalive.map(TcpKeepaliveConfig::new))
    }

    /// Configures TCP keepalive with explicit idle, interval, and retry parameters.
    ///
    /// Defaults are explicit: `None` disables keepalive, while leaving this
    /// unset defers to the operating system. Unsupported interval or retry
    /// parameters return `io::ErrorKind::Unsupported` when the socket is
    /// connected or listened.
    pub fn set_keepalive_config(&self, keepalive: Option<TcpKeepaliveConfig>) -> io::Result<()> {
        self.state.lock().keepalive =
            keepalive.map_or(KeepaliveConfig::Disabled, KeepaliveConfig::Enabled);
        Ok(())
    }

    /// Sets `TCP_USER_TIMEOUT` for the stream or listener created from this
    /// handle; see [`TcpStream::set_user_timeout`]. It is applied at
    /// `connect` or `listen`, and streams accepted from the listener inherit
    /// it. `None` leaves the kernel default.
    ///
    /// # Errors
    ///
    /// `io::ErrorKind::Unsupported` on platforms without the option (it exists
    /// on Linux, Android, Fuchsia and Cygwin).
    pub fn set_user_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        super::user_timeout::check_supported("TcpSocket::set_user_timeout")?;
        self.state.lock().user_timeout = timeout;
        Ok(())
    }

    /// Sets the SO_REUSEPORT option on this socket (Unix only).
    #[cfg(unix)]
    pub fn set_reuseport(&self, reuseport: bool) -> io::Result<()> {
        self.state.lock().reuseport = reuseport;
        Ok(())
    }

    /// Binds this socket to the given local address.
    ///
    /// The address is recorded here. The operating-system socket is created
    /// and bound by [`Self::listen`] or [`Self::connect`], so an OS bind error
    /// such as an address already in use is returned by that call, not by
    /// this one.
    ///
    /// # Errors
    ///
    /// `io::ErrorKind::InvalidInput` when the address family does not match
    /// the socket's, or when the socket already has an address.
    pub fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        {
            let mut state = self.state.lock();
            if !family_matches(state.family, addr) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "address family does not match socket",
                ));
            }
            if state.bound.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "socket is already bound",
                ));
            }
            state.bound = Some(addr);
        }
        Ok(())
    }

    /// Starts listening, returning a TCP listener.
    ///
    /// Refuses with [`IoCapabilityDenied`](crate::cx::IoCapabilityDenied)
    /// when the calling task's `Cx` lacks the IO capability.
    pub fn listen(self, backlog: u32) -> io::Result<TcpListener> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = self;
            let _ = backlog;
            Err(super::browser_tcp_unsupported("TcpSocket::listen"))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::cx::io_gate::require_ambient_io("net::TcpSocket::listen")?;
            let state = self.state.into_inner();
            let addr = state.bound.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "socket is not bound")
            })?;

            let domain = match state.family {
                TcpSocketFamily::V4 => socket2::Domain::IPV4,
                TcpSocketFamily::V6 => socket2::Domain::IPV6,
            };
            let socket =
                socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;

            if state.reuseaddr {
                socket.set_reuse_address(true)?;
            }

            #[cfg(unix)]
            if state.reuseport {
                socket.set_reuse_port(true)?;
            }

            apply_socket_options(&socket, &state)?;
            socket.bind(&socket2::SockAddr::from(addr))?;
            socket.listen(i32::try_from(backlog).unwrap_or(i32::MAX))?;
            socket.set_nonblocking(true)?;

            TcpListener::from_std(socket.into())
        }
    }

    /// Connects this socket, returning a TCP stream.
    ///
    /// Refuses with [`IoCapabilityDenied`](crate::cx::IoCapabilityDenied)
    /// when the calling task's `Cx` lacks the IO capability.
    pub async fn connect(self, addr: SocketAddr) -> io::Result<TcpStream> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = self;
            let _ = addr;
            Err(super::browser_tcp_unsupported("TcpSocket::connect"))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            crate::cx::io_gate::require_ambient_io("net::TcpSocket::connect")?;
            let state = self.state.into_inner();

            if !family_matches(state.family, addr) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "address family does not match socket",
                ));
            }

            let domain = match state.family {
                TcpSocketFamily::V4 => socket2::Domain::IPV4,
                TcpSocketFamily::V6 => socket2::Domain::IPV6,
            };
            let socket =
                socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;

            if state.reuseaddr {
                socket.set_reuse_address(true)?;
            }

            #[cfg(unix)]
            if state.reuseport {
                socket.set_reuse_port(true)?;
            }

            apply_socket_options(&socket, &state)?;
            if let Some(bound) = state.bound {
                socket.bind(&socket2::SockAddr::from(bound))?;
            }

            // Async connect using the configured socket
            TcpStream::connect_from_socket(socket, addr).await
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn apply_socket_options(socket: &socket2::Socket, state: &TcpSocketState) -> io::Result<()> {
    if let Some(nodelay) = state.nodelay {
        socket.set_tcp_nodelay(nodelay)?;
    }

    match state.keepalive {
        KeepaliveConfig::Enabled(config) => {
            let params = config.to_socket2()?;
            socket.set_tcp_keepalive(&params)?;
        }
        KeepaliveConfig::Disabled => socket.set_keepalive(false)?,
        KeepaliveConfig::Default => {}
    }

    if let Some(timeout) = state.user_timeout {
        super::user_timeout::set_socket_user_timeout(socket, Some(timeout))?;
    }

    Ok(())
}

fn family_matches(family: TcpSocketFamily, addr: SocketAddr) -> bool {
    match family {
        TcpSocketFamily::V4 => addr.is_ipv4(),
        TcpSocketFamily::V6 => addr.is_ipv6(),
    }
}

#[cfg(test)]
#[path = "socket_inline_tests.rs"]
mod tests;
