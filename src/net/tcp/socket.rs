//! TCP socket configuration.

use crate::net::tcp::listener::TcpListener;
use crate::net::tcp::stream::TcpStream;
use std::io;
use std::net::{self, SocketAddr};
use std::sync::Mutex;

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
    reuseport: bool,
}

impl TcpSocket {
    /// Creates a new IPv4 TCP socket.
    pub fn new_v4() -> io::Result<Self> {
        Ok(Self {
            state: Mutex::new(TcpSocketState {
                family: TcpSocketFamily::V4,
                bound: None,
                reuseaddr: false,
                reuseport: false,
            }),
        })
    }

    /// Creates a new IPv6 TCP socket.
    pub fn new_v6() -> io::Result<Self> {
        Ok(Self {
            state: Mutex::new(TcpSocketState {
                family: TcpSocketFamily::V6,
                bound: None,
                reuseaddr: false,
                reuseport: false,
            }),
        })
    }

    /// Sets the SO_REUSEADDR option on this socket.
    pub fn set_reuseaddr(&self, reuseaddr: bool) -> io::Result<()> {
        self.state
            .lock()
            .expect("tcp socket lock poisoned")
            .reuseaddr = reuseaddr;
        Ok(())
    }

    /// Sets the SO_REUSEPORT option on this socket (Unix only).
    #[cfg(unix)]
    pub fn set_reuseport(&self, reuseport: bool) -> io::Result<()> {
        self.state
            .lock()
            .expect("tcp socket lock poisoned")
            .reuseport = reuseport;
        Ok(())
    }

    /// Binds this socket to the given local address.
    pub fn bind(&self, addr: SocketAddr) -> io::Result<()> {
        {
            let mut state = self.state.lock().expect("tcp socket lock poisoned");
            if !family_matches(state.family, addr) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "address family does not match socket",
                ));
            }
            state.bound = Some(addr);
        }
        Ok(())
    }

    /// Starts listening, returning a TCP listener.
    pub fn listen(self, _backlog: u32) -> io::Result<TcpListener> {
        let state = self
            .state
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.reuseaddr || state.reuseport {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "SO_REUSEADDR/SO_REUSEPORT not supported in Phase 0",
            ));
        }
        let addr = state
            .bound
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket is not bound"))?;

        // Use blocking bind for Phase 0
        // We can't use async bind here because this method is synchronous.
        // We can construct TcpListener using std::net::TcpListener directly.
        // But TcpListener struct expects it.
        // We'll construct TcpListener directly.
        // But `TcpListener` field `inner` is private.
        // So we need to use `TcpListener::bind`? But that's async.
        // Or make `inner` pub(crate).
        // I will update `listener.rs` to make `inner` pub(crate) if needed, or assume I can access it if in same module tree.
        // They are in `net::tcp`.
        // So `crate::net::tcp::listener::TcpListener` field `inner` needs to be accessible?
        // No, `TcpSocket` is in `socket.rs`. `TcpListener` in `listener.rs`.
        // They are siblings.
        // So `inner` needs to be `pub(crate)`.

        let listener = net::TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;

        Ok(TcpListener::from_std(listener))
    }

    /// Connects this socket, returning a TCP stream.
    pub async fn connect(self, addr: SocketAddr) -> io::Result<TcpStream> {
        let state = self
            .state
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.bound.is_some() || state.reuseaddr || state.reuseport {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TcpSocket configuration before connect is not supported in Phase 0",
            ));
        }
        if !family_matches(state.family, addr) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "address family does not match socket",
            ));
        }

        // Async connect using TcpStream::connect
        TcpStream::connect(addr).await
    }
}

fn family_matches(family: TcpSocketFamily, addr: SocketAddr) -> bool {
    match family {
        TcpSocketFamily::V4 => addr.is_ipv4(),
        TcpSocketFamily::V6 => addr.is_ipv6(),
    }
}
