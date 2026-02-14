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

        TcpListener::from_std(listener)
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
        // ubs:ignore — TcpStream returned to caller; caller owns shutdown lifecycle
        TcpStream::connect(addr).await
    }
}

fn family_matches(family: TcpSocketFamily, addr: SocketAddr) -> bool {
    match family {
        TcpSocketFamily::V4 => addr.is_ipv4(),
        TcpSocketFamily::V6 => addr.is_ipv6(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_bind_family_match_v4() {
        init_test("test_bind_family_match_v4");
        let socket = TcpSocket::new_v4().expect("new_v4");
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let result = socket.bind(addr);
        crate::assert_with_log!(result.is_ok(), "bind v4", true, result.is_ok());
        crate::test_complete!("test_bind_family_match_v4");
    }

    #[test]
    fn test_bind_family_mismatch() {
        init_test("test_bind_family_mismatch");
        let socket = TcpSocket::new_v4().expect("new_v4");
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
        let err = socket.bind(addr).expect_err("expected mismatch error");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "bind mismatch kind",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::test_complete!("test_bind_family_mismatch");
    }

    #[test]
    fn test_listen_requires_bind() {
        init_test("test_listen_requires_bind");
        let socket = TcpSocket::new_v4().expect("new_v4");
        let err = socket.listen(128).expect_err("listen without bind");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "listen requires bind",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::test_complete!("test_listen_requires_bind");
    }

    #[test]
    fn test_listen_reuseaddr_unsupported() {
        init_test("test_listen_reuseaddr_unsupported");
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        socket.set_reuseaddr(true).expect("set_reuseaddr");
        let err = socket
            .listen(128)
            .expect_err("reuseaddr should be unsupported");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Unsupported,
            "reuseaddr unsupported",
            io::ErrorKind::Unsupported,
            err.kind()
        );
        crate::test_complete!("test_listen_reuseaddr_unsupported");
    }

    #[cfg(unix)]
    #[test]
    fn test_listen_reuseport_unsupported() {
        init_test("test_listen_reuseport_unsupported");
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        socket.set_reuseport(true).expect("set_reuseport");
        let err = socket
            .listen(128)
            .expect_err("reuseport should be unsupported");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::Unsupported,
            "reuseport unsupported",
            io::ErrorKind::Unsupported,
            err.kind()
        );
        crate::test_complete!("test_listen_reuseport_unsupported");
    }

    #[test]
    fn test_listen_success_v4() {
        init_test("test_listen_success_v4");
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        let listener = socket.listen(128).expect("listen");
        let local = listener.local_addr().expect("local_addr");
        crate::assert_with_log!(
            local.ip() == Ipv4Addr::LOCALHOST,
            "local addr ip",
            Ipv4Addr::LOCALHOST,
            local.ip()
        );
        crate::assert_with_log!(
            local.port() != 0,
            "local port assigned",
            true,
            local.port() != 0
        );
        crate::test_complete!("test_listen_success_v4");
    }

    #[test]
    fn test_connect_rejects_configuration() {
        init_test("test_connect_rejects_configuration");
        futures_lite::future::block_on(async {
            let socket = TcpSocket::new_v4().expect("new_v4");
            socket
                .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("bind");
            let err = socket
                .connect(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)))
                .await
                .expect_err("connect should reject bound socket");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::Unsupported,
                "connect configuration rejected",
                io::ErrorKind::Unsupported,
                err.kind()
            );
        });
        crate::test_complete!("test_connect_rejects_configuration");
    }

    #[test]
    fn test_connect_family_mismatch() {
        init_test("test_connect_family_mismatch");
        futures_lite::future::block_on(async {
            let socket = TcpSocket::new_v4().expect("new_v4");
            let err = socket
                .connect(SocketAddr::from((Ipv6Addr::LOCALHOST, 80)))
                .await
                .expect_err("connect should reject IPv6");
            crate::assert_with_log!(
                err.kind() == io::ErrorKind::InvalidInput,
                "connect family mismatch",
                io::ErrorKind::InvalidInput,
                err.kind()
            );
        });
        crate::test_complete!("test_connect_family_mismatch");
    }

    #[test]
    fn test_connect_success_v4() {
        init_test("test_connect_success_v4");
        let listener = net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = listener.accept().expect("accept");
            let _ = tx.send(());
        });

        futures_lite::future::block_on(async {
            let stream = TcpSocket::new_v4().expect("new_v4").connect(addr).await;
            crate::assert_with_log!(stream.is_ok(), "connect ok", true, stream.is_ok());
            if let Ok(stream) = stream {
                let peer = stream.peer_addr().expect("peer addr");
                crate::assert_with_log!(peer.ip() == addr.ip(), "peer ip", addr.ip(), peer.ip());
            }
        });

        let accepted = rx.recv_timeout(Duration::from_secs(1)).is_ok();
        crate::assert_with_log!(accepted, "accepted connection", true, accepted);
        handle.join().expect("join accept thread");
        crate::test_complete!("test_connect_success_v4");
    }
}
