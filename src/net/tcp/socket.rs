//! TCP socket configuration.

use crate::net::tcp::listener::TcpListener;
use crate::net::tcp::stream::TcpStream;
use parking_lot::Mutex;
use std::io;
use std::net::SocketAddr;

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
        self.state.lock().reuseaddr = reuseaddr;
        Ok(())
    }

    /// Sets the SO_REUSEPORT option on this socket (Unix only).
    #[cfg(unix)]
    pub fn set_reuseport(&self, reuseport: bool) -> io::Result<()> {
        self.state.lock().reuseport = reuseport;
        Ok(())
    }

    /// Binds this socket to the given local address.
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
    pub fn listen(self, backlog: u32) -> io::Result<TcpListener> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = self;
            let _ = backlog;
            Err(super::browser_tcp_unsupported("TcpSocket::listen"))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
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

            socket.bind(&socket2::SockAddr::from(addr))?;
            socket.listen(i32::try_from(backlog).unwrap_or(i32::MAX))?;
            socket.set_nonblocking(true)?;

            TcpListener::from_std(socket.into())
        }
    }

    /// Connects this socket, returning a TCP stream.
    pub async fn connect(self, addr: SocketAddr) -> io::Result<TcpStream> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = self;
            let _ = addr;
            Err(super::browser_tcp_unsupported("TcpSocket::connect"))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
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

            if let Some(bound) = state.bound {
                socket.bind(&socket2::SockAddr::from(bound))?;
            }

            // Async connect using the configured socket
            TcpStream::connect_from_socket(socket, addr).await
        }
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
    use std::net::{self, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    fn test_bind_rejects_rebind_and_preserves_original_local_identity() {
        init_test("test_bind_rejects_rebind_and_preserves_original_local_identity");
        let socket = TcpSocket::new_v4().expect("new_v4");
        let first = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let second = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

        socket.bind(first).expect("first bind");
        let err = socket.bind(second).expect_err("second bind should fail");
        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "rebind rejected",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::assert_with_log!(
            socket.state.lock().bound == Some(first),
            "first bind preserved in socket state",
            Some(first),
            socket.state.lock().bound
        );

        let listener = socket.listen(128).expect("listen after rejected rebind");
        let local = listener.local_addr().expect("listener local_addr");
        crate::assert_with_log!(
            local.ip() == first.ip(),
            "listen uses original local identity",
            first.ip(),
            local.ip()
        );
        crate::test_complete!("test_bind_rejects_rebind_and_preserves_original_local_identity");
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
    fn test_listen_with_reuseaddr() {
        init_test("test_listen_with_reuseaddr");
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        socket.set_reuseaddr(true).expect("set_reuseaddr");
        let listener = socket
            .listen(128)
            .expect("listen with reuseaddr should succeed");
        let addr = listener.local_addr().expect("local_addr");
        crate::assert_with_log!(addr.port() > 0, "bound port", true, addr.port() > 0);
        crate::test_complete!("test_listen_with_reuseaddr");
    }

    #[cfg(unix)]
    #[test]
    fn test_listen_with_reuseport() {
        init_test("test_listen_with_reuseport");
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        socket.set_reuseport(true).expect("set_reuseport");
        let listener = socket
            .listen(128)
            .expect("listen with reuseport should succeed");
        let addr = listener.local_addr().expect("local_addr");
        crate::assert_with_log!(addr.port() > 0, "bound port", true, addr.port() > 0);
        crate::test_complete!("test_listen_with_reuseport");
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
    fn test_connect_with_bind_success() {
        init_test("test_connect_with_bind_success");
        let listener = net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind listener");
        let listen_addr = listener.local_addr().expect("local addr");
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = listener.accept().expect("accept");
            let _ = tx.send(());
        });

        futures_lite::future::block_on(async {
            let socket = TcpSocket::new_v4().expect("new_v4");
            // Bind to an ephemeral port
            socket
                .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("bind");

            let stream = socket.connect(listen_addr).await;
            crate::assert_with_log!(stream.is_ok(), "connect with bind ok", true, stream.is_ok());

            if let Ok(stream) = stream {
                let local = stream.local_addr().expect("local addr");
                // Verify we are indeed bound to local loopback (port will be non-zero)
                crate::assert_with_log!(
                    local.ip() == Ipv4Addr::LOCALHOST,
                    "local ip",
                    Ipv4Addr::LOCALHOST,
                    local.ip()
                );
            }
        });

        let accepted = rx.recv_timeout(Duration::from_secs(1)).is_ok();
        crate::assert_with_log!(accepted, "accepted connection", true, accepted);
        handle.join().expect("join accept thread");
        crate::test_complete!("test_connect_with_bind_success");
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

    #[test]
    fn test_listen_reuseaddr() {
        init_test("test_listen_reuseaddr");
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket.set_reuseaddr(true).expect("set_reuseaddr");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        let listener = socket.listen(128);
        crate::assert_with_log!(listener.is_ok(), "listen ok", true, listener.is_ok());
        crate::test_complete!("test_listen_reuseaddr");
    }
}
