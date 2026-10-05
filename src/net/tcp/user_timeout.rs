//! `TCP_USER_TIMEOUT`: how long transmitted data may stay unacknowledged
//! before the kernel aborts the connection.
//!
//! Keepalive does not cover a peer that stops acknowledging while data is in
//! flight: Linux sends no keepalive probes then, and the connection is
//! reported dead only at the retransmission limit (`tcp_retries2`, 15 minutes
//! or more). This option bounds that wait.

use super::stream::TcpStream;
use std::io;
use std::time::Duration;

impl TcpStream {
    /// Sets `TCP_USER_TIMEOUT`: the kernel aborts the connection when data
    /// it transmitted stays unacknowledged, or data it buffered stays
    /// untransmitted, for this long.
    ///
    /// The abort surfaces from the next read or write as
    /// `io::ErrorKind::TimedOut`, or as a soft error already pending on the
    /// socket (such as `HostUnreachable`). `None` or a zero duration restores
    /// the kernel default. The value has millisecond resolution and is clamped
    /// to `u32::MAX` milliseconds. Unlike a connect timeout, it bounds an
    /// established connection; it does not replace read deadlines or
    /// cancellation.
    ///
    /// # Errors
    ///
    /// `io::ErrorKind::Unsupported` on platforms without the option (it exists
    /// on Linux, Android, Fuchsia and Cygwin); the socket is left unchanged.
    pub fn set_user_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = timeout;
            Err(unsupported("TcpStream::set_user_timeout"))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let stream = self
                .try_as_std()
                .ok_or_else(|| unsupported("TcpStream::set_user_timeout"))?;
            set_socket_user_timeout(&socket2::SockRef::from(stream), timeout)
        }
    }

    /// Returns the `TCP_USER_TIMEOUT` value, or `None` for the kernel default.
    ///
    /// # Errors
    ///
    /// `io::ErrorKind::Unsupported` on platforms without the option.
    pub fn user_timeout(&self) -> io::Result<Option<Duration>> {
        #[cfg(target_arch = "wasm32")]
        {
            Err(unsupported("TcpStream::user_timeout"))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let stream = self
                .try_as_std()
                .ok_or_else(|| unsupported("TcpStream::user_timeout"))?;
            socket_user_timeout(&socket2::SockRef::from(stream))
        }
    }
}

const SUPPORTED: bool = cfg!(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "cygwin",
));

fn unsupported(op: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{op}: TCP_USER_TIMEOUT is unsupported on this platform"),
    )
}

/// Refuses on platforms without `TCP_USER_TIMEOUT`, so a `TcpSocket` setter
/// fails when called rather than at connect or listen.
pub(super) fn check_supported(op: &str) -> io::Result<()> {
    if SUPPORTED {
        Ok(())
    } else {
        Err(unsupported(op))
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn set_socket_user_timeout(
    socket: &socket2::Socket,
    timeout: Option<Duration>,
) -> io::Result<()> {
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    ))]
    {
        socket.set_tcp_user_timeout(timeout)
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    )))]
    {
        let _ = (socket, timeout);
        Err(unsupported("set_user_timeout"))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn socket_user_timeout(socket: &socket2::Socket) -> io::Result<Option<Duration>> {
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    ))]
    {
        socket.tcp_user_timeout()
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    )))]
    {
        let _ = socket;
        Err(unsupported("user_timeout"))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::net::tcp::socket::TcpSocket;
    use std::net::{Ipv4Addr, SocketAddr};

    fn connected_stream(socket: TcpSocket) -> (TcpStream, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let accept = std::thread::spawn(move || listener.accept().expect("accept").0);
        let stream = futures_lite::future::block_on(socket.connect(addr)).expect("connect");
        (stream, accept.join().expect("accept thread"))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn set_user_timeout_reads_back_and_none_restores_the_default() {
        let (stream, _peer) = connected_stream(TcpSocket::new_v4().expect("new_v4"));
        assert_eq!(stream.user_timeout().expect("read default"), None);

        stream
            .set_user_timeout(Some(Duration::from_secs(10)))
            .expect("set 10 s");
        assert_eq!(
            stream.user_timeout().expect("read back"),
            Some(Duration::from_secs(10))
        );
        let raw = socket2::SockRef::from(stream.try_as_std().expect("std stream"))
            .tcp_user_timeout()
            .expect("getsockopt TCP_USER_TIMEOUT");
        assert_eq!(raw, Some(Duration::from_millis(10_000)));

        stream.set_user_timeout(None).expect("restore default");
        assert_eq!(stream.user_timeout().expect("read default again"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_user_timeout_is_applied_at_connect() {
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .set_user_timeout(Some(Duration::from_millis(2500)))
            .expect("set on socket");
        let (stream, _peer) = connected_stream(socket);
        assert_eq!(
            stream.user_timeout().expect("read back"),
            Some(Duration::from_millis(2500))
        );
    }

    /// tcp(7): an accepted socket inherits the listener's TCP_USER_TIMEOUT.
    #[cfg(target_os = "linux")]
    #[test]
    fn listener_user_timeout_is_inherited_by_accepted_streams() {
        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        socket
            .set_user_timeout(Some(Duration::from_secs(7)))
            .expect("set on listener socket");
        let listener = socket.listen(16).expect("listen");
        let addr = listener.local_addr().expect("local addr");
        let client = std::thread::spawn(move || std::net::TcpStream::connect(addr));
        let (accepted, _) = futures_lite::future::block_on(listener.accept()).expect("accept");
        let _client = client.join().expect("client thread").expect("connect");
        assert_eq!(
            accepted.user_timeout().expect("read back"),
            Some(Duration::from_secs(7))
        );
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "cygwin",
    )))]
    #[test]
    fn user_timeout_is_unsupported_elsewhere() {
        let socket = TcpSocket::new_v4().expect("new_v4");
        let err = socket
            .set_user_timeout(Some(Duration::from_secs(10)))
            .expect_err("unsupported platform");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        let (stream, _peer) = connected_stream(socket);
        let err = stream
            .set_user_timeout(Some(Duration::from_secs(10)))
            .expect_err("unsupported platform");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
