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
    /// the kernel default. The value has millisecond resolution: a non-zero
    /// duration under 1 ms counts as 1 ms, and the value is clamped to
    /// `i32::MAX` milliseconds (about 24.8 days), the most Linux accepts.
    /// Unlike a connect timeout, it bounds an
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
        // The kernel takes whole milliseconds and reads 0 as its default, so
        // a non-zero duration under 1 ms truncated to the default: the
        // opposite of a tight bound. It rounds up to 1 ms instead
        // (br-asupersync-8vrx8q). The kernel also takes the value as an
        // `int` and refuses one above i32::MAX ms with EINVAL, keeping the
        // old value, while socket2 clamps only to u32::MAX ms; the value is
        // clamped to i32::MAX ms here (GH #74 follow-up).
        let max = Duration::from_millis(2_147_483_647);
        let timeout = timeout.map(|t| {
            if t.is_zero() {
                t
            } else {
                t.clamp(Duration::from_millis(1), max)
            }
        });
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

    /// A non-zero timeout under 1 ms truncated to 0, which the kernel reads as
    /// "use the default": the opposite of the request (br-asupersync-8vrx8q).
    /// It now rounds up to 1 ms, on a stream and on a socket applied at
    /// connect, while a zero duration still restores the default.
    #[cfg(target_os = "linux")]
    #[test]
    fn sub_millisecond_user_timeout_rounds_up_to_one_millisecond() {
        let (stream, _peer) = connected_stream(TcpSocket::new_v4().expect("new_v4"));
        stream
            .set_user_timeout(Some(Duration::from_micros(500)))
            .expect("set 500 us");
        assert_eq!(
            stream.user_timeout().expect("read back"),
            Some(Duration::from_millis(1))
        );
        stream
            .set_user_timeout(Some(Duration::ZERO))
            .expect("zero restores the default");
        assert_eq!(stream.user_timeout().expect("read default"), None);

        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .set_user_timeout(Some(Duration::from_nanos(1)))
            .expect("set on socket");
        let (stream, _peer) = connected_stream(socket);
        assert_eq!(
            stream.user_timeout().expect("read back"),
            Some(Duration::from_millis(1))
        );
    }

    /// Linux takes TCP_USER_TIMEOUT as an `int`: above i32::MAX ms it failed
    /// with EINVAL and kept the old value, although the docs promised a
    /// clamp. A huge timeout now clamps to i32::MAX ms, on a stream and on a
    /// socket applied at connect (GH #74 follow-up).
    #[cfg(target_os = "linux")]
    #[test]
    fn huge_user_timeout_clamps_to_the_kernel_maximum() {
        let max = Duration::from_millis(2_147_483_647);
        let (stream, _peer) = connected_stream(TcpSocket::new_v4().expect("new_v4"));
        for huge in [
            max + Duration::from_millis(1),
            Duration::from_millis(u64::from(u32::MAX)),
            Duration::MAX,
        ] {
            stream
                .set_user_timeout(Some(huge))
                .expect("a huge timeout clamps instead of failing");
            assert_eq!(
                stream.user_timeout().expect("read back"),
                Some(max),
                "{huge:?}"
            );
        }
        stream.set_user_timeout(Some(max)).expect("set the maximum");
        assert_eq!(stream.user_timeout().expect("read back"), Some(max));

        let socket = TcpSocket::new_v4().expect("new_v4");
        socket
            .set_user_timeout(Some(Duration::MAX))
            .expect("set on socket");
        let (stream, _peer) = connected_stream(socket);
        assert_eq!(stream.user_timeout().expect("read back"), Some(max));
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
