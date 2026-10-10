//! Linux-only UDP launch-time sends (`SO_TXTIME` / `SCM_TXTIME`) and
//! socket error-queue reads (`MSG_ERRQUEUE`), GH #73.
//!
//! # Launch-time sends
//!
//! [`UdpSocket::set_txtime`] turns on `SO_TXTIME`; afterwards every datagram
//! is sent with [`UdpSocket::send_to_with_txtime`] or
//! [`UdpSocket::send_with_txtime`], which attach a per-datagram `SCM_TXTIME`
//! launch time. The ETF qdisc (or a NIC with launch-time offload) then
//! releases each datagram at that instant; `sch_fq` uses it as a pacing time.
//!
//! Once `SO_TXTIME` is on, the plain send paths of the same `UdpSocket`
//! (`send`, `send_to`, the batch sends and [`SendSink`](super::SendSink))
//! return `InvalidInput` instead of sending: the ETF qdisc silently drops a
//! datagram that carries no launch time (the send itself reports `Ok`, only
//! the error queue says otherwise), so a mixed-up send path would lose data
//! without any synchronous signal. The kernel offers no way to turn
//! `SO_TXTIME` off again, so the refusal lasts for the socket's lifetime. The
//! state is tracked per `UdpSocket` handle: [`UdpSocket::try_clone`] made
//! after `set_txtime` inherits it, but a socket rebuilt with
//! [`UdpSocket::from_std`] (or a clone made before `set_txtime`) does not know
//! that the option is on; call `set_txtime` on that handle too.
//!
//! A launch-time send reports kernel *submission* only. A submitted datagram
//! cannot be retracted by cancelling the task; rejected or missed launch times
//! surface later on the error queue when the socket was configured with
//! [`UdpTxTimeConfig::with_report_errors`].
//!
//! # Error queue
//!
//! [`UdpSocket::recv_error`] reads one report from the socket's error queue:
//! launch-time reports (`SO_EE_ORIGIN_TXTIME`), and ICMP / ICMPv6 errors once
//! [`UdpSocket::set_recverr`] is on. Its readiness is `POLLERR`, which the
//! reactor models as [`Interest::ERROR`]; a pending `recv_error` arms only
//! that interest, and the socket's readable/writable operations re-arm their
//! own interest on their next poll, so the two do not disturb each other.
//!
//! While reports sit in the queue the kernel keeps signalling `POLLERR` on the
//! socket, and every readiness wait on it (readable and writable ones too)
//! is woken by it. Drain the queue promptly (e.g. with
//! [`UdpSocket::try_recv_error`] in a loop) once reports are enabled. Reports
//! are best-effort: the kernel drops them under memory or queue pressure.

use super::UdpSocket;
use crate::runtime::reactor::Interest;
use nix::sys::socket::{
    self, ControlMessage, ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6, SockaddrStorage,
    setsockopt, sockopt,
};
use std::io::{self, IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::task::{Context, Poll};

/// `SO_EE_ORIGIN_TXTIME` from `linux/errqueue.h` (not defined by `libc`).
const SO_EE_ORIGIN_TXTIME: u8 = 6;
/// `SO_EE_ORIGIN_ZEROCOPY` from `linux/errqueue.h`.
const SO_EE_ORIGIN_ZEROCOPY: u8 = 5;
/// `SO_EE_CODE_TXTIME_INVALID_PARAM` from `linux/errqueue.h`.
const SO_EE_CODE_TXTIME_INVALID_PARAM: u8 = 1;
/// `SO_EE_CODE_TXTIME_MISSED` from `linux/errqueue.h`.
const SO_EE_CODE_TXTIME_MISSED: u8 = 2;
/// `SOF_TXTIME_DEADLINE_MODE` from `linux/net_tstamp.h`.
const SOF_TXTIME_DEADLINE_MODE: u32 = 1 << 0;
/// `SOF_TXTIME_REPORT_ERRORS` from `linux/net_tstamp.h`.
const SOF_TXTIME_REPORT_ERRORS: u32 = 1 << 1;

/// Clock that `SO_TXTIME` launch times are expressed in.
///
/// These are the only clocks the kernel accepts for `SO_TXTIME`. Any clock
/// other than [`Monotonic`](Self::Monotonic) needs `CAP_NET_ADMIN`; without
/// it [`UdpSocket::set_txtime`] fails with `PermissionDenied`. The ETF qdisc
/// is normally configured with `CLOCK_TAI`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpTxTimeClock {
    /// `CLOCK_MONOTONIC`; usable without privileges (`sch_fq` pacing).
    Monotonic,
    /// `CLOCK_TAI`; the clock ETF and TSN schedules use.
    Tai,
    /// `CLOCK_REALTIME`.
    Realtime,
}

impl UdpTxTimeClock {
    /// The raw `clockid_t`.
    #[must_use]
    pub const fn clockid(self) -> libc::clockid_t {
        match self {
            Self::Monotonic => libc::CLOCK_MONOTONIC,
            Self::Tai => libc::CLOCK_TAI,
            Self::Realtime => libc::CLOCK_REALTIME,
        }
    }

    /// The current time on this clock in nanoseconds, the unit launch times
    /// are given in.
    pub fn now_ns(self) -> io::Result<u64> {
        let now = nix::time::clock_gettime(nix::time::ClockId::from_raw(self.clockid()))
            .map_err(io::Error::from)?;
        let out_of_range = || io::Error::other("clock value out of range for u64 nanoseconds");
        let secs = u64::try_from(now.tv_sec()).map_err(|_| out_of_range())?;
        let nanos = u64::try_from(now.tv_nsec()).map_err(|_| out_of_range())?;
        secs.checked_mul(1_000_000_000)
            .and_then(|ns| ns.checked_add(nanos))
            .ok_or_else(out_of_range)
    }
}

/// `SO_TXTIME` configuration for [`UdpSocket::set_txtime`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpTxTimeConfig {
    clock: UdpTxTimeClock,
    deadline_mode: bool,
    report_errors: bool,
}

impl UdpTxTimeConfig {
    /// Launch times on `clock`, no deadline mode, no error reports.
    #[must_use]
    pub const fn new(clock: UdpTxTimeClock) -> Self {
        Self {
            clock,
            deadline_mode: false,
            report_errors: false,
        }
    }

    /// `SOF_TXTIME_DEADLINE_MODE`: treat each launch time as a deadline
    /// (ETF may send the datagram as soon as possible before it).
    #[must_use]
    pub const fn with_deadline_mode(mut self, on: bool) -> Self {
        self.deadline_mode = on;
        self
    }

    /// `SOF_TXTIME_REPORT_ERRORS`: queue a report on the socket's error queue
    /// for every rejected (`InvalidParam`) or missed launch time; read them
    /// with [`UdpSocket::recv_error`].
    #[must_use]
    pub const fn with_report_errors(mut self, on: bool) -> Self {
        self.report_errors = on;
        self
    }

    /// The configured clock.
    #[must_use]
    pub const fn clock(&self) -> UdpTxTimeClock {
        self.clock
    }

    /// Whether deadline mode is on.
    #[must_use]
    pub const fn deadline_mode(&self) -> bool {
        self.deadline_mode
    }

    /// Whether launch-time errors are reported on the error queue.
    #[must_use]
    pub const fn report_errors(&self) -> bool {
        self.report_errors
    }

    const fn flags(self) -> u32 {
        let mut flags = 0;
        if self.deadline_mode {
            flags |= SOF_TXTIME_DEADLINE_MODE;
        }
        if self.report_errors {
            flags |= SOF_TXTIME_REPORT_ERRORS;
        }
        flags
    }
}

/// Where an error-queue report came from (`sock_extended_err.ee_origin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpErrorOrigin {
    /// `SO_EE_ORIGIN_NONE`.
    None,
    /// `SO_EE_ORIGIN_LOCAL`: raised by the local stack.
    Local,
    /// `SO_EE_ORIGIN_ICMP`: an ICMP error from the network.
    Icmp,
    /// `SO_EE_ORIGIN_ICMP6`: an ICMPv6 error from the network.
    Icmp6,
    /// `SO_EE_ORIGIN_TIMESTAMPING` (a.k.a. `SO_EE_ORIGIN_TXSTATUS`).
    Timestamping,
    /// `SO_EE_ORIGIN_ZEROCOPY`.
    Zerocopy,
    /// `SO_EE_ORIGIN_TXTIME`: a rejected or missed launch time.
    TxTime,
    /// Any other origin value.
    Other(u8),
}

impl UdpErrorOrigin {
    const fn from_raw(origin: u8) -> Self {
        match origin {
            libc::SO_EE_ORIGIN_NONE => Self::None,
            libc::SO_EE_ORIGIN_LOCAL => Self::Local,
            libc::SO_EE_ORIGIN_ICMP => Self::Icmp,
            libc::SO_EE_ORIGIN_ICMP6 => Self::Icmp6,
            libc::SO_EE_ORIGIN_TIMESTAMPING => Self::Timestamping,
            SO_EE_ORIGIN_ZEROCOPY => Self::Zerocopy,
            SO_EE_ORIGIN_TXTIME => Self::TxTime,
            other => Self::Other(other),
        }
    }
}

/// What went wrong with a launch time (`SO_EE_ORIGIN_TXTIME` report code).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpTxTimeErrorKind {
    /// `SO_EE_CODE_TXTIME_INVALID_PARAM`: the qdisc rejected the launch time
    /// (already in the past, wrong clock, or missing entirely).
    InvalidParam,
    /// `SO_EE_CODE_TXTIME_MISSED`: the datagram was dequeued too late.
    Missed,
    /// Any other code.
    Other(u8),
}

/// A decoded `SO_EE_ORIGIN_TXTIME` report; see [`UdpErrorReport::txtime_error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpTxTimeError {
    /// What went wrong.
    pub kind: UdpTxTimeErrorKind,
    /// The launch time the datagram carried, in nanoseconds on the socket's
    /// `SO_TXTIME` clock (0 when it carried none).
    pub launch_time_ns: u64,
}

/// One report read from a socket's error queue (`struct sock_extended_err`
/// plus what `recvmsg(MSG_ERRQUEUE)` returns alongside it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct UdpErrorReport {
    /// `ee_errno`: the error, e.g. `ECONNREFUSED` for an ICMP port
    /// unreachable, `ECANCELED` / `EINVAL` for launch-time reports.
    pub errno: i32,
    /// `ee_origin`.
    pub origin: UdpErrorOrigin,
    /// `ee_type` (the ICMP type for ICMP origins).
    pub ee_type: u8,
    /// `ee_code` (the ICMP code for ICMP origins, the txtime code for
    /// launch-time reports).
    pub ee_code: u8,
    /// `ee_info` (e.g. the path MTU for "fragmentation needed").
    pub ee_info: u32,
    /// `ee_data`.
    pub ee_data: u32,
    /// `SO_EE_OFFENDER`: the node that raised the error (the ICMP sender);
    /// `None` for locally raised errors.
    pub offender: Option<SocketAddr>,
    /// The destination of the datagram that caused the error, when the
    /// kernel reports it (network-originated errors).
    pub destination: Option<SocketAddr>,
    /// Bytes of the offending datagram copied into the caller's buffer.
    ///
    /// For network error origins ([`UdpErrorOrigin::Icmp`] and
    /// [`UdpErrorOrigin::Icmp6`]), this is the payload (or prefix preserved by
    /// the ICMP error) of the datagram that triggered the error.
    ///
    /// For launch-time reports ([`UdpErrorOrigin::TxTime`]), the ETF queueing
    /// discipline queues the packet as it sits at the qdisc, which on Ethernet
    /// includes the link-layer header.
    pub len: usize,
    /// Whether that payload was longer than the buffer (`MSG_TRUNC`).
    pub truncated: bool,
}

impl UdpErrorReport {
    /// The report's `errno` as an [`io::Error`].
    #[must_use]
    pub fn error(&self) -> io::Error {
        io::Error::from_raw_os_error(self.errno)
    }

    /// Decodes a launch-time report; `None` for reports of any other origin.
    #[must_use]
    pub const fn txtime_error(&self) -> Option<UdpTxTimeError> {
        if !matches!(self.origin, UdpErrorOrigin::TxTime) {
            return None;
        }
        let kind = match self.ee_code {
            SO_EE_CODE_TXTIME_INVALID_PARAM => UdpTxTimeErrorKind::InvalidParam,
            SO_EE_CODE_TXTIME_MISSED => UdpTxTimeErrorKind::Missed,
            other => UdpTxTimeErrorKind::Other(other),
        };
        // The kernel splits the 64-bit launch time: high half in ee_data,
        // low half in ee_info.
        let launch_time_ns = ((self.ee_data as u64) << 32) | self.ee_info as u64;
        Some(UdpTxTimeError {
            kind,
            launch_time_ns,
        })
    }
}

pub(super) fn plain_send_refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "SO_TXTIME is set on this UDP socket: a datagram without a launch time would be \
         dropped by an ETF qdisc; send it with send_to_with_txtime / send_with_txtime",
    )
}

fn txtime_not_configured() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "launch-time send on a UDP socket without SO_TXTIME; call UdpSocket::set_txtime first",
    )
}

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "cancelled")
}

fn checkpoint_cancelled() -> bool {
    crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false)
}

fn sockaddr_in_to_std(raw: &libc::sockaddr_in) -> Option<SocketAddr> {
    if raw.sin_family != libc::AF_INET as libc::sa_family_t {
        return None;
    }
    let ip = Ipv4Addr::from_bits(u32::from_be(raw.sin_addr.s_addr));
    Some(SocketAddr::V4(SocketAddrV4::new(
        ip,
        u16::from_be(raw.sin_port),
    )))
}

fn sockaddr_in6_to_std(raw: &libc::sockaddr_in6) -> Option<SocketAddr> {
    if raw.sin6_family != libc::AF_INET6 as libc::sa_family_t {
        return None;
    }
    let ip = Ipv6Addr::from(raw.sin6_addr.s6_addr);
    Some(SocketAddr::V6(SocketAddrV6::new(
        ip,
        u16::from_be(raw.sin6_port),
        raw.sin6_flowinfo,
        raw.sin6_scope_id,
    )))
}

fn storage_to_std(addr: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(v4) = addr.as_sockaddr_in() {
        return Some(SocketAddr::V4(SocketAddrV4::from(*v4)));
    }
    addr.as_sockaddr_in6()
        .map(|v6| SocketAddr::V6(SocketAddrV6::from(*v6)))
}

/// One `sendmsg` with an `SCM_TXTIME` control message.
fn sendmsg_with_txtime(
    fd: std::os::fd::RawFd,
    buf: &[u8],
    target: Option<SocketAddr>,
    launch_time_ns: u64,
) -> io::Result<usize> {
    let iov = [IoSlice::new(buf)];
    let cmsgs = [ControlMessage::TxTime(&launch_time_ns)];
    let sent = match target {
        Some(SocketAddr::V4(v4)) => socket::sendmsg(
            fd,
            &iov,
            &cmsgs,
            MsgFlags::empty(),
            Some(&SockaddrIn::from(v4)),
        ),
        Some(SocketAddr::V6(v6)) => socket::sendmsg(
            fd,
            &iov,
            &cmsgs,
            MsgFlags::empty(),
            Some(&SockaddrIn6::from(v6)),
        ),
        None => socket::sendmsg::<()>(fd, &iov, &cmsgs, MsgFlags::empty(), None),
    };
    sent.map_err(io::Error::from)
}

/// One non-blocking `recvmsg(MSG_ERRQUEUE)`; `WouldBlock` when the queue is
/// empty.
fn recv_error_once(fd: std::os::fd::RawFd, buf: &mut [u8]) -> io::Result<UdpErrorReport> {
    // Room for the extended error with an IPv6 offender plus any ancillary
    // control messages the socket may have enabled (IP_PKTINFO / in6_pktinfo,
    // HOPLIMIT, TCLASS, ORIGDSTADDR, and a timestamping triple) so the
    // report is not lost to MSG_CTRUNC. A Vec keeps the buffer cmsghdr-aligned.
    let mut cmsg_buf = nix::cmsg_space!(
        libc::sock_extended_err,
        libc::sockaddr_in6,
        libc::in6_pktinfo,
        libc::c_int,
        libc::c_int,
        libc::sockaddr_storage,
        [libc::timespec; 3]
    );
    let mut iov = [IoSliceMut::new(buf)];
    let msg = socket::recvmsg::<SockaddrStorage>(
        fd,
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
    )
    .map_err(io::Error::from)?;

    let len = msg.bytes;
    let truncated = msg.flags.contains(MsgFlags::MSG_TRUNC);
    let destination = msg.address.as_ref().and_then(storage_to_std);

    let cmsgs = msg.cmsgs().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "error-queue control data truncated (MSG_CTRUNC); the report was lost",
        )
    })?;
    for cmsg in cmsgs {
        let (err, offender) = match cmsg {
            ControlMessageOwned::Ipv4RecvErr(err, offender) => {
                (err, offender.as_ref().and_then(sockaddr_in_to_std))
            }
            ControlMessageOwned::Ipv6RecvErr(err, offender) => {
                (err, offender.as_ref().and_then(sockaddr_in6_to_std))
            }
            _ => continue,
        };
        return Ok(UdpErrorReport {
            errno: i32::try_from(err.ee_errno).unwrap_or(i32::MAX),
            origin: UdpErrorOrigin::from_raw(err.ee_origin),
            ee_type: err.ee_type,
            ee_code: err.ee_code,
            ee_info: err.ee_info,
            ee_data: err.ee_data,
            offender,
            destination,
            len,
            truncated,
        });
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "error-queue message carried no IP_RECVERR/IPV6_RECVERR control message",
    ))
}

impl UdpSocket {
    /// Turns on `SO_TXTIME` with `config` (Linux only).
    ///
    /// After this succeeds, send every datagram with
    /// [`send_to_with_txtime`](Self::send_to_with_txtime) or
    /// [`send_with_txtime`](Self::send_with_txtime). The plain send paths of
    /// this handle (`send`, `send_to`, the batch sends, `SendSink`) return
    /// `InvalidInput` from then on: an ETF qdisc silently drops a datagram
    /// without a launch time while the send itself reports `Ok`. The kernel
    /// cannot turn `SO_TXTIME` off again, so this lasts for the socket's
    /// lifetime. Calling `set_txtime` again reconfigures the clock and flags.
    ///
    /// The state is kept per handle: a [`try_clone`](Self::try_clone) made
    /// afterwards inherits it, but a socket rebuilt with
    /// [`from_std`](Self::from_std), or a clone made before this call, does
    /// not know the option is on; call `set_txtime` on that handle too.
    ///
    /// # Errors
    ///
    /// `PermissionDenied` for any clock but [`UdpTxTimeClock::Monotonic`]
    /// without `CAP_NET_ADMIN`; the socket is left unchanged on error.
    pub fn set_txtime(&mut self, config: UdpTxTimeConfig) -> io::Result<()> {
        let raw = libc::sock_txtime {
            clockid: config.clock.clockid(),
            flags: config.flags(),
        };
        setsockopt(&*self.inner, sockopt::TxTime, &raw).map_err(io::Error::from)?;
        self.txtime = Some(config);
        Ok(())
    }

    /// The `SO_TXTIME` configuration set through this handle, if any.
    #[must_use]
    pub const fn txtime(&self) -> Option<UdpTxTimeConfig> {
        self.txtime
    }

    /// Turns on (or off) queueing of ICMP / ICMPv6 errors on this socket's
    /// error queue (`IP_RECVERR`, and `IPV6_RECVERR` on an IPv6 socket), to
    /// be read with [`recv_error`](Self::recv_error) (Linux only).
    ///
    /// With it on, the kernel also reports such errors on the next ordinary
    /// receive, as with a connected socket. Drain the queue promptly: while
    /// it is non-empty every readiness wait on the socket is woken by
    /// `POLLERR`.
    pub fn set_recverr(&self, on: bool) -> io::Result<()> {
        match self.inner.local_addr()? {
            SocketAddr::V4(_) => {
                setsockopt(&*self.inner, sockopt::Ipv4RecvErr, &on).map_err(io::Error::from)?;
            }
            SocketAddr::V6(_) => {
                setsockopt(&*self.inner, sockopt::Ipv6RecvErr, &on).map_err(io::Error::from)?;
                // IPv4-mapped traffic on a dual-stack socket is governed by
                // IP_RECVERR; a v6-only socket may refuse it, which is fine.
                let _ = setsockopt(&*self.inner, sockopt::Ipv4RecvErr, &on);
            }
        }
        self.recverr.store(on, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Whether `IP_RECVERR` / `IPV6_RECVERR` has been set through this handle.
    #[must_use]
    pub fn recverr(&self) -> bool {
        self.recverr.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Sends `buf` to `target` with launch time `launch_time_ns` (nanoseconds
    /// on the clock given to [`set_txtime`](Self::set_txtime)) in an
    /// `SCM_TXTIME` control message (Linux only).
    ///
    /// Waits for writability like [`send_to`](Self::send_to) when the send
    /// buffer is full (datagrams queued for a future launch time count against
    /// `SO_SNDBUF` until they leave). `Ok` means the kernel accepted the
    /// datagram; a launch time the qdisc rejects or misses is reported on the
    /// error queue. The target is a resolved address: no name lookup happens
    /// on this timing-sensitive path.
    ///
    /// # Errors
    ///
    /// `InvalidInput` if `SO_TXTIME` was not set through this handle.
    pub async fn send_to_with_txtime(
        &mut self,
        buf: &[u8],
        target: SocketAddr,
        launch_time_ns: u64,
    ) -> io::Result<usize> {
        std::future::poll_fn(|cx| self.poll_send_with_txtime(cx, buf, Some(target), launch_time_ns))
            .await
    }

    /// [`send_to_with_txtime`](Self::send_to_with_txtime) to the connected
    /// peer (Linux only).
    pub async fn send_with_txtime(&mut self, buf: &[u8], launch_time_ns: u64) -> io::Result<usize> {
        std::future::poll_fn(|cx| self.poll_send_with_txtime(cx, buf, None, launch_time_ns)).await
    }

    /// Poll form of [`send_to_with_txtime`](Self::send_to_with_txtime)
    /// (`target: None` sends to the connected peer).
    pub fn poll_send_with_txtime(
        &mut self,
        cx: &Context<'_>,
        buf: &[u8],
        target: Option<SocketAddr>,
        launch_time_ns: u64,
    ) -> Poll<io::Result<usize>> {
        if self.txtime.is_none() {
            return Poll::Ready(Err(txtime_not_configured()));
        }
        if checkpoint_cancelled() {
            return Poll::Ready(Err(cancelled()));
        }
        match sendmsg_with_txtime(self.inner.as_raw_fd(), buf, target, launch_time_ns) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if let Err(err) = self.register_interest(cx, Interest::WRITABLE) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Reads one report from the socket's error queue (`MSG_ERRQUEUE`),
    /// waiting for `POLLERR` readiness ([`Interest::ERROR`]) while the queue
    /// is empty (Linux only).
    ///
    /// The payload of the datagram that caused the error is copied into
    /// `buf` (an empty `buf` is fine; the report says whether the payload was
    /// truncated). Reports come from launch-time errors
    /// ([`UdpTxTimeConfig::with_report_errors`]) and, once
    /// [`set_recverr`](Self::set_recverr) is on, ICMP errors. Reports are
    /// best-effort: the kernel drops them under memory or queue pressure.
    ///
    /// Waiting here arms only `Interest::ERROR`; the socket's receive and
    /// send operations re-arm their own interest when polled. While reports
    /// are queued the kernel keeps signalling `POLLERR`, which also wakes
    /// those other waits, so drain the queue promptly (for example with
    /// [`try_recv_error`](Self::try_recv_error) in a loop).
    ///
    /// When the queue is empty but the socket holds a pending error (the
    /// kernel signals `POLLERR` for it too, for example an ICMP port
    /// unreachable on a connected socket without `set_recverr`), that error is
    /// returned and cleared instead of waiting.
    ///
    /// Cancel-safe: a report is only dequeued by the call that returns it.
    pub async fn recv_error(&mut self, buf: &mut [u8]) -> io::Result<UdpErrorReport> {
        std::future::poll_fn(|cx| self.poll_recv_error(cx, buf)).await
    }

    /// Poll form of [`recv_error`](Self::recv_error).
    pub fn poll_recv_error(
        &mut self,
        cx: &Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<UdpErrorReport>> {
        if checkpoint_cancelled() {
            return Poll::Ready(Err(cancelled()));
        }
        match recv_error_once(self.inner.as_raw_fd(), buf) {
            Ok(report) => Poll::Ready(Ok(report)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // An empty queue can still leave POLLERR raised: a pending
                // socket error (for example an ICMP port unreachable on a
                // connected socket without IP_RECVERR) sits in the socket's
                // error field, which MSG_ERRQUEUE does not clear. Re-arming on
                // it would spin, so read and clear it with SO_ERROR.
                //
                // Dequeuing a report already clears the error field, so with
                // the queue empty a nonzero error is the only record of it: no
                // IP_RECVERR, an error that arrived before set_recverr, or a
                // report the kernel could not queue (receive buffer full).
                // Return it. If a report was queued between the two reads, the
                // error was that report's shadow: return the report instead,
                // so the error is delivered once.
                match socket::getsockopt(&*self.inner, sockopt::SocketError) {
                    Ok(0) => {}
                    Ok(code) => {
                        return Poll::Ready(match recv_error_once(self.inner.as_raw_fd(), buf) {
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                Err(io::Error::from_raw_os_error(code))
                            }
                            report => report,
                        });
                    }
                    Err(errno) => return Poll::Ready(Err(io::Error::from(errno))),
                }
                if let Err(err) = self.register_interest(cx, Interest::ERROR) {
                    return Poll::Ready(Err(err));
                }
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    /// Reads one report from the error queue without waiting; `Ok(None)`
    /// when the queue is empty (Linux only).
    pub fn try_recv_error(&self, buf: &mut [u8]) -> io::Result<Option<UdpErrorReport>> {
        match recv_error_once(self.inner.as_raw_fd(), buf) {
            Ok(report) => Ok(Some(report)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txtime_config_flags_match_linux_net_tstamp() {
        let config = UdpTxTimeConfig::new(UdpTxTimeClock::Tai);
        assert_eq!(config.flags(), 0);
        assert_eq!(config.with_deadline_mode(true).flags(), 1);
        assert_eq!(config.with_report_errors(true).flags(), 2);
        let both = config.with_deadline_mode(true).with_report_errors(true);
        assert_eq!(both.flags(), 3);
        assert!(both.deadline_mode() && both.report_errors());
        assert_eq!(both.clock(), UdpTxTimeClock::Tai);
        assert_eq!(UdpTxTimeClock::Tai.clockid(), libc::CLOCK_TAI);
    }

    fn report(origin: u8, code: u8, data: u32, info: u32) -> UdpErrorReport {
        UdpErrorReport {
            errno: libc::ECANCELED,
            origin: UdpErrorOrigin::from_raw(origin),
            ee_type: 0,
            ee_code: code,
            ee_info: info,
            ee_data: data,
            offender: None,
            destination: None,
            len: 0,
            truncated: false,
        }
    }

    #[test]
    fn txtime_report_decodes_split_launch_time_and_code() {
        let launch = 0x0123_4567_89ab_cdef_u64;
        let missed = report(6, 2, (launch >> 32) as u32, launch as u32);
        assert_eq!(missed.origin, UdpErrorOrigin::TxTime);
        assert_eq!(
            missed.txtime_error(),
            Some(UdpTxTimeError {
                kind: UdpTxTimeErrorKind::Missed,
                launch_time_ns: launch,
            })
        );
        let invalid = report(6, 1, 0, 0);
        assert_eq!(
            invalid.txtime_error().map(|e| e.kind),
            Some(UdpTxTimeErrorKind::InvalidParam)
        );
        assert_eq!(
            report(6, 9, 0, 0).txtime_error().map(|e| e.kind),
            Some(UdpTxTimeErrorKind::Other(9))
        );
        // ICMP reports are not launch-time reports.
        assert_eq!(report(2, 3, 0, 0).txtime_error(), None);
        assert_eq!(missed.error().raw_os_error(), Some(libc::ECANCELED));
    }

    #[test]
    fn error_origin_maps_linux_errqueue_values() {
        assert_eq!(UdpErrorOrigin::from_raw(0), UdpErrorOrigin::None);
        assert_eq!(UdpErrorOrigin::from_raw(1), UdpErrorOrigin::Local);
        assert_eq!(UdpErrorOrigin::from_raw(2), UdpErrorOrigin::Icmp);
        assert_eq!(UdpErrorOrigin::from_raw(3), UdpErrorOrigin::Icmp6);
        assert_eq!(UdpErrorOrigin::from_raw(4), UdpErrorOrigin::Timestamping);
        assert_eq!(UdpErrorOrigin::from_raw(5), UdpErrorOrigin::Zerocopy);
        assert_eq!(UdpErrorOrigin::from_raw(6), UdpErrorOrigin::TxTime);
        assert_eq!(UdpErrorOrigin::from_raw(42), UdpErrorOrigin::Other(42));
    }

    #[test]
    fn offender_conversion_ignores_unspecified_family() {
        // Local errors (launch-time reports) carry a zeroed AF_UNSPEC offender.
        let mut v4 = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 9_u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(Ipv4Addr::LOCALHOST).to_be(),
            },
            sin_zero: [0; 8],
        };
        assert_eq!(
            sockaddr_in_to_std(&v4),
            Some("127.0.0.1:9".parse().unwrap())
        );
        v4.sin_family = 0;
        assert_eq!(sockaddr_in_to_std(&v4), None);

        let mut v6 = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 9_u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: Ipv6Addr::LOCALHOST.octets(),
            },
            sin6_scope_id: 0,
        };
        assert_eq!(sockaddr_in6_to_std(&v6), Some("[::1]:9".parse().unwrap()));
        v6.sin6_family = 0;
        assert_eq!(sockaddr_in6_to_std(&v6), None);
    }

    #[test]
    fn recverr_state_tracking_and_clone() {
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = UdpSocket::from_std(std_sock).unwrap();
        assert!(!socket.recverr());
        socket.set_recverr(true).unwrap();
        assert!(socket.recverr());
        let cloned = socket.try_clone().unwrap();
        assert!(cloned.recverr());
        socket.set_recverr(false).unwrap();
        assert!(!socket.recverr());
    }
}
