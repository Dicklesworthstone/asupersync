use super::*;
use crate::io::ReadBuf;
use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Waker};

struct Endpoint {
    input: Vec<u8>, pos: usize, output: Vec<u8>, write_limit: usize, blocked: usize,
    reads: usize, writes: usize, flushes: usize, shutdowns: usize,
    shutdown_pending: bool, shutdown_error: bool, shutdown_done: bool,
    response_after_shutdown: bool, write_panic: bool, write_overreport: bool,
    not_sync: Cell<usize>,
}
impl Endpoint {
    fn new(input: &[u8], write_limit: usize) -> Self {
        Self { input: input.to_vec(), pos: 0, output: Vec::new(), write_limit, blocked: 0,
            reads: 0, writes: 0, flushes: 0, shutdowns: 0,
            shutdown_pending: false, shutdown_error: false, shutdown_done: false,
            response_after_shutdown: false, write_panic: false, write_overreport: false,
            not_sync: Cell::new(0) }
    }
    fn calls(&self) -> (usize, usize, usize, usize) { (self.reads, self.writes, self.flushes, self.shutdowns) }
}
impl AsyncRead for Endpoint {
    fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.reads += 1;
        this.not_sync.set(this.not_sync.get() + 1);
        if this.response_after_shutdown && !this.shutdown_done { return Poll::Pending; }
        let n = buf.remaining().min(this.input.len() - this.pos);
        buf.put_slice(&this.input[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Endpoint {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.writes += 1;
        assert!(!this.shutdown_done, "never write after successful half-close");
        assert!(!this.write_panic, "reverse provider panic sentinel");
        if this.write_overreport { return Poll::Ready(Ok(bytes.len() + 1)); }
        if this.output.len() == this.write_limit {
            this.blocked += 1;
            return Poll::Pending;
        }
        let n = bytes.len().min(2).min(this.write_limit - this.output.len());
        this.output.extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().flushes += 1;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.shutdowns += 1;
        assert!(!this.shutdown_done, "successful shutdown must not be repeated");
        if this.shutdown_pending { return Poll::Pending; }
        if std::mem::take(&mut this.shutdown_error) {
            return Poll::Ready(Err(io::Error::from_raw_os_error(23)));
        }
        this.shutdown_done = true;
        Poll::Ready(Ok(()))
    }
}

fn once(session: &mut BidirectionalCopySession<Endpoint, Endpoint>, cx: &Cx) -> Poll<io::Result<(u64, u64)>> {
    let mut run = std::pin::pin!(session.run(cx));
    run.as_mut().poll(&mut Context::from_waker(Waker::noop()))
}
fn finish(session: &mut BidirectionalCopySession<Endpoint, Endpoint>, cx: &Cx) -> (u64, u64) {
    for _ in 0..1024 {
        if let Poll::Ready(result) = once(session, cx) { return result.unwrap(); }
    }
    panic!("duplex transfer did not finish within the deterministic test bound");
}
fn invariant(progress: BidirectionalCopyProgress) {
    for direction in [progress.a_to_b, progress.b_to_a] {
        assert_eq!(direction.read - direction.written, direction.buffered as u64);
    }
}

#[test]
fn both_read_ahead_buffers_survive_drop_at_every_pair_of_partial_write_offsets() {
    let a_data = b"abcdefgh";
    let b_data = b"1234567";
    for (ab_capacity, ba_capacity) in [(1, 2), (4, 3), (16, 16)] {
        for ab_prefix in 0..a_data.len() {
            for ba_prefix in 0..b_data.len() {
                let cx = Cx::for_testing();
                let mut session = BidirectionalCopySession::with_capacities(
                    Endpoint::new(a_data, ba_prefix), Endpoint::new(b_data, ab_prefix),
                    ab_capacity, ba_capacity,
                ).unwrap();
                for attempt in 0..128 {
                    assert!(once(&mut session, &cx).is_pending());
                    invariant(session.progress());
                    if session.a.blocked != 0 && session.b.blocked != 0 { break; }
                    assert!(attempt < 127, "must actually reach both writer boundaries");
                }
                let before = session.progress();
                assert_eq!(before.a_to_b.written, ab_prefix as u64);
                assert_eq!(before.b_to_a.written, ba_prefix as u64);
                assert!(before.a_to_b.buffered > 0 && before.b_to_a.buffered > 0);
                assert_eq!(session.pending_a_to_b(), &a_data[ab_prefix..before.a_to_b.read as usize]);
                assert_eq!(session.pending_b_to_a(), &b_data[ba_prefix..before.b_to_a.read as usize]);
                assert!(once(&mut session, &cx).is_pending());
                assert_eq!(session.progress(), before);
                session.a.write_limit = usize::MAX;
                session.b.write_limit = usize::MAX;
                assert_eq!(finish(&mut session, &cx), (8, 7));
                assert_eq!(session.a.output, b_data);
                assert_eq!(session.b.output, a_data);
                assert!(session.is_complete());
                invariant(session.progress());
                assert_eq!((session.a.shutdowns, session.b.shutdowns), (1, 1));
            }
        }
    }
}

#[test]
fn one_blocked_writer_does_not_stall_the_other_direction() {
    let cx = Cx::for_testing();
    let mut session = BidirectionalCopySession::new(
        Endpoint::new(b"request", usize::MAX), Endpoint::new(b"response", 0),
    );
    assert!(once(&mut session, &cx).is_pending());
    assert_eq!(session.a.output, b"response");
    assert!(session.progress().b_to_a.write_shutdown);
    assert_eq!(session.pending_a_to_b(), b"request");
    let a_shutdowns = session.a.shutdowns;
    session.b.write_limit = usize::MAX;
    assert_eq!(finish(&mut session, &cx), (7, 8));
    assert_eq!(session.a.shutdowns, a_shutdowns, "completed opposite direction remains closed");
}

#[test]
fn response_after_request_half_close_still_flows_in_reverse() {
    let mut b = Endpoint::new(b"response", usize::MAX);
    b.response_after_shutdown = true;
    let mut session = BidirectionalCopySession::new(Endpoint::new(b"request", usize::MAX), b);
    assert_eq!(finish(&mut session, &Cx::for_testing()), (7, 8));
    assert_eq!(session.a.output, b"response");
    assert_eq!(session.b.output, b"request");
    assert!(session.progress().a_to_b.write_shutdown);
    assert!(session.progress().b_to_a.write_shutdown);
}

#[test]
fn pending_and_failed_shutdown_resume_without_repeating_a_completed_half_close() {
    let cx = Cx::for_testing();
    let mut a = Endpoint::new(b"", usize::MAX);
    a.shutdown_pending = true;
    let mut session = BidirectionalCopySession::new(a, Endpoint::new(b"", usize::MAX));
    assert!(once(&mut session, &cx).is_pending());
    assert!(session.progress().a_to_b.write_shutdown);
    assert!(!session.progress().b_to_a.write_shutdown);
    let b_calls = session.b.calls();
    assert!(once(&mut session, &cx).is_pending());
    assert_eq!(session.b.calls(), b_calls);
    session.a.shutdown_pending = false;
    session.a.shutdown_error = true;
    assert!(matches!(once(&mut session, &cx), Poll::Ready(Err(error)) if error.raw_os_error() == Some(23)));
    assert_eq!(finish(&mut session, &cx), (0, 0));
    assert_eq!(session.b.calls(), b_calls);
    assert_eq!((session.a.flushes, session.b.flushes), (1, 1));
}

#[test]
fn cancellation_and_extraction_preserve_both_distinct_unwritten_suffixes() {
    let cx = Cx::for_testing();
    let mut session = BidirectionalCopySession::new(
        Endpoint::new(b"abcdef", 2), Endpoint::new(b"12345", 3),
    );
    assert!(once(&mut session, &cx).is_pending());
    let before = session.progress();
    cx.cancel_with(crate::types::CancelKind::User, Some("pause both directions"));
    assert!(matches!(once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted));
    assert_eq!(session.progress(), before);
    let (a, b, ab, ba) = session.into_parts();
    assert_eq!(b.output, b"abc");
    assert_eq!(ab, b"def");
    assert_eq!(a.output, b"12");
    assert_eq!(ba, b"345");
    assert_eq!((a.pos, b.pos), (6, 5));
}

#[test]
fn reverse_provider_panic_fences_both_endpoints_before_any_new_io() {
    let cx = Cx::for_testing();
    let mut a = Endpoint::new(b"request", usize::MAX);
    a.write_panic = true;
    let mut session = BidirectionalCopySession::new(a, Endpoint::new(b"reply", usize::MAX));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| once(&mut session, &cx))).is_err());
    let calls = (session.a.calls(), session.b.calls());
    let before = session.progress();
    session.a.write_panic = false;
    assert!(matches!(once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData));
    assert_eq!((session.a.calls(), session.b.calls()), calls);
    assert_eq!(session.progress(), before);
    assert!(!session.is_complete());
}

#[test]
fn impossible_write_count_fences_the_pair_and_preserves_pending_bytes() {
    let cx = Cx::for_testing();
    let mut b = Endpoint::new(b"reply", usize::MAX);
    b.write_overreport = true;
    let mut session = BidirectionalCopySession::new(Endpoint::new(b"request", usize::MAX), b);
    assert!(matches!(once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData));
    let calls = (session.a.calls(), session.b.calls());
    assert_eq!(session.pending_a_to_b(), b"request");
    session.b.write_overreport = false;
    assert!(matches!(once(&mut session, &cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidData));
    assert_eq!((session.a.calls(), session.b.calls()), calls);
}

#[test]
fn complete_pair_is_idempotent_and_supports_send_only_endpoints() {
    fn assert_send<T: Send>(_: T) {}
    let cx = Cx::for_testing();
    let mut session = BidirectionalCopySession::new(
        Endpoint::new(b"secret-a", usize::MAX), Endpoint::new(b"secret-b", usize::MAX),
    );
    // Endpoint deliberately contains Cell and is therefore not Sync.
    assert_send(session.run(&cx));
    assert_eq!(finish(&mut session, &cx), (8, 8));
    let calls = (session.a.calls(), session.b.calls());
    cx.cancel_with(crate::types::CancelKind::User, Some("already complete"));
    assert_eq!(finish(&mut session, &cx), (8, 8));
    assert_eq!((session.a.calls(), session.b.calls()), calls);
    assert!(!format!("{session:?}").contains("secret-"));
}

#[test]
fn zero_capacity_refuses_and_long_transfers_yield_with_progress_on_both_sides() {
    for capacities in [(0, 1), (1, 0), (0, 0)] {
        assert!(matches!(BidirectionalCopySession::with_capacities(
            Endpoint::new(b"", usize::MAX), Endpoint::new(b"", usize::MAX), capacities.0, capacities.1,
        ), Err(error) if error.kind() == io::ErrorKind::InvalidInput));
    }
    let cx = Cx::for_testing();
    let mut session = BidirectionalCopySession::with_capacities(
        Endpoint::new(&[1; 256], usize::MAX), Endpoint::new(&[2; 256], usize::MAX), 1, 1,
    ).unwrap();
    assert!(once(&mut session, &cx).is_pending());
    assert!(session.progress().a_to_b.written > 0);
    assert!(session.progress().b_to_a.written > 0);
    assert_eq!(session.a.reads + session.a.writes + session.b.reads + session.b.writes, POLL_BUDGET);
    assert_eq!(finish(&mut session, &cx), (256, 256));
    assert_eq!(session.a.output, [2; 256]);
    assert_eq!(session.b.output, [1; 256]);
}

#[test]
fn legacy_copy_is_a_negative_control_for_dropping_private_read_ahead() {
    let data = b"abcdefgh";
    let mut reader = Endpoint::new(data, usize::MAX);
    let mut writer = Endpoint::new(b"", 3);
    {
        let mut legacy = std::pin::pin!(crate::io::copy(&mut reader, &mut writer));
        assert!(legacy.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    assert_eq!(reader.pos, data.len(), "the source advanced before the stalled write");
    assert_eq!(writer.output, &data[..3]);
    writer.write_limit = usize::MAX;
    {
        let mut retry = std::pin::pin!(crate::io::copy(&mut reader, &mut writer));
        assert!(matches!(retry.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Ok(0))));
    }
    assert_ne!(writer.output, data, "legacy API's documented private suffix was discarded");

    let cx = Cx::for_testing();
    let mut retained = crate::io::CopySession::new(
        Endpoint::new(data, usize::MAX), Endpoint::new(b"", 3),
    );
    {
        let mut first = std::pin::pin!(retained.run(&cx));
        assert!(first.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    }
    assert_eq!(retained.pending_bytes(), &data[3..]);
    retained.writer.write_limit = usize::MAX;
    {
        let mut resume = std::pin::pin!(retained.run(&cx));
        assert!(matches!(resume.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Ok(8))));
    }
    let (_, writer, pending) = retained.into_parts();
    assert_eq!(writer.output, data);
    assert!(pending.is_empty());
}
