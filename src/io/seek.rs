//! Async seek trait.

use std::io::{self, SeekFrom};
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Trait for async seeking.
pub trait AsyncSeek {
    /// Attempt to seek to an offset, in bytes, in a stream.
    ///
    /// A seek beyond the end of a stream is allowed, but behavior is defined
    /// by the implementation.
    fn poll_seek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>>;
}

impl<P: DerefMut + Unpin> AsyncSeek for Pin<P>
where
    P::Target: AsyncSeek,
{
    fn poll_seek(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        self.get_mut().as_mut().poll_seek(cx, pos)
    }
}

impl<S: AsyncSeek + Unpin + ?Sized> AsyncSeek for Box<S> {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        Pin::new(&mut **self).poll_seek(cx, pos)
    }
}

impl<S: AsyncSeek + Unpin + ?Sized> AsyncSeek for &mut S {
    fn poll_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        pos: SeekFrom,
    ) -> Poll<io::Result<u64>> {
        Pin::new(&mut **self).poll_seek(cx, pos)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]

    use super::*;
    use std::task::Waker;

    #[derive(Debug, Clone, Copy)]
    enum SeekReply {
        Ready(u64),
        Error(io::ErrorKind),
    }

    #[derive(Debug)]
    struct SeekProbe {
        expected_waker: Waker,
        reply: SeekReply,
        polls: usize,
        positions: Vec<SeekFrom>,
        saw_expected_waker: bool,
    }

    impl SeekProbe {
        fn new(expected_waker: Waker, reply: SeekReply) -> Self {
            Self {
                expected_waker,
                reply,
                polls: 0,
                positions: Vec::new(),
                saw_expected_waker: false,
            }
        }
    }

    impl AsyncSeek for SeekProbe {
        fn poll_seek(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            pos: SeekFrom,
        ) -> Poll<io::Result<u64>> {
            self.polls += 1;
            self.positions.push(pos);
            self.saw_expected_waker = cx.waker().will_wake(&self.expected_waker);
            match self.reply {
                SeekReply::Ready(position) => Poll::Ready(Ok(position)),
                SeekReply::Error(kind) => {
                    Poll::Ready(Err(io::Error::new(kind, "injected seek failure")))
                }
            }
        }
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn mut_ref_forwarding_preserves_position_and_context() {
        init_test("mut_ref_forwarding_preserves_position_and_context");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut probe = SeekProbe::new(waker.clone(), SeekReply::Ready(11));

        let poll = {
            let mut forwarded = &mut probe;
            Pin::new(&mut forwarded).poll_seek(&mut cx, SeekFrom::Current(-3))
        };
        let ready = matches!(poll, Poll::Ready(Ok(11)));

        crate::assert_with_log!(ready, "forwarded result", true, ready);
        crate::assert_with_log!(probe.polls == 1, "one inner poll", 1, probe.polls);
        crate::assert_with_log!(
            probe.positions == vec![SeekFrom::Current(-3)],
            "position forwarded",
            vec![SeekFrom::Current(-3)],
            probe.positions.clone()
        );
        crate::assert_with_log!(
            probe.saw_expected_waker,
            "context forwarded",
            true,
            probe.saw_expected_waker
        );
        crate::test_complete!("mut_ref_forwarding_preserves_position_and_context");
    }

    #[test]
    fn box_forwarding_preserves_position_and_context() {
        init_test("box_forwarding_preserves_position_and_context");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut probe = Box::new(SeekProbe::new(waker.clone(), SeekReply::Ready(42)));

        let poll = Pin::new(&mut probe).poll_seek(&mut cx, SeekFrom::Start(7));
        let ready = matches!(poll, Poll::Ready(Ok(42)));

        crate::assert_with_log!(ready, "forwarded result", true, ready);
        crate::assert_with_log!(probe.polls == 1, "one inner poll", 1, probe.polls);
        crate::assert_with_log!(
            probe.positions == vec![SeekFrom::Start(7)],
            "position forwarded",
            vec![SeekFrom::Start(7)],
            probe.positions.clone()
        );
        crate::assert_with_log!(
            probe.saw_expected_waker,
            "context forwarded",
            true,
            probe.saw_expected_waker
        );
        crate::test_complete!("box_forwarding_preserves_position_and_context");
    }

    #[test]
    fn pin_forwarding_propagates_inner_error() {
        init_test("pin_forwarding_propagates_inner_error");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut probe =
            SeekProbe::new(waker.clone(), SeekReply::Error(io::ErrorKind::InvalidInput));
        let mut pinned = Pin::new(&mut probe);

        let err = match Pin::new(&mut pinned).poll_seek(&mut cx, SeekFrom::End(-1)) {
            Poll::Ready(Err(err)) => err,
            other => panic!("expected forwarded seek error, got {other:?}"),
        };

        crate::assert_with_log!(
            err.kind() == io::ErrorKind::InvalidInput,
            "error kind",
            io::ErrorKind::InvalidInput,
            err.kind()
        );
        crate::assert_with_log!(probe.polls == 1, "one inner poll", 1, probe.polls);
        crate::assert_with_log!(
            probe.positions == vec![SeekFrom::End(-1)],
            "position forwarded",
            vec![SeekFrom::End(-1)],
            probe.positions.clone()
        );
        crate::assert_with_log!(
            probe.saw_expected_waker,
            "context forwarded",
            true,
            probe.saw_expected_waker
        );
        crate::test_complete!("pin_forwarding_propagates_inner_error");
    }
}
