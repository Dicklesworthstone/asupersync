/// Metamorphic tests for `io::copy` streaming invariants.
use asupersync::io::{
    AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, ReadBuf, copy, copy_buf,
    copy_with_progress,
};
use futures_lite::future::block_on;
use proptest::prelude::*;
use std::cmp;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

#[derive(Debug, Clone)]
struct PartialReader {
    data: Vec<u8>,
    position: usize,
    max_chunk: usize,
    pending_every: Option<usize>,
    poll_count: usize,
}

impl PartialReader {
    fn new(data: Vec<u8>, max_chunk: usize, pending_every: Option<usize>) -> Self {
        Self {
            data,
            position: 0,
            max_chunk: max_chunk.max(1),
            pending_every,
            poll_count: 0,
        }
    }
}

impl AsyncRead for PartialReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_count += 1;

        if let Some(every) = self.pending_every {
            if every > 0 && self.poll_count % every == 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        if self.position >= self.data.len() {
            return Poll::Ready(Ok(()));
        }

        let remaining = &self.data[self.position..];
        let to_copy = cmp::min(remaining.len(), cmp::min(self.max_chunk, buf.remaining()));
        buf.put_slice(&remaining[..to_copy]);
        self.position += to_copy;
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug, Clone)]
struct PartialWriter {
    written: Vec<u8>,
    max_chunk: usize,
    limit: Option<usize>,
    pending_every: Option<usize>,
    poll_count: usize,
}

impl PartialWriter {
    fn new(max_chunk: usize, limit: Option<usize>, pending_every: Option<usize>) -> Self {
        Self {
            written: Vec::new(),
            max_chunk: max_chunk.max(1),
            limit,
            pending_every,
            poll_count: 0,
        }
    }

    fn snapshot(&self) -> Vec<u8> {
        self.written.clone()
    }
}

impl AsyncWrite for PartialWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_count += 1;

        if let Some(every) = self.pending_every {
            if every > 0 && self.poll_count % every == 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        if let Some(limit) = self.limit {
            if self.written.len() >= limit {
                return Poll::Ready(Err(io::Error::other("write limit exceeded")));
            }
        }

        let mut to_write = cmp::min(buf.len(), self.max_chunk);
        if let Some(limit) = self.limit {
            let remaining = limit.saturating_sub(self.written.len());
            to_write = cmp::min(to_write, remaining);
        }

        self.written.extend_from_slice(&buf[..to_write]);
        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn noop_waker() -> Waker {
    Waker::noop().clone()
}

fn arb_case() -> impl Strategy<Value = (Vec<u8>, usize, usize, usize, Option<usize>)> {
    (
        proptest::collection::vec(any::<u8>(), 0..2048),
        1_usize..64,
        1_usize..64,
        8_usize..256,
        prop::option::of(2_usize..1024),
    )
        .prop_filter(
            "limit must be smaller than payload when present",
            |(data, _, _, _, limit)| limit.is_none_or(|value| value < data.len()),
        )
}

proptest! {
    #[test]
    fn mr_copy_transfers_all_bytes(
        (data, read_chunk, write_chunk, _, _) in arb_case(),
        pending in prop::option::of(2_usize..6),
    ) {
        let mut reader = PartialReader::new(data.clone(), read_chunk, pending);
        let mut writer = PartialWriter::new(write_chunk, None, pending);

        let copied = block_on(copy(&mut reader, &mut writer)).expect("copy should succeed");

        prop_assert_eq!(copied, u64::try_from(data.len()).expect("usize fits into u64"));
        prop_assert_eq!(writer.snapshot(), data);
    }

    #[test]
    fn mr_copy_with_progress_is_monotonic(
        (data, read_chunk, write_chunk, _, _) in arb_case(),
        pending in prop::option::of(2_usize..6),
    ) {
        let mut reader = PartialReader::new(data.clone(), read_chunk, pending);
        let mut writer = PartialWriter::new(write_chunk, None, pending);
        let mut progress = Vec::new();

        let copied = block_on(copy_with_progress(&mut reader, &mut writer, |total| {
            progress.push(total);
        })).expect("copy_with_progress should succeed");

        prop_assert_eq!(copied, u64::try_from(data.len()).expect("usize fits into u64"));
        if data.is_empty() {
            prop_assert!(progress.is_empty());
        } else {
            prop_assert!(!progress.is_empty());
            for pair in progress.windows(2) {
                prop_assert!(pair[0] <= pair[1], "progress must be monotonic");
            }
            prop_assert_eq!(progress.last().copied(), Some(copied));
        }
        prop_assert_eq!(writer.snapshot(), data);
    }

    #[test]
    fn mr_copy_drop_preserves_written_prefix(
        data in proptest::collection::vec(any::<u8>(), 64..1024),
        read_chunk in 1_usize..32,
        write_chunk in 1_usize..32,
        pending_every in 2_usize..6,
        poll_budget in 1_usize..24,
    ) {
        let mut reader = PartialReader::new(data.clone(), read_chunk, Some(pending_every));
        let mut writer = PartialWriter::new(write_chunk, None, Some(pending_every));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(copy(&mut reader, &mut writer));
        let mut completed = false;

        for _ in 0..poll_budget {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(result) => {
                    let copied = result.expect("copy should not fail");
                    prop_assert_eq!(copied, u64::try_from(data.len()).expect("usize fits into u64"));
                    completed = true;
                    break;
                }
                Poll::Pending => {}
            }
        }

        drop(future);
        let prefix_after_drop = writer.snapshot();
        let prefix_len = prefix_after_drop.len();

        prop_assert_eq!(prefix_after_drop, data[..prefix_len].to_vec());
        if completed {
            prop_assert_eq!(prefix_len, data.len());
        }
    }

    #[test]
    fn mr_copy_respects_writer_limit(
        (data, read_chunk, write_chunk, _, limit) in arb_case(),
        pending in prop::option::of(2_usize..6),
    ) {
        prop_assume!(limit.is_some());
        let limit = limit.expect("prop_assume ensures limit is present");
        let mut reader = PartialReader::new(data.clone(), read_chunk, pending);
        let mut writer = PartialWriter::new(write_chunk, Some(limit), pending);

        let error = block_on(copy(&mut reader, &mut writer)).expect_err("copy should stop at the writer limit");
        prop_assert_eq!(error.kind(), io::ErrorKind::Other);
        prop_assert!(error.to_string().contains("limit exceeded"));
        prop_assert_eq!(writer.snapshot(), data[..limit].to_vec());
    }

    #[test]
    fn mr_buffered_and_unbuffered_copy_match(
        (data, read_chunk, write_chunk, buffer_size, _) in arb_case(),
        pending in prop::option::of(2_usize..6),
    ) {
        let mut unbuffered_reader = PartialReader::new(data.clone(), read_chunk, pending);
        let mut unbuffered_writer = PartialWriter::new(write_chunk, None, pending);
        let unbuffered = block_on(copy(&mut unbuffered_reader, &mut unbuffered_writer))
            .expect("unbuffered copy should succeed");

        let mut buffered_reader = BufReader::with_capacity(
            buffer_size,
            PartialReader::new(data.clone(), read_chunk, pending),
        );
        let mut buffered_writer = BufWriter::with_capacity(
            buffer_size,
            PartialWriter::new(write_chunk, None, pending),
        );
        let buffered = block_on(copy_buf(&mut buffered_reader, &mut buffered_writer))
            .expect("buffered copy should succeed");
        block_on(buffered_writer.flush()).expect("buf writer flush should succeed");

        prop_assert_eq!(unbuffered, buffered);
        prop_assert_eq!(unbuffered_writer.snapshot(), data.clone());
        prop_assert_eq!(buffered_writer.get_ref().snapshot(), data);
    }
}

#[test]
fn unit_limit_is_applied_before_append() {
    let mut writer = PartialWriter::new(8, Some(3), None);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    match Pin::new(&mut writer).poll_write(&mut cx, b"abcdef") {
        Poll::Ready(Ok(count)) => assert_eq!(count, 3),
        outcome => panic!("unexpected first poll outcome: {outcome:?}"),
    }

    match Pin::new(&mut writer).poll_write(&mut cx, b"z") {
        Poll::Ready(Err(err)) => assert!(err.to_string().contains("limit exceeded")),
        outcome => panic!("unexpected second poll outcome: {outcome:?}"),
    }

    assert_eq!(writer.snapshot(), b"abc");
}
