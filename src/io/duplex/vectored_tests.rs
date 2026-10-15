#![allow(clippy::pedantic, clippy::nursery)]

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Wake;

fn write_vectored(stream: &mut DuplexStream, buffers: &[IoSlice<'_>]) -> usize {
    match AsyncWrite::poll_write_vectored(
        Pin::new(stream), &mut Context::from_waker(Waker::noop()), buffers,
    ) {
        Poll::Ready(Ok(count)) => count,
        other => panic!("expected an immediate vectored write: {other:?}"),
    }
}

fn read_vectored(stream: &mut DuplexStream, buffers: &mut [IoSliceMut<'_>]) -> usize {
    match AsyncReadVectored::poll_read_vectored(
        Pin::new(stream), &mut Context::from_waker(Waker::noop()), buffers,
    ) {
        Poll::Ready(Ok(count)) => count,
        other => panic!("expected an immediate vectored read: {other:?}"),
    }
}

fn read_bytes(stream: &mut DuplexStream, capacity: usize) -> Vec<u8> {
    let mut bytes = vec![0; capacity];
    let mut buffer = ReadBuf::new(&mut bytes);
    assert!(matches!(
        Pin::new(stream).poll_read(&mut Context::from_waker(Waker::noop()), &mut buffer),
        Poll::Ready(Ok(()))
    ));
    buffer.filled().to_vec()
}

#[test]
fn vectored_write_preserves_the_exact_prefix_at_every_capacity_boundary() {
    for capacity in 0..=20 {
        let (mut writer, mut reader) = duplex(capacity);
        let buffers = [
            IoSlice::new(b""), IoSlice::new(b"HEAD"), IoSlice::new(b""),
            IoSlice::new(b"payload"), IoSlice::new(b"TAIL"),
        ];
        assert!(AsyncWrite::is_write_vectored(&writer));
        let count = write_vectored(&mut writer, &buffers);
        let expected = capacity.clamp(1, 15);
        assert_eq!(count, expected, "capacity={capacity}");
        assert_eq!(read_bytes(&mut reader, 32), b"HEADpayloadTAIL"[..expected]);
        assert!(writer.write.lock().buffer.is_empty());
    }
}

#[test]
fn vectored_read_spans_destinations_without_replacing_descriptors_or_touching_the_tail() {
    let payload: Vec<u8> = (0..19).collect();
    for available in 0..=19 {
        let (mut writer, mut reader) = duplex(32);
        assert_eq!(write_vectored(&mut writer, &[IoSlice::new(&payload[..available])]), available);
        assert!(matches!(
            Pin::new(&mut writer).poll_shutdown(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
        let mut first = [0xA5; 4];
        let mut second = [0xA5; 7];
        let mut third = [0xA5; 4];
        let count = {
            let mut buffers = [
                IoSliceMut::new(&mut []), IoSliceMut::new(&mut first),
                IoSliceMut::new(&mut []), IoSliceMut::new(&mut second),
                IoSliceMut::new(&mut third),
            ];
            let descriptors: Vec<_> = buffers.iter().map(|b| (b.as_ptr(), b.len())).collect();
            let count = read_vectored(&mut reader, &mut buffers);
            assert_eq!(
                buffers.iter().map(|b| (b.as_ptr(), b.len())).collect::<Vec<_>>(),
                descriptors
            );
            count
        };
        assert_eq!(count, available.min(15));
        let result = [first.as_slice(), second.as_slice(), third.as_slice()].concat();
        assert_eq!(&result[..count], &payload[..count]);
        assert!(result[count..].iter().all(|byte| *byte == 0xA5));
        assert_eq!(read_bytes(&mut reader, 32), payload[count..available]);
    }
}

struct Count(AtomicUsize);

impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn vectored_backpressure_and_scalar_reads_share_one_byte_cursor_and_waiter() {
    let (mut writer, mut reader) = duplex(3);
    assert_eq!(write_vectored(&mut writer, &[IoSlice::new(b"ab"), IoSlice::new(b"cd")]), 3);
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&count));
    let pending = [IoSlice::new(b"d"), IoSlice::new(b"ef")];
    assert!(AsyncWrite::poll_write_vectored(
        Pin::new(&mut writer), &mut Context::from_waker(&waker), &pending,
    ).is_pending());
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    let mut first = [0; 1];
    let mut second = [0; 1];
    assert_eq!(read_vectored(&mut reader, &mut [
        IoSliceMut::new(&mut first), IoSliceMut::new(&mut second),
    ]), 2);
    assert_eq!([first[0], second[0]], *b"ab");
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert_eq!(write_vectored(&mut writer, &pending), 2);
    assert_eq!(read_bytes(&mut reader, 8), b"cde");
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
}

#[test]
fn vectored_reads_cross_the_ring_wrap_without_reordering_or_replaying_bytes() {
    let (mut writer, mut reader) = duplex(8);
    reader.read.lock().buffer = VecDeque::with_capacity(8);
    assert_eq!(write_vectored(&mut writer, &[IoSlice::new(b"abcdefgh")]), 8);
    assert_eq!(read_bytes(&mut reader, 6), b"abcdef");
    assert_eq!(write_vectored(&mut writer, &[IoSlice::new(b"ijk"), IoSlice::new(b"lmn")]), 6);
    assert!(!reader.read.lock().buffer.as_slices().1.is_empty(), "reached wrapped storage");
    let mut a = [0; 3];
    let mut b = [0; 2];
    let mut c = [0; 3];
    assert_eq!(read_vectored(&mut reader, &mut [
        IoSliceMut::new(&mut a), IoSliceMut::new(&mut b), IoSliceMut::new(&mut c),
    ]), 8);
    assert_eq!([a.as_slice(), b.as_slice(), c.as_slice()].concat(), b"ghijklmn");
    assert!(reader.read.lock().buffer.is_empty());
}

#[test]
fn descriptor_windows_make_positive_progress_past_long_empty_prefixes() {
    let (mut writer, mut reader) = duplex(64);
    let mut source = vec![IoSlice::new(b""); 4096];
    source.extend((0..32).map(|_| IoSlice::new(b"x")));
    assert_eq!(write_vectored(&mut writer, &source), MAX_VECTORED_BUFFERS);
    assert_eq!(write_vectored(&mut writer, &source[4096 + MAX_VECTORED_BUFFERS..]), 16);

    let mut bytes = [0xA5; 32];
    {
        let mut destinations: Vec<_> = (0..4096).map(|_| IoSliceMut::new(&mut [])).collect();
        destinations.extend(bytes.chunks_mut(1).map(IoSliceMut::new));
        assert_eq!(read_vectored(&mut reader, &mut destinations), MAX_VECTORED_BUFFERS);
    }
    assert_eq!(&bytes[..16], &[b'x'; 16]);
    assert_eq!(&bytes[16..], &[0xA5; 16]);
    assert_eq!(read_bytes(&mut reader, 32), &[b'x'; 16]);
}

#[test]
fn empty_vectored_operations_are_noops_but_nonempty_closed_writes_fail() {
    let (mut a, b) = duplex(1);
    assert_eq!(read_vectored(&mut a, &mut []), 0);
    assert_eq!(read_vectored(&mut a, &mut [IoSliceMut::new(&mut [])]), 0);
    assert!(a.read.lock().read_waker.is_none());
    assert_eq!(write_vectored(&mut a, &[]), 0);
    assert_eq!(write_vectored(&mut a, &[IoSlice::new(b"")]), 0);
    drop(b);
    assert_eq!(write_vectored(&mut a, &[IoSlice::new(b"")]), 0);
    assert!(matches!(AsyncWrite::poll_write_vectored(
        Pin::new(&mut a), &mut Context::from_waker(Waker::noop()), &[IoSlice::new(b"x")],
    ), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe));
    let mut bytes = [0xA5; 2];
    assert_eq!(read_vectored(&mut a, &mut [IoSliceMut::new(&mut bytes)]), 0);
    assert_eq!(bytes, [0xA5; 2]);
}

#[test]
fn native_vectored_sessions_resume_dropped_waits_over_the_real_duplex_transport() {
    use crate::cx::Cx;
    use crate::io::transfer_session::{ReadExactVectoredSession, WriteAllVectoredSession};
    use crate::runtime::RuntimeBuilder;
    use std::future::Future;

    crate::test_utils::init_test_logging();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().expect("native runtime context");
        let (mut writer, mut reader) = duplex(2);
        let sources = [IoSlice::new(b"HEAD"), IoSlice::new(b"payload")];
        let mut header = [0; 4];
        let mut body = [0; 7];
        {
            let mut destinations = [IoSliceMut::new(&mut header), IoSliceMut::new(&mut body)];
            let mut send = WriteAllVectoredSession::new(&mut writer, &sources).unwrap();
            let mut receive = ReadExactVectoredSession::new(&mut reader, &mut destinations).unwrap();
            {
                let mut attempt = std::pin::pin!(send.run(&cx));
                assert!(attempt.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            }
            assert_eq!(send.bytes_written(), 2, "writer reached full-pipe suspension");
            {
                let mut attempt = std::pin::pin!(receive.run(&cx));
                assert!(attempt.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
            }
            assert_eq!(receive.bytes_read(), 2, "reader reached empty-pipe suspension");
            let (sent, received) = futures_lite::future::zip(send.run(&cx), receive.run(&cx)).await;
            assert_eq!(sent.unwrap(), 11);
            assert_eq!(received.unwrap(), 11);
            assert!(send.is_complete());
            assert!(receive.is_complete());
            assert!(!send.is_poisoned());
            assert!(!receive.is_poisoned());
        }
        assert_eq!(header, *b"HEAD");
        assert_eq!(body, *b"payload");
        assert!(writer.write.lock().buffer.is_empty());
        assert!(matches!(
            Pin::new(&mut writer).poll_shutdown(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
        assert!(read_bytes(&mut reader, 1).is_empty(), "no duplicated suffix");
    });
}
