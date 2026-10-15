//! `io::ext::AsyncBufReadExt`: `fill_buf`/`consume`, `read_until`,
//! `read_line`, `lines` and `split` over a `BufReader` on a real socket whose
//! data arrives in small, delayed pieces, so every method crosses buffer
//! refills and pending reads.

use asupersync::io::ext::AsyncBufReadExt;
use asupersync::io::{AsyncWriteExt, BufReader};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, yield_now};
use asupersync::stream::StreamExt;

/// A connected pair whose writer sends `data` in `chunk`-byte pieces with
/// yields between them, then closes.
async fn trickled(
    handle: &asupersync::runtime::RuntimeHandle,
    data: &'static [u8],
    chunk: usize,
) -> TcpStream {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let mut client = TcpStream::connect(address).await.expect("connect");
    let (server, _) = listener.accept().await.expect("accept");
    drop(handle.spawn(async move {
        for piece in data.chunks(chunk) {
            client.write_all(piece).await.expect("write");
            for _ in 0..3 {
                yield_now().await;
            }
        }
    }));
    server
}

#[test]
fn buffered_read_helpers_cross_refills_and_pending_reads() {
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    let handle = runtime.handle();
    runtime.block_on(async move {
        // read_until + fill_buf/consume + read_line on one reader.
        let stream = trickled(&handle, b"HEADER\0binary-ish\nsecond line\r\nrest", 3).await;
        let mut reader = BufReader::with_capacity(4, stream);
        let mut header = Vec::new();
        assert_eq!(
            reader.read_until(b'\0', &mut header).await.expect("until"),
            7
        );
        assert_eq!(header, b"HEADER\0");

        let peeked = reader.fill_buf().await.expect("fill").to_vec();
        assert!(!peeked.is_empty() && b"binary-ish\n".starts_with(&peeked));
        reader.consume(peeked.len());
        let mut rest_of_line = Vec::new();
        reader
            .read_until(b'\n', &mut rest_of_line)
            .await
            .expect("until newline");
        assert_eq!([peeked, rest_of_line].concat(), b"binary-ish\n");

        let mut line = String::new();
        assert_eq!(reader.read_line(&mut line).await.expect("line"), 13);
        assert_eq!(line, "second line\n", "read_line normalises \\r\\n");
        let mut tail = Vec::new();
        assert_eq!(reader.read_until(b'\n', &mut tail).await.expect("tail"), 4);
        assert_eq!(tail, b"rest", "end-of-stream ends the last segment");
        assert_eq!(reader.read_until(b'\n', &mut tail).await.expect("eof"), 0);
        assert!(reader.fill_buf().await.expect("fill at eof").is_empty());

        // lines
        let stream = trickled(&handle, b"alpha\nbeta\r\n\ngamma", 2).await;
        let lines: Vec<String> = BufReader::new(stream)
            .lines()
            .map(|line| line.expect("line"))
            .collect()
            .await;
        assert_eq!(lines, ["alpha", "beta", "", "gamma"]);

        // split
        let stream = trickled(&handle, b"a,bb,,ccc,", 1).await;
        let segments: Vec<Vec<u8>> = BufReader::with_capacity(2, stream)
            .split(b',')
            .map(|segment| segment.expect("segment"))
            .collect()
            .await;
        assert_eq!(segments, [&b"a"[..], b"bb", b"", b"ccc"]);
    });
}

#[test]
fn split_over_an_in_memory_reader_yields_a_final_unterminated_segment() {
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    runtime.block_on(async {
        // `[u8]::split` is an inherent method and wins `.split` on a slice;
        // the trait method is called by its path.
        let segments: Vec<Vec<u8>> = AsyncBufReadExt::split(&b"x|y|z"[..], b'|')
            .map(|segment| segment.expect("segment"))
            .collect()
            .await;
        assert_eq!(segments, [&b"x"[..], b"y", b"z"]);
        let empty: Vec<_> = AsyncBufReadExt::split(&b""[..], b'|').collect().await;
        assert!(empty.is_empty());
    });
}

/// Reports end of input once, then stays pending, like a stdin or a blocking
/// file read whose next read is handed to a thread.
struct EofThenPending {
    reads: usize,
}

impl asupersync::io::AsyncRead for EofThenPending {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut asupersync::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.reads += 1;
        if self.reads == 1 {
            std::task::Poll::Ready(Ok(()))
        } else {
            std::task::Poll::Pending
        }
    }
}

/// `fill_buf` answers end of input from the fill that saw it. It used to fill
/// a second time to borrow the bytes for its own lifetime, which started a new
/// read; when that read was pending, the next poll panicked with "FillBuf
/// polled after completion" (br-asupersync-68jvck).
#[test]
fn fill_buf_at_end_of_input_does_not_read_again() {
    let mut reader = BufReader::new(EofThenPending { reads: 0 });
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    {
        let mut fill = std::pin::pin!(reader.fill_buf());
        match fill.as_mut().poll(&mut context) {
            std::task::Poll::Ready(Ok(bytes)) => {
                assert!(bytes.is_empty(), "end of input is empty");
            }
            std::task::Poll::Ready(Err(error)) => panic!("fill_buf failed: {error}"),
            std::task::Poll::Pending => {
                panic!("fill_buf started another read after end of input")
            }
        }
    }
    assert_eq!(reader.get_ref().reads, 1, "one read reached the source");
}

/// Always ready: each read returns one byte with no delimiter, until `left`
/// runs out.
struct Dribble {
    left: usize,
}

impl asupersync::io::AsyncRead for Dribble {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut asupersync::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.left > 0 && buf.remaining() > 0 {
            self.left -= 1;
            buf.put_slice(b"x");
        }
        std::task::Poll::Ready(Ok(()))
    }
}

/// `read_until` and `split` yield after a bounded number of refills, as
/// `read_line` and `lines` do. Over a source that is always ready they used
/// to loop until the delimiter or end of input, holding the worker so that a
/// surrounding timeout could not fire (br-asupersync-68jvck).
#[test]
fn read_until_and_split_yield_on_an_always_ready_source() {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());

    let mut reader = BufReader::with_capacity(1, Dribble { left: 1_000 });
    let mut line = Vec::new();
    {
        let mut read = std::pin::pin!(reader.read_until(b'\n', &mut line));
        assert!(
            read.as_mut().poll(&mut context).is_pending(),
            "read_until yields before consuming 1000 ready refills"
        );
    }
    assert!(
        !line.is_empty() && line.len() < 1_000,
        "{} bytes",
        line.len()
    );

    let mut segments = BufReader::with_capacity(1, Dribble { left: 1_000 }).split(b'\n');
    assert!(
        asupersync::stream::Stream::poll_next(std::pin::Pin::new(&mut segments), &mut context)
            .is_pending(),
        "split yields before consuming 1000 ready refills"
    );
}
