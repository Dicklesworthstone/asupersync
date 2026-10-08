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
