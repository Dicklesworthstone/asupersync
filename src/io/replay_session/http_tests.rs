//! Execute the existing HTTP client, not a parallel parser or a protocol mock.
//! Only the byte transport is scripted; no real socket/OS-conformance claim.

use super::tests::drive;
use super::*;
use crate::http::h1::{Http1Client, HttpError, Method, Request, Response, Version};
use crate::io::replay::IoTapeDecodeLimits;
use crate::io::{AsyncRead, ReadBuf};
use crate::time::VirtualClock;
use crate::time::replay::TimeTapeDecodeLimits;
use crate::util::DetEntropy;
use crate::util::entropy_replay::EntropyTapeDecodeLimits;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Context;

struct HttpTransport {
    response: &'static [u8],
    offset: usize,
    writes: Vec<u8>,
    pause_read: bool,
    pause_write: bool,
    calls: Arc<AtomicUsize>,
}

impl HttpTransport {
    fn new(response: &'static [u8]) -> Self {
        Self {
            response,
            offset: 0,
            writes: Vec::new(),
            pause_read: true,
            pause_write: true,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl AsyncRead for HttpTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.calls.fetch_add(1, Ordering::Relaxed);
        if this.pause_read {
            this.pause_read = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.pause_read = true;
        let count = buf.remaining().min(5).min(this.response.len() - this.offset);
        buf.put_slice(&this.response[this.offset..this.offset + count]);
        this.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for HttpTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.calls.fetch_add(1, Ordering::Relaxed);
        if this.pause_write {
            this.pause_write = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.pause_write = true;
        let count = bytes.len().min(7);
        this.writes.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

fn request<'a, I, E, C>(
    io: &'a mut I,
    entropy: &'a E,
    clock: &'a C,
    path: &'static str,
) -> ReplayConsumerFuture<'a, Result<Response, HttpError>>
where
    I: AsyncRead + AsyncWrite + Unpin,
    E: EntropySource + ?Sized,
    C: TimeSource + ?Sized,
{
    Box::pin(async move {
        let req = Request {
            method: Method::Get,
            uri: path.to_owned(),
            version: Version::Http11,
            headers: vec![
                ("Host".to_owned(), "replay.invalid".to_owned()),
                ("X-Nonce".to_owned(), format!("{:016x}", entropy.next_u64())),
                ("X-Time".to_owned(), clock.now().as_nanos().to_string()),
            ],
            body: Vec::new(),
            trailers: Vec::new(),
            peer_addr: None,
        };
        Http1Client::request_with_io_and_max_body_size(io, req, 1024)
            .await
            .map(|(response, _, _)| response)
    })
}

fn capture_http(
    response: &'static [u8],
) -> (RecordedSession, Result<Response, HttpError>, Arc<AtomicUsize>) {
    let transport = HttpTransport::new(response);
    let calls = Arc::clone(&transport.calls);
    let mut capture = RecordingSession::new(
        transport,
        Arc::new(DetEntropy::new(42)),
        Arc::new(VirtualClock::new()),
        SessionCaptureLimits {
            io: IoCaptureLimits::new(1000, 4096, 65_536, 8),
            entropy: EntropyCaptureLimits::new(8, 64, 1),
            clock_observations: 8,
        },
    )
    .unwrap();
    let entropy = capture.entropy();
    let clock = capture.clock();
    let result = drive(request(capture.io(), entropy.as_ref(), clock.as_ref(), "/resource"));
    let (transport, session) = capture.into_parts();
    assert!(transport.writes.starts_with(b"GET /resource HTTP/1.1\r\n"));
    assert!(transport.writes.windows(7).any(|part| part == b"X-Nonce"));
    drop(transport);
    drop(entropy);
    drop(clock);
    (session.unwrap(), result, calls)
}

fn restore(session: RecordedSession) -> ReplaySession {
    let bytes = session.to_canonical_bytes(1_048_576).unwrap();
    drop(session);
    let restored = RecordedSession::from_canonical_bytes(
        bytes.as_ref(),
        SessionDecodeLimits {
            max_encoded_bytes: 1_048_576,
            io: IoTapeDecodeLimits::new(
                1_048_576, IoCaptureLimits::new(1000, 4096, 65_536, 8), 1_048_576,
            ),
            entropy: EntropyTapeDecodeLimits::new(1024, EntropyCaptureLimits::new(8, 64, 1), 4096),
            clock: TimeTapeDecodeLimits::new(1024, 8, 64),
        },
    )
    .unwrap();
    drop(bytes);
    restored.replay()
}

#[test]
fn real_http_client_chunked_body_and_trailers_replay_after_all_sources_are_gone() {
    let (session, original, calls) = capture_http(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nyes\r\n0\r\nX-Replay: kept\r\n\r\n",
    );
    let original = original.unwrap();
    assert_eq!(original.status, 200);
    assert_eq!(original.body, b"yes");
    assert!(original.trailers.iter().any(|(name, value)| name.eq_ignore_ascii_case("x-replay") && value == "kept"));
    let polls_before = calls.load(Ordering::Relaxed);
    let response = drive(restore(session).run(1000, |p| request(p.io, p.entropy, p.clock, "/resource")))
        .unwrap().unwrap();
    assert_eq!(response.status, original.status);
    assert_eq!(response.headers, original.headers);
    assert_eq!(response.body, original.body);
    assert_eq!(response.trailers, original.trailers);
    assert_eq!(calls.load(Ordering::Relaxed), polls_before);
}

#[test]
fn real_http_client_malformed_framing_reproduces_the_original_parser_error() {
    let (session, original, _) = capture_http(
        b"HTTP/1.1 200 OK\r\nContent-Length: +3\r\n\r\nyes",
    );
    assert!(matches!(original, Err(HttpError::BadContentLength)));
    let result = drive(restore(session).run(1000, |p| request(p.io, p.entropy, p.clock, "/resource")))
        .unwrap();
    assert!(matches!(result, Err(HttpError::BadContentLength)));
}

#[test]
fn real_http_client_different_request_cannot_be_accepted_as_recorded_network_error() {
    let (session, original, _) = capture_http(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nyes");
    assert_eq!(original.unwrap().body, b"yes");
    let error = drive(restore(session).run(1000, |p| request(p.io, p.entropy, p.clock, "/modified")))
        .unwrap_err();
    // The HTTP client reports an I/O error, but the session rejects its output:
    // it was manufactured by divergence, not an error observed in production.
    assert!(matches!(error, SessionRunError::Replay(SessionReplayError {
        io: Some(IoReplayCompletionError::Diverged(_)), ..
    })));
}
