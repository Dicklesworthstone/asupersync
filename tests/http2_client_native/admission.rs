//! Active HTTP/2 admission spans native setup, response ownership, and reuse.

use super::*;
use std::num::NonZeroUsize;
use std::task::Poll;

#[test]
fn queued_native_request_deadline_never_dials_and_dropped_owner_releases_capacity() {
    for workers in [1, 2] {
        // This peer never answers the first request. Its live future must keep
        // the only admission slot even while the caller drives another request.
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let silent_address = silent.local_addr().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let runtime = runtime(workers);
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            let client = Http2Client::new()
                .timeout(Duration::from_secs(5))
                .max_concurrent_requests(NonZeroUsize::new(1).unwrap());
            let mut first = Box::pin(
                client
                    .post(format!("http://{silent_address}/held"))
                    .send(&cx),
            );
            poll_fn(|task| {
                assert!(first.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;

            let result = client
                .clone()
                .post(format!("http://{address}/queued"))
                .timeout(Duration::from_millis(50))
                .send(&cx)
                .await;
            assert!(matches!(result, Err(Http2ClientError::DeadlineExceeded)));
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "admission must precede opening a native connection"
            );
            assert!(cx.checkpoint().is_ok());

            // A timed-out waiter must not release the first request's slot.
            let again = client
                .post(format!("http://{address}/still-queued"))
                .timeout(Duration::from_millis(50))
                .send(&cx)
                .await;
            assert!(matches!(again, Err(Http2ClientError::DeadlineExceeded)));
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );

            drop(first);
            listener.set_nonblocking(false).unwrap();
            let peer = std::thread::spawn(move || {
                let mut peer = Peer::accept(listener, 65_535);
                let stream = peer.request();
                peer.connection
                    .send_headers(stream, vec![Header::new(":status", "204")], true)
                    .unwrap();
                peer.flush();
                peer.eof();
            });
            let response = client
                .post(format!("http://{address}/after-drop"))
                .send(&cx)
                .await
                .expect("dropping the active request must release capacity");
            assert_eq!(response.status, 204);
            peer.join().unwrap();
            drop(silent);
        });
        quiescent(&runtime);
    }
}

#[cfg(feature = "http2-streaming")]
#[test]
fn streaming_body_retains_admission_until_eof_and_hands_off_its_pooled_connection() {
    use asupersync::bytes::Buf;
    use asupersync::http::body::Body;
    use std::pin::Pin;

    for workers in [1, 2] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let mut peer = Peer::accept(listener, 65_535);
            let mut previous = 0;
            for _ in 0..2 {
                let stream = peer.request();
                assert!(stream > previous, "the admitted waiter must reuse the socket");
                previous = stream;
                peer.connection
                    .send_headers(
                        stream,
                        vec![
                            Header::new(":status", "200"),
                            Header::new("content-length", "3"),
                        ],
                        false,
                    )
                    .unwrap();
                peer.connection
                    .send_data(stream, Bytes::from_static(b"abc"), true)
                    .unwrap();
                peer.flush();
            }
            peer.eof();
        });
        let runtime = runtime(workers);
        runtime.block_on(async move {
            let cx = Cx::current().unwrap();
            let client = Http2Client::new()
                .timeout(Duration::from_secs(5))
                .reuse_connections_bounded(1, 1)
                .max_concurrent_requests(NonZeroUsize::new(1).unwrap());
            let mut first = client
                .post(format!("http://{address}/stream"))
                .send_streaming(&cx)
                .await
                .unwrap();
            assert_eq!(first.status, 200);
            let mut queued = Box::pin(
                client
                    .clone()
                    .post(format!("http://{address}/next"))
                    .send(&cx),
            );
            poll_fn(|task| {
                assert!(
                    queued.as_mut().poll(task).is_pending(),
                    "response headers must not release the streaming slot"
                );
                Poll::Ready(())
            })
            .await;

            let mut body = Vec::new();
            while let Some(frame) =
                poll_fn(|task| Pin::new(&mut first.body).poll_frame(task)).await
            {
                let mut data = frame.unwrap().into_data().expect("DATA only");
                let length = data.remaining();
                body.extend_from_slice(&data.copy_to_bytes(length));
            }
            assert_eq!(body, b"abc");
            let next = queued
                .await
                .expect("EOF must release admission after returning the idle socket");
            assert_eq!(next.status, 200);
            assert_eq!(next.body.as_ref(), b"abc");
            assert!(first.body.is_end_stream());
            assert_eq!(client.close_idle_connections(), 1);
        });
        peer.join().unwrap();
        quiescent(&runtime);
    }
}
