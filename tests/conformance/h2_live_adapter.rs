//! Shared HTTP/2 conformance adapter over the production Connection/Frame seams.
//!
//! This module gives H2 conformance tests one place to initialize a real
//! connection, feed real frames, and inspect observable state without rebuilding
//! local simulation models in each frame-specific test.

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{
    connection::{Connection, ConnectionState, ReceivedFrame},
    error::ErrorCode,
    frame::{
        DataFrame, Frame, FrameHeader, FrameType, GoAwayFrame, HeadersFrame, PingFrame,
        PriorityFrame, PrioritySpec, SettingsFrame, parse_frame,
    },
    hpack::{Encoder as HpackEncoder, Header},
    settings::Settings,
};

#[derive(Debug)]
pub(crate) struct H2LiveAdapter {
    connection: Connection,
}

impl H2LiveAdapter {
    pub(crate) fn client() -> Result<Self, String> {
        let mut adapter = Self {
            connection: Connection::client(Settings::client()),
        };
        adapter.accept_peer_settings()?;
        Ok(adapter)
    }

    pub(crate) fn server() -> Result<Self, String> {
        let mut adapter = Self {
            connection: Connection::server(Settings::default()),
        };
        adapter.accept_peer_settings()?;
        Ok(adapter)
    }

    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }

    pub(crate) fn feed(&mut self, frame: Frame) -> Result<Option<ReceivedFrame>, String> {
        self.connection
            .process_frame(frame)
            .map_err(|err| err.to_string())
    }

    pub(crate) fn drain_pending(&mut self) -> Vec<Frame> {
        let mut frames = Vec::new();
        while self.connection.has_pending_frames() {
            let Some(frame) = self.connection.next_frame() else {
                break;
            };
            frames.push(frame);
        }
        frames
    }

    pub(crate) fn open_stream(&mut self, path: &str, end_stream: bool) -> Result<u32, String> {
        self.connection
            .open_stream(request_headers(path), end_stream)
            .map_err(|err| err.to_string())
    }

    pub(crate) fn parse_encoded(frame: &Frame) -> Result<Frame, String> {
        let mut wire = BytesMut::new();
        frame.encode(&mut wire).map_err(|err| err.to_string())?;
        let header = FrameHeader::parse(&mut wire).map_err(|err| err.to_string())?;
        parse_frame(&header, wire.freeze()).map_err(|err| err.to_string())
    }

    fn accept_peer_settings(&mut self) -> Result<(), String> {
        let received = self.feed(Frame::Settings(SettingsFrame::new(vec![])))?;
        if received.is_some() {
            return Err(
                "SETTINGS handshake unexpectedly produced an application frame".to_string(),
            );
        }

        let pending = self.drain_pending();
        match pending.as_slice() {
            [Frame::Settings(settings)] if settings.ack => {}
            other => {
                return Err(format!(
                    "SETTINGS handshake should queue exactly one ACK, got {other:?}"
                ));
            }
        }

        if self.connection.state() != ConnectionState::Open {
            return Err(format!(
                "SETTINGS handshake should open the connection, got {:?}",
                self.connection.state()
            ));
        }

        Ok(())
    }
}

pub(crate) fn request_headers(path: &str) -> Vec<Header> {
    vec![
        Header::new(":method", "GET"),
        Header::new(":path", path),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.test"),
    ]
}

pub(crate) fn encoded_request_headers(path: &str) -> Bytes {
    let mut encoder = HpackEncoder::new();
    let mut encoded = BytesMut::new();
    encoder.encode(&request_headers(path), &mut encoded);
    encoded.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_initializes_settings_headers_and_data_end_stream() {
        let mut adapter = H2LiveAdapter::server().expect("server SETTINGS handshake");
        assert_eq!(adapter.connection().state(), ConnectionState::Open);

        let received = adapter
            .feed(Frame::Headers(HeadersFrame::new(
                1,
                encoded_request_headers("/adapter"),
                false,
                true,
            )))
            .expect("feed HEADERS");
        match received {
            Some(ReceivedFrame::Headers {
                stream_id,
                headers,
                end_stream,
            }) => {
                assert_eq!(stream_id, 1);
                assert!(!end_stream);
                assert!(
                    headers
                        .iter()
                        .any(|header| header.name == ":path" && header.value == "/adapter")
                );
            }
            other => panic!("expected received HEADERS, got {other:?}"),
        }
        assert!(
            !adapter
                .connection()
                .stream(1)
                .expect("stream opened by HEADERS")
                .state()
                .is_closed()
        );

        let received = adapter
            .feed(Frame::Data(DataFrame::new(
                1,
                Bytes::from_static(b"body"),
                true,
            )))
            .expect("feed DATA END_STREAM");
        match received {
            Some(ReceivedFrame::Data {
                stream_id,
                data,
                end_stream,
            }) => {
                assert_eq!(stream_id, 1);
                assert_eq!(data.as_ref(), b"body");
                assert!(end_stream);
            }
            other => panic!("expected received DATA, got {other:?}"),
        }
    }

    #[test]
    fn adapter_preserves_pending_order_and_ping_ack_semantics() {
        let mut adapter = H2LiveAdapter::client().expect("client SETTINGS handshake");
        let stream_id = adapter
            .open_stream("/queued-before-ping", false)
            .expect("open local stream");
        adapter
            .feed(Frame::Ping(PingFrame::new(*b"testping")))
            .expect("feed inbound PING");

        let pending = adapter.drain_pending();
        assert_eq!(pending.len(), 2, "HEADERS must remain ahead of PING ACK");
        match &pending[0] {
            Frame::Headers(headers) => assert_eq!(headers.stream_id, stream_id),
            other => panic!("expected queued HEADERS first, got {other:?}"),
        }
        match &pending[1] {
            Frame::Ping(ping) => {
                assert!(ping.ack);
                assert_eq!(ping.opaque_data, *b"testping");
            }
            other => panic!("expected queued PING ACK second, got {other:?}"),
        }

        adapter
            .feed(Frame::Ping(PingFrame::ack(*b"testping")))
            .expect("feed inbound PING ACK");
        assert!(
            adapter.drain_pending().is_empty(),
            "PING ACK frames must not be ACKed again"
        );
    }

    #[test]
    fn adapter_covers_goaway_priority_and_malformed_parse() {
        let mut client = H2LiveAdapter::client().expect("client SETTINGS handshake");
        let stream1 = client
            .open_stream("/kept-after-goaway", false)
            .expect("open stream 1");
        let stream3 = client
            .open_stream("/reset-after-goaway", false)
            .expect("open stream 3");
        assert_eq!((stream1, stream3), (1, 3));
        let _ = client.drain_pending();

        let mut goaway = GoAwayFrame::new(stream1, ErrorCode::NoError);
        goaway.debug_data = Bytes::from_static(b"drain");
        let received = client
            .feed(Frame::GoAway(goaway))
            .expect("feed peer GOAWAY");
        match received {
            Some(ReceivedFrame::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            }) => {
                assert_eq!(last_stream_id, stream1);
                assert_eq!(error_code, ErrorCode::NoError);
                assert_eq!(debug_data.as_ref(), b"drain");
            }
            other => panic!("expected received GOAWAY, got {other:?}"),
        }
        assert_eq!(client.connection().state(), ConnectionState::Closing);
        assert!(
            !client
                .connection()
                .stream(stream1)
                .expect("stream at GOAWAY boundary")
                .state()
                .is_closed()
        );
        assert!(
            client
                .connection()
                .stream(stream3)
                .expect("stream beyond GOAWAY boundary")
                .state()
                .is_closed()
        );

        let mut server = H2LiveAdapter::server().expect("server SETTINGS handshake");
        server
            .feed(Frame::Headers(HeadersFrame::new(
                1,
                encoded_request_headers("/priority"),
                false,
                true,
            )))
            .expect("feed stream HEADERS before PRIORITY");
        let priority = PrioritySpec {
            exclusive: true,
            dependency: 0,
            weight: 31,
        };
        server
            .feed(Frame::Priority(PriorityFrame {
                stream_id: 1,
                priority,
            }))
            .expect("feed PRIORITY");
        assert_eq!(
            *server
                .connection()
                .stream(1)
                .expect("stream priority target")
                .priority(),
            priority
        );

        let encoded_ping = H2LiveAdapter::parse_encoded(&Frame::Ping(PingFrame::new(*b"parseok!")))
            .expect("parse encoded PING through frame parser");
        match encoded_ping {
            Frame::Ping(ping) => assert_eq!(ping.opaque_data, *b"parseok!"),
            other => panic!("expected parsed PING, got {other:?}"),
        }

        let malformed_priority = FrameHeader {
            length: 4,
            frame_type: FrameType::Priority as u8,
            flags: 0,
            stream_id: 1,
        };
        assert!(
            parse_frame(&malformed_priority, Bytes::from_static(&[0, 0, 0, 0])).is_err(),
            "malformed PRIORITY payload must fail through the real parser"
        );
    }
}
