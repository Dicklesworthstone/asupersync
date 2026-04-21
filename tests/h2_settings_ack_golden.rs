#![allow(warnings)]
#![allow(clippy::all)]
//! Golden transcript for HTTP/2 SETTINGS and SETTINGS ACK exchanges.

use asupersync::bytes::BytesMut;
use asupersync::http::h2::frame::SettingsFrame;
use asupersync::http::h2::{Connection, Frame, Setting, Settings, SettingsBuilder};
use insta::assert_json_snapshot;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct SettingsAckGolden {
    scenarios: Vec<SettingsAckScenario>,
}

#[derive(Debug, Serialize)]
struct SettingsAckScenario {
    name: &'static str,
    frames: Vec<SettingsAckFrame>,
}

#[derive(Debug, Serialize)]
struct SettingsAckFrame {
    direction: &'static str,
    frame_type: &'static str,
    ack: bool,
    stream_id: String,
    settings: Vec<String>,
    encoded_bytes: Vec<u8>,
}

fn encode_frame(frame: &Frame) -> Vec<u8> {
    let mut buf = BytesMut::new();
    frame.encode(&mut buf);
    buf.to_vec()
}

fn scrub_stream_id(stream_id: u32) -> String {
    if stream_id == 0 {
        "<connection>".to_string()
    } else {
        stream_id.to_string()
    }
}

fn record_settings_frame(direction: &'static str, frame: Frame) -> SettingsAckFrame {
    let encoded_bytes = encode_frame(&frame);
    let stream_id = scrub_stream_id(frame.stream_id());
    match frame {
        Frame::Settings(settings) => SettingsAckFrame {
            direction,
            frame_type: "SETTINGS",
            ack: settings.ack,
            stream_id,
            settings: settings
                .settings
                .iter()
                .map(|setting| format!("{setting:?}"))
                .collect(),
            encoded_bytes,
        },
        other => panic!("expected SETTINGS frame, got {other:?}"),
    }
}

fn scenario_client_initial_settings() -> SettingsAckScenario {
    let mut conn = Connection::client(Settings::client());
    conn.queue_initial_settings();

    let first = conn
        .next_frame()
        .expect("client initial settings should queue a frame");

    SettingsAckScenario {
        name: "client_initial_settings",
        frames: vec![record_settings_frame("out", first)],
    }
}

fn scenario_server_acks_peer_settings() -> SettingsAckScenario {
    let mut conn = Connection::server(Settings::server());
    let incoming = Frame::Settings(SettingsFrame::new(vec![
        Setting::MaxConcurrentStreams(50),
        Setting::InitialWindowSize(32_768),
    ]));

    conn.process_frame(incoming.clone())
        .expect("server should accept peer settings");
    let ack = conn
        .next_frame()
        .expect("peer settings should enqueue an ACK");

    SettingsAckScenario {
        name: "server_acks_peer_settings",
        frames: vec![
            record_settings_frame("in", incoming),
            record_settings_frame("out", ack),
        ],
    }
}

fn scenario_client_requeues_settings_after_ack() -> SettingsAckScenario {
    let settings = SettingsBuilder::client()
        .header_table_size(8_192)
        .max_frame_size(32_768)
        .max_header_list_size(131_072)
        .build();
    let mut conn = Connection::client(settings);
    conn.queue_initial_settings();

    let first = conn
        .next_frame()
        .expect("first local settings frame should be queued");
    let ack = Frame::Settings(SettingsFrame::ack());
    conn.process_frame(ack.clone())
        .expect("receiving SETTINGS ACK should be a no-op");

    conn.queue_initial_settings();
    let second = conn
        .next_frame()
        .expect("connection should allow sending settings again after ACK");

    SettingsAckScenario {
        name: "client_requeues_settings_after_ack",
        frames: vec![
            record_settings_frame("out", first),
            record_settings_frame("in", ack),
            record_settings_frame("out", second),
        ],
    }
}

#[test]
fn h2_settings_ack_transcript() {
    let golden = SettingsAckGolden {
        scenarios: vec![
            scenario_client_initial_settings(),
            scenario_server_acks_peer_settings(),
            scenario_client_requeues_settings_after_ack(),
        ],
    };

    assert_json_snapshot!("h2_settings_ack_transcript", golden);
}
