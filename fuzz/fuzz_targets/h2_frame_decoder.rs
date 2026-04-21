#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::{BufMut, Bytes, BytesMut};
use asupersync::codec::Decoder;
use asupersync::http::h2::error::ErrorCode;
use asupersync::http::h2::frame::{
    FrameHeader, FrameType, HeadersFrame, MAX_FRAME_SIZE, Setting, SettingsFrame, data_flags,
    ping_flags, settings_flags,
};
use asupersync::http::h2::{Connection, Frame, FrameCodec, Settings};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 4096;
const MAX_FRAMES: usize = 24;
const MAX_PAYLOAD_LEN: usize = 512;

#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    max_frame_size: u32,
    split_at: u16,
    frames: Vec<FrameSpec>,
    unknown_type: u8,
    unknown_flags: u8,
    unknown_payload: Vec<u8>,
    ping_seed: [u8; 8],
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum StreamTarget {
    Connection,
    Stream1,
    Stream3,
    Stream5,
}

impl StreamTarget {
    fn stream_id(self) -> u32 {
        match self {
            Self::Connection => 0,
            Self::Stream1 => 1,
            Self::Stream3 => 3,
            Self::Stream5 => 5,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum SettingsMode {
    Empty,
    Ack,
    AckWithPayload,
    EnablePush,
    InvalidEnablePush,
    InitialWindow,
    InvalidInitialWindow,
    MaxFrameSize,
    InvalidMaxFrameSize,
}

#[derive(Arbitrary, Debug, Clone)]
enum FrameSpec {
    Settings {
        mode: SettingsMode,
        value: u32,
    },
    WindowUpdate {
        target: StreamTarget,
        increment: u32,
    },
    Data {
        target: StreamTarget,
        end_stream: bool,
        padded: bool,
        pad_length: u8,
        payload: Vec<u8>,
        malformed_padding: bool,
    },
    Ping {
        ack: bool,
        invalid_stream: bool,
        declared_len: u8,
        payload: [u8; 8],
    },
    GoAway {
        invalid_stream: bool,
        last_stream_id: u32,
        error_code: u32,
        debug_data: Vec<u8>,
    },
    Unknown {
        frame_type: u8,
        flags: u8,
        target: StreamTarget,
        payload: Vec<u8>,
    },
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(input) = arbitrary::Unstructured::new(data).arbitrary::<FuzzInput>() {
        exercise_partial_decode(&input);
        exercise_unknown_passthrough(&input);
        exercise_sequence(&input);
    }
});

fn exercise_partial_decode(input: &FuzzInput) {
    let mut frame = BytesMut::new();
    Frame::Ping(asupersync::http::h2::frame::PingFrame::new(input.ping_seed)).encode(&mut frame);

    let split = usize::min(usize::from(input.split_at), frame.len().saturating_sub(1));
    let mut partial = BytesMut::from(&frame[..split]);
    let before = partial.clone();
    let mut codec = FrameCodec::new();
    codec.set_max_frame_size(normalize_max_frame_size(input.max_frame_size));

    assert!(
        codec
            .decode(&mut partial)
            .expect("partial decode should not error")
            .is_none(),
        "partial frame should remain pending"
    );
    assert_eq!(
        partial, before,
        "partial frame must not consume buffered bytes"
    );

    partial.extend_from_slice(&frame[split..]);
    match codec.decode(&mut partial) {
        Ok(Some(Frame::Ping(ping))) => assert_eq!(ping.opaque_data, input.ping_seed),
        Ok(Some(other)) => panic!("expected decoded PING frame, got {other:?}"),
        Ok(None) => panic!("completed frame must decode"),
        Err(err) => panic!("completed valid frame must not error: {err}"),
    }
    assert!(
        partial.is_empty(),
        "completed frame should drain the buffer"
    );
}

fn exercise_unknown_passthrough(input: &FuzzInput) {
    let mut stream = BytesMut::new();
    encode_unknown_frame(
        non_standard_type(input.unknown_type),
        input.unknown_flags,
        StreamTarget::Connection.stream_id(),
        truncate_bytes(&input.unknown_payload),
        &mut stream,
    );
    Frame::Ping(asupersync::http::h2::frame::PingFrame::new(input.ping_seed)).encode(&mut stream);

    let mut codec = FrameCodec::new();
    codec.set_max_frame_size(normalize_max_frame_size(input.max_frame_size));

    match codec.decode(&mut stream) {
        Ok(Some(Frame::Ping(ping))) => assert_eq!(ping.opaque_data, input.ping_seed),
        Ok(Some(other)) => panic!("expected PING after unknown frame skip, got {other:?}"),
        Ok(None) => panic!("unknown frame must not block following valid frame"),
        Err(err) => panic!("unknown frame passthrough must not error: {err}"),
    }
    assert!(stream.is_empty(), "unknown passthrough stream should drain");
}

fn exercise_sequence(input: &FuzzInput) {
    let mut stream = BytesMut::new();
    for spec in input.frames.iter().take(MAX_FRAMES) {
        encode_frame_spec(spec, &mut stream);
    }

    let mut codec = FrameCodec::new();
    codec.set_max_frame_size(normalize_max_frame_size(input.max_frame_size));
    let mut connection = setup_connection();
    let mut saw_goaway = false;

    loop {
        match codec.decode(&mut stream) {
            Ok(Some(frame)) => match connection.process_frame(frame) {
                Ok(_) => drain_frames(&mut connection),
                Err(err) => {
                    if err.is_connection_error() {
                        saw_goaway |= assert_goaway_on_error(&mut connection, err.code);
                    }
                    drain_frames(&mut connection);
                }
            },
            Ok(None) => break,
            Err(err) => {
                if err.is_connection_error() {
                    saw_goaway |= assert_goaway_on_error(&mut connection, err.code);
                }
                break;
            }
        }
    }

    assert!(
        !saw_goaway || connection.next_frame().is_none(),
        "GOAWAY verification should drain the pending queue"
    );
}

fn setup_connection() -> Connection {
    let mut connection = Connection::server(Settings::default());
    let _ = connection.process_frame(Frame::Settings(SettingsFrame::new(vec![])));
    let _ = connection.process_frame(Frame::Headers(HeadersFrame::new(
        1,
        Bytes::new(),
        false,
        true,
    )));
    drain_frames(&mut connection);
    connection
}

fn drain_frames(connection: &mut Connection) {
    while connection.next_frame().is_some() {}
}

fn assert_goaway_on_error(connection: &mut Connection, error_code: ErrorCode) -> bool {
    connection.goaway(error_code, Bytes::new());
    match connection.next_frame() {
        Some(Frame::GoAway(frame)) => {
            assert_eq!(frame.error_code, error_code);
            true
        }
        None => false,
        other => panic!("expected queued GOAWAY after connection error, got {other:?}"),
    }
}

fn normalize_max_frame_size(max_frame_size: u32) -> u32 {
    max_frame_size.clamp(16_384, MAX_FRAME_SIZE)
}

fn truncate_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().take(MAX_PAYLOAD_LEN).collect()
}

fn non_standard_type(frame_type: u8) -> u8 {
    if FrameType::from_u8(frame_type).is_some() {
        frame_type.wrapping_add(10)
    } else {
        frame_type
    }
}

fn encode_frame_spec(spec: &FrameSpec, dst: &mut BytesMut) {
    match spec {
        FrameSpec::Settings { mode, value } => encode_settings_frame(*mode, *value, dst),
        FrameSpec::WindowUpdate { target, increment } => {
            encode_window_update_frame(target.stream_id(), *increment, dst);
        }
        FrameSpec::Data {
            target,
            end_stream,
            padded,
            pad_length,
            payload,
            malformed_padding,
        } => encode_data_frame(
            target.stream_id(),
            *end_stream,
            *padded,
            *pad_length,
            payload,
            *malformed_padding,
            dst,
        ),
        FrameSpec::Ping {
            ack,
            invalid_stream,
            declared_len,
            payload,
        } => encode_ping_frame(*ack, *invalid_stream, *declared_len, payload, dst),
        FrameSpec::GoAway {
            invalid_stream,
            last_stream_id,
            error_code,
            debug_data,
        } => encode_goaway_frame(
            *invalid_stream,
            *last_stream_id,
            *error_code,
            debug_data,
            dst,
        ),
        FrameSpec::Unknown {
            frame_type,
            flags,
            target,
            payload,
        } => encode_unknown_frame(
            non_standard_type(*frame_type),
            *flags,
            target.stream_id(),
            truncate_bytes(payload),
            dst,
        ),
    }
}

fn encode_settings_frame(mode: SettingsMode, value: u32, dst: &mut BytesMut) {
    match mode {
        SettingsMode::Empty => Frame::Settings(SettingsFrame::new(vec![])).encode(dst),
        SettingsMode::Ack => Frame::Settings(SettingsFrame::ack()).encode(dst),
        SettingsMode::AckWithPayload => {
            let payload = setting_payload(Setting::MaxConcurrentStreams(value.max(1)));
            write_raw_frame(
                FrameType::Settings as u8,
                settings_flags::ACK,
                0,
                payload,
                dst,
            );
        }
        SettingsMode::EnablePush => {
            let payload = setting_payload(Setting::EnablePush(value & 1 == 1));
            write_raw_frame(FrameType::Settings as u8, 0, 0, payload, dst);
        }
        SettingsMode::InvalidEnablePush => {
            write_raw_frame(
                FrameType::Settings as u8,
                0,
                0,
                raw_setting_payload(0x2, value.max(2)),
                dst,
            );
        }
        SettingsMode::InitialWindow => {
            let payload = setting_payload(Setting::InitialWindowSize(value & 0x7fff_ffff));
            write_raw_frame(FrameType::Settings as u8, 0, 0, payload, dst);
        }
        SettingsMode::InvalidInitialWindow => {
            write_raw_frame(
                FrameType::Settings as u8,
                0,
                0,
                raw_setting_payload(0x4, value | 0x8000_0000),
                dst,
            );
        }
        SettingsMode::MaxFrameSize => {
            let frame_size = value.clamp(16_384, MAX_FRAME_SIZE);
            let payload = setting_payload(Setting::MaxFrameSize(frame_size));
            write_raw_frame(FrameType::Settings as u8, 0, 0, payload, dst);
        }
        SettingsMode::InvalidMaxFrameSize => {
            let invalid = if value & 1 == 0 {
                16_383
            } else {
                MAX_FRAME_SIZE + 1
            };
            write_raw_frame(
                FrameType::Settings as u8,
                0,
                0,
                raw_setting_payload(0x5, invalid),
                dst,
            );
        }
    }
}

fn encode_window_update_frame(stream_id: u32, increment: u32, dst: &mut BytesMut) {
    let mut payload = BytesMut::with_capacity(4);
    payload.put_u32(increment & 0x7fff_ffff);
    write_raw_frame(
        FrameType::WindowUpdate as u8,
        0,
        stream_id,
        payload.freeze(),
        dst,
    );
}

fn encode_data_frame(
    stream_id: u32,
    end_stream: bool,
    padded: bool,
    pad_length: u8,
    payload: &[u8],
    malformed_padding: bool,
    dst: &mut BytesMut,
) {
    let payload = truncate_bytes(payload);
    let mut flags = 0;
    if end_stream {
        flags |= data_flags::END_STREAM;
    }
    let mut body = BytesMut::new();
    if padded {
        flags |= data_flags::PADDED;
        body.put_u8(pad_length);
        body.extend_from_slice(&payload);
        if !malformed_padding {
            body.extend_from_slice(&vec![0; usize::from(pad_length)]);
        }
    } else {
        body.extend_from_slice(&payload);
    }

    write_raw_frame(FrameType::Data as u8, flags, stream_id, body.freeze(), dst);
}

fn encode_ping_frame(
    ack: bool,
    invalid_stream: bool,
    declared_len: u8,
    payload: &[u8; 8],
    dst: &mut BytesMut,
) {
    let mut flags = 0;
    if ack {
        flags |= ping_flags::ACK;
    }
    let stream_id = if invalid_stream { 1 } else { 0 };
    let actual_len = usize::from(declared_len % 13);
    let mut body = BytesMut::new();
    while body.len() < actual_len {
        body.extend_from_slice(payload);
    }
    body.truncate(actual_len);
    write_raw_frame(FrameType::Ping as u8, flags, stream_id, body.freeze(), dst);
}

fn encode_goaway_frame(
    invalid_stream: bool,
    last_stream_id: u32,
    error_code: u32,
    debug_data: &[u8],
    dst: &mut BytesMut,
) {
    let stream_id = if invalid_stream { 1 } else { 0 };
    let mut body = BytesMut::new();
    body.put_u32(last_stream_id & 0x7fff_ffff);
    body.put_u32(error_code);
    body.extend_from_slice(&truncate_bytes(debug_data));
    write_raw_frame(FrameType::GoAway as u8, 0, stream_id, body.freeze(), dst);
}

fn encode_unknown_frame(
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
    dst: &mut BytesMut,
) {
    write_raw_frame(frame_type, flags, stream_id, Bytes::from(payload), dst);
}

fn setting_payload(setting: Setting) -> Bytes {
    raw_setting_payload(setting.id(), setting.value())
}

fn raw_setting_payload(id: u16, value: u32) -> Bytes {
    let mut payload = BytesMut::with_capacity(6);
    payload.put_u16(id);
    payload.put_u32(value);
    payload.freeze()
}

fn write_raw_frame(frame_type: u8, flags: u8, stream_id: u32, payload: Bytes, dst: &mut BytesMut) {
    let header = FrameHeader {
        length: payload.len() as u32,
        frame_type,
        flags,
        stream_id,
    };
    header.write(dst);
    dst.extend_from_slice(&payload);
}
