#![no_main]

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;

use asupersync::cx::Cx;
use asupersync::messaging::protocol::{
    ProtocolAdapter, ProtocolAdapterError, ProtocolConnectionState, ProtocolNegotiation,
    ProtocolTransportEvent, RespProtocolAdapter,
};
use asupersync::messaging::redis::{RedisProtocolLimits, RespValue};
use asupersync::types::{Budget, RegionId, TaskId};

const MAX_SCRIPT_STEPS: usize = 64;
const MAX_MESSAGE_DEPTH: usize = 3;
const MAX_ARRAY_ITEMS: usize = 4;
const MAX_INLINE_STRING_LEN: usize = 24;
const MAX_BULK_BYTES: usize = 64;
const MAX_DECODE_BYTES: usize = 192;

fn fuzz_test_cx(cancelled: bool) -> Cx {
    let cx = Cx::new(
        RegionId::new_for_test(0, 0),
        TaskId::new_for_test(0, 0),
        Budget::INFINITE,
    );
    if cancelled {
        cx.set_cancel_requested(true);
    }
    cx
}

fn build_limits(u: &mut Unstructured<'_>) -> Option<RedisProtocolLimits> {
    let max_frame_size = usize::from(u.int_in_range::<u16>(64..=4096).ok()?);
    let max_nesting_depth = usize::from(u.int_in_range::<u8>(1..=4).ok()?);
    let max_array_len = usize::from(u.int_in_range::<u8>(1..=8).ok()?);
    let max_bulk_cap = max_frame_size.saturating_sub(16).clamp(1, 256);
    let max_bulk_string_len = usize::from(u.int_in_range::<u16>(1..=max_bulk_cap as u16).ok()?);

    Some(RedisProtocolLimits {
        max_frame_size,
        max_nesting_depth,
        max_array_len,
        max_bulk_string_len,
    })
}

fn next_event(u: &mut Unstructured<'_>) -> Option<ProtocolTransportEvent> {
    Some(match u.int_in_range::<u8>(0..=3).ok()? {
        0 => ProtocolTransportEvent::Connected,
        1 => ProtocolTransportEvent::DrainRequested,
        2 => ProtocolTransportEvent::Closed,
        _ => ProtocolTransportEvent::Reset,
    })
}

fn ascii_string(u: &mut Unstructured<'_>, max_len: usize) -> Option<String> {
    let len_cap = max_len.min(MAX_INLINE_STRING_LEN);
    let len = usize::from(u.int_in_range::<u8>(0..=len_cap as u8).ok()?);
    let bytes = u.bytes(len).ok()?;
    let mut out = String::with_capacity(len);

    for byte in bytes {
        let ch = match byte % 38 {
            0..=25 => char::from(b'a' + (byte % 26)),
            26..=35 => char::from(b'0' + ((byte % 10) as u8)),
            36 => '-',
            _ => '_',
        };
        out.push(ch);
    }

    Some(out)
}

fn bulk_bytes(u: &mut Unstructured<'_>, limits: RedisProtocolLimits) -> Option<Vec<u8>> {
    let len_cap = limits.max_bulk_string_len.min(MAX_BULK_BYTES);
    let len = usize::from(u.int_in_range::<u8>(0..=len_cap as u8).ok()?);
    Some(u.bytes(len).ok()?.to_vec())
}

fn build_value(
    u: &mut Unstructured<'_>,
    limits: RedisProtocolLimits,
    depth: usize,
) -> Option<RespValue> {
    let allow_array = depth < MAX_MESSAGE_DEPTH && depth < limits.max_nesting_depth;
    let max_tag = if allow_array { 6 } else { 5 };
    Some(match u.int_in_range::<u8>(0..=max_tag).ok()? {
        0 => RespValue::SimpleString(ascii_string(u, limits.max_frame_size)?),
        1 => RespValue::Error(ascii_string(u, limits.max_frame_size)?),
        2 => RespValue::Integer(i64::from(u.arbitrary::<i32>().ok()?)),
        3 => {
            if u.arbitrary::<bool>().ok()? {
                RespValue::BulkString(None)
            } else {
                RespValue::BulkString(Some(bulk_bytes(u, limits)?))
            }
        }
        4 => RespValue::Null,
        5 => RespValue::Boolean(u.arbitrary::<bool>().ok()?),
        _ => {
            if u.arbitrary::<bool>().ok()? {
                RespValue::Array(None)
            } else {
                let item_cap = limits.max_array_len.min(MAX_ARRAY_ITEMS);
                let len = usize::from(u.int_in_range::<u8>(0..=item_cap as u8).ok()?);
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(build_value(u, limits, depth + 1)?);
                }
                RespValue::Array(Some(items))
            }
        }
    })
}

fn take_bytes<'a>(u: &mut Unstructured<'a>, max_len: usize) -> Option<&'a [u8]> {
    let len_cap = max_len.min(MAX_DECODE_BYTES);
    let len = usize::from(u.int_in_range::<u8>(0..=len_cap as u8).ok()?);
    u.bytes(len).ok()
}

fn assert_cancelled_behaviour(limits: RedisProtocolLimits) {
    let cancelled_cx = fuzz_test_cx(true);
    let adapter = RespProtocolAdapter::new(limits);

    assert!(matches!(
        adapter.begin_handshake(&cancelled_cx),
        Err(ProtocolAdapterError::Cancelled)
    ));
    assert!(matches!(
        adapter.health_check(&cancelled_cx),
        Err(ProtocolAdapterError::Cancelled)
    ));

    let mut transport_adapter = RespProtocolAdapter::new(limits);
    assert!(matches!(
        transport_adapter.on_transport_event(&cancelled_cx, ProtocolTransportEvent::Connected),
        Err(ProtocolAdapterError::Cancelled)
    ));
}

fn assert_negotiation_shape(negotiation: &ProtocolNegotiation) {
    assert_eq!(negotiation.adapter_name, "redis-resp-adapter");
    assert_eq!(negotiation.protocol_family, "redis-resp");
    assert_eq!(negotiation.version_hint, Some("RESP2"));
    assert!(negotiation.capabilities.pipelined_requests);
    assert!(negotiation.capabilities.request_reply);
    assert!(negotiation.capabilities.features.contains(&"bulk_strings"));
}

fn assert_roundtrip_generated(limits: RedisProtocolLimits, value: &RespValue) {
    let adapter = RespProtocolAdapter::new(limits);
    let mut encoded = Vec::new();
    adapter
        .encode_message(value, &mut encoded)
        .expect("fresh adapter should encode generated RESP value");

    if encoded.len() > limits.max_frame_size {
        return;
    }

    let decoded = adapter
        .try_decode_message(&encoded)
        .expect("fresh adapter should decode generated RESP value")
        .expect("generated RESP value should decode as a full frame");

    assert_eq!(decoded.consumed, encoded.len());
    assert_eq!(&decoded.message, value);
}

fn assert_prefix_consumption(limits: RedisProtocolLimits, first: &RespValue, second: &RespValue) {
    let first_encoded = first.encode();
    let second_encoded = second.encode();
    let combined_len = first_encoded.len() + second_encoded.len();

    if combined_len > limits.max_frame_size {
        return;
    }

    let mut combined = first_encoded.clone();
    combined.extend_from_slice(&second_encoded);

    let adapter = RespProtocolAdapter::new(limits);
    let decoded = adapter
        .try_decode_message(&combined)
        .expect("combined valid RESP frames should not error")
        .expect("first valid RESP frame should decode from concatenated input");

    assert_eq!(decoded.consumed, first_encoded.len());
    assert_eq!(&decoded.message, first);
}

fn exercise_decode(adapter: &RespProtocolAdapter, input: &[u8]) {
    let limits = adapter.limits();

    match adapter.try_decode_message(input) {
        Ok(Some(decoded)) => {
            assert!(decoded.consumed > 0);
            assert!(decoded.consumed <= input.len());
            assert_roundtrip_generated(limits, &decoded.message);
        }
        Ok(None) | Err(_) => {}
    }
}

fn run_fuzz(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let Some(limits) = build_limits(&mut u) else {
        return;
    };

    assert_cancelled_behaviour(limits);

    let live_cx = fuzz_test_cx(false);
    let mut adapter = RespProtocolAdapter::new(limits);
    exercise_decode(&adapter, data);

    let mut steps = 0usize;
    while steps < MAX_SCRIPT_STEPS && !u.is_empty() {
        steps += 1;
        let Some(opcode) = u.int_in_range::<u8>(0..=5).ok() else {
            break;
        };

        match opcode {
            0 => match adapter.begin_handshake(&live_cx) {
                Ok(negotiation) => assert_negotiation_shape(&negotiation),
                Err(ProtocolAdapterError::Lifecycle { .. }) => {
                    assert_eq!(adapter.connection_state(), ProtocolConnectionState::Closed);
                }
                Err(other) => panic!("unexpected handshake error: {other:?}"),
            },
            1 => match adapter.health_check(&live_cx) {
                Ok(health) => {
                    assert_eq!(health.state, adapter.connection_state());
                    assert_eq!(
                        health.ready,
                        adapter.connection_state() == ProtocolConnectionState::Ready
                    );
                }
                Err(other) => panic!("unexpected health error: {other:?}"),
            },
            2 => {
                let Some(event) = next_event(&mut u) else {
                    break;
                };
                let before = adapter.connection_state();
                match adapter.on_transport_event(&live_cx, event) {
                    Ok(next) => assert_eq!(next, adapter.connection_state()),
                    Err(ProtocolAdapterError::Lifecycle { .. }) => {
                        assert_eq!(adapter.connection_state(), before);
                    }
                    Err(other) => panic!("unexpected transport error: {other:?}"),
                }
            }
            3 => {
                let Some(bytes) = take_bytes(&mut u, limits.max_frame_size) else {
                    break;
                };
                exercise_decode(&adapter, bytes);
            }
            4 => {
                let Some(value) = build_value(&mut u, limits, 0) else {
                    break;
                };
                if adapter.connection_state() != ProtocolConnectionState::Closed {
                    let mut encoded = Vec::new();
                    adapter
                        .encode_message(&value, &mut encoded)
                        .expect("open adapter should encode generated RESP value");
                    assert_roundtrip_generated(limits, &value);
                } else {
                    let mut encoded = Vec::new();
                    assert!(matches!(
                        adapter.encode_message(&value, &mut encoded),
                        Err(ProtocolAdapterError::Lifecycle { .. })
                    ));
                }
            }
            _ => {
                let Some(first) = build_value(&mut u, limits, 0) else {
                    break;
                };
                let Some(second) = build_value(&mut u, limits, 0) else {
                    break;
                };
                assert_prefix_consumption(limits, &first, &second);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    run_fuzz(data);
});
