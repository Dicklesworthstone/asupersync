#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::redis::RespValue;
use libfuzzer_sys::fuzz_target;

const MAX_KEYS: usize = 8;
const MAX_FIELD_BYTES: usize = 96;

#[derive(Debug, Arbitrary, Clone)]
enum TrackingPushCase {
    Invalidate {
        keys: Vec<Vec<u8>>,
        malformed: TrackingMalformed,
    },
    Tracking {
        name: Vec<u8>,
        token: i64,
        malformed: TrackingMalformed,
    },
}

#[derive(Debug, Arbitrary, Clone, Copy)]
enum TrackingMalformed {
    None,
    TruncateOne,
    TruncateMany(u8),
    BadHeaderKind,
    BadBulkLengthDigit,
    MissingArrayPayload,
}

fuzz_target!(|case: TrackingPushCase| {
    let case = case.sanitize();
    let valid_wire = case.valid_wire();
    let wire = case.mutated_wire(valid_wire.clone());

    match case.is_valid() {
        true => {
            let Some((decoded, consumed)) =
                RespValue::try_decode(&wire).expect("valid client tracking push must decode")
            else {
                panic!("valid client tracking push must be complete");
            };
            assert_eq!(consumed, wire.len());
            assert_eq!(decoded.encode(), wire);
            case.assert_decoded(decoded);
        }
        false => {
            if let Ok(Some((decoded, consumed))) = RespValue::try_decode(&wire) {
                assert!(consumed <= wire.len());

                let encoded = decoded.encode();
                if let Ok(Some((round_trip, round_trip_consumed))) = RespValue::try_decode(&encoded)
                {
                    assert_eq!(round_trip_consumed, encoded.len());
                    assert_eq!(round_trip.encode(), encoded);
                }
            }
        }
    }
});

impl TrackingPushCase {
    fn sanitize(self) -> Self {
        match self {
            Self::Invalidate {
                mut keys,
                malformed,
            } => {
                keys.truncate(MAX_KEYS);
                for key in &mut keys {
                    key.truncate(MAX_FIELD_BYTES);
                }
                Self::Invalidate { keys, malformed }
            }
            Self::Tracking {
                mut name,
                token,
                malformed,
            } => {
                name.truncate(MAX_FIELD_BYTES);
                Self::Tracking {
                    name,
                    token,
                    malformed,
                }
            }
        }
    }

    fn is_valid(&self) -> bool {
        matches!(
            self,
            Self::Invalidate {
                malformed: TrackingMalformed::None,
                ..
            } | Self::Tracking {
                malformed: TrackingMalformed::None,
                ..
            }
        )
    }

    fn valid_wire(&self) -> Vec<u8> {
        match self {
            Self::Invalidate { keys, .. } => {
                let mut wire = format!(">2\r\n+invalidate\r\n*{}\r\n", keys.len()).into_bytes();
                for key in keys {
                    append_bulk_string(&mut wire, key);
                }
                wire
            }
            Self::Tracking { name, token, .. } => {
                let mut wire = b">3\r\n+tracking\r\n".to_vec();
                append_bulk_string(&mut wire, name);
                wire.extend_from_slice(format!(":{token}\r\n").as_bytes());
                wire
            }
        }
    }

    fn mutated_wire(&self, mut wire: Vec<u8>) -> Vec<u8> {
        let malformed = match self {
            Self::Invalidate { malformed, .. } | Self::Tracking { malformed, .. } => malformed,
        };
        match malformed {
            TrackingMalformed::None => wire,
            TrackingMalformed::TruncateOne => {
                let _ = wire.pop();
                wire
            }
            TrackingMalformed::TruncateMany(n) => {
                let trim = usize::from(*n).min(wire.len());
                wire.truncate(wire.len().saturating_sub(trim));
                wire
            }
            TrackingMalformed::BadHeaderKind => {
                if let Some(pos) = find_kind_marker(&wire) {
                    wire[pos] = b':';
                }
                wire
            }
            TrackingMalformed::BadBulkLengthDigit => {
                if let Some(pos) = wire.iter().position(|byte| *byte == b'$') {
                    if pos + 1 < wire.len() {
                        wire[pos + 1] = b'x';
                    }
                }
                wire
            }
            TrackingMalformed::MissingArrayPayload => match self {
                Self::Invalidate { .. } => b">2\r\n+invalidate\r\n".to_vec(),
                Self::Tracking { .. } => {
                    let mut malformed = b">3\r\n+tracking\r\n".to_vec();
                    malformed.extend_from_slice(b"$1\r\na\r\n");
                    malformed
                }
            },
        }
    }

    fn assert_decoded(&self, decoded: RespValue) {
        let RespValue::Push(mut items) = decoded else {
            panic!("client tracking frame must decode as RESP3 push");
        };
        assert!(!items.is_empty(), "push frame must include a kind");

        let kind = decode_text(items.remove(0));
        match self {
            Self::Invalidate { keys, .. } => {
                assert_eq!(kind, "invalidate");
                assert_eq!(items.len(), 1);
                match items.remove(0) {
                    RespValue::Array(Some(values)) => {
                        assert_eq!(values.len(), keys.len());
                        for (value, expected) in values.into_iter().zip(keys) {
                            match value {
                                RespValue::BulkString(Some(bytes)) => assert_eq!(&bytes, expected),
                                other => panic!(
                                    "invalidate key must decode as bulk string, got {other:?}"
                                ),
                            }
                        }
                    }
                    other => panic!("invalidate payload must be RESP array, got {other:?}"),
                }
            }
            Self::Tracking { name, token, .. } => {
                assert_eq!(kind, "tracking");
                assert_eq!(items.len(), 2);
                match items.remove(0) {
                    RespValue::BulkString(Some(bytes)) => {
                        assert_eq!(bytes.as_slice(), name.as_slice())
                    }
                    other => panic!("tracking name must decode as bulk string, got {other:?}"),
                }
                match items.remove(0) {
                    RespValue::Integer(value) => assert_eq!(value, *token),
                    other => panic!("tracking token must decode as integer, got {other:?}"),
                }
            }
        }
    }
}

fn append_bulk_string(wire: &mut Vec<u8>, value: &[u8]) {
    wire.extend_from_slice(format!("${}\r\n", value.len()).as_bytes());
    wire.extend_from_slice(value);
    wire.extend_from_slice(b"\r\n");
}

fn find_kind_marker(wire: &[u8]) -> Option<usize> {
    wire.windows(3)
        .position(|window| window == b"\r\n+")
        .map(|pos| pos + 2)
}

fn decode_text(value: RespValue) -> String {
    match value {
        RespValue::SimpleString(text) => text,
        RespValue::BulkString(Some(bytes)) => {
            String::from_utf8(bytes).expect("tracking push kind should remain valid UTF-8")
        }
        other => panic!("tracking push kind must be textual, got {other:?}"),
    }
}
