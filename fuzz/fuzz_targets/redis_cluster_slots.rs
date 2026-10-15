#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::messaging::redis::{
    RedisClusterSlotNode, RedisClusterSlotRange, RedisError, RespValue,
    parse_cluster_slots_response,
};
use libfuzzer_sys::fuzz_target;

const MAX_TEXT_BYTES: usize = 64;
const MAX_REPLICAS: usize = 4;
const MAX_RANGES: usize = 16;
const REDIS_CLUSTER_MAX_SLOT: u16 = 16_383;

fn observe_cluster_slots_parse(
    value: &RespValue,
) -> Result<Vec<RedisClusterSlotRange>, RedisError> {
    let response_len = match value {
        RespValue::Array(Some(items)) => Some(items.len()),
        _ => None,
    };
    let result = parse_cluster_slots_response(value);

    match &result {
        Ok(ranges) => {
            if let Some(response_len) = response_len {
                assert!(
                    ranges.len() <= response_len,
                    "raw CLUSTER SLOTS parse produced more ranges than response entries"
                );
            }
            for range in ranges {
                assert!(
                    range.start <= range.end,
                    "raw CLUSTER SLOTS parse produced a reversed range"
                );
                assert!(
                    range.end <= REDIS_CLUSTER_MAX_SLOT,
                    "raw CLUSTER SLOTS parse produced an out-of-range slot"
                );
            }
        }
        Err(err) => {
            assert!(
                !format!("{err:?}").is_empty(),
                "Redis CLUSTER SLOTS parser errors must remain observable"
            );
        }
    }

    result
}

#[derive(Arbitrary, Debug, Clone)]
enum FuzzEndpoint {
    Null,
    Empty,
    Unknown,
    Text(String),
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzNode {
    endpoint: FuzzEndpoint,
    port: u16,
    node_id: Option<String>,
    legacy_shape: bool,
    include_metadata: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzSlotRange {
    start: u16,
    width: u16,
    master: FuzzNode,
    replicas: Vec<FuzzNode>,
}

#[derive(Arbitrary, Debug, Clone)]
enum MalformedCase {
    ReversedRange,
    SlotOutOfRange,
    MissingMaster,
    BadNodePort,
    NonUtf8Endpoint,
}

#[derive(Arbitrary, Debug, Clone)]
struct ClusterSlotsInput {
    ranges: Vec<FuzzSlotRange>,
    malformed: MalformedCase,
}

impl FuzzEndpoint {
    fn into_resp_and_expected(self) -> (RespValue, Option<String>) {
        match self {
            Self::Null => (RespValue::BulkString(None), None),
            Self::Empty => (RespValue::BulkString(Some(Vec::new())), None),
            Self::Unknown => (
                RespValue::BulkString(Some(b"?".to_vec())),
                Some("?".to_string()),
            ),
            Self::Text(mut text) => {
                truncate_text(&mut text);
                let expected = (!text.is_empty()).then(|| text.clone());
                (RespValue::BulkString(Some(text.into_bytes())), expected)
            }
        }
    }
}

impl FuzzNode {
    fn into_resp_and_expected(self) -> (RespValue, RedisClusterSlotNode) {
        let (endpoint, expected_endpoint) = self.endpoint.into_resp_and_expected();
        let mut fields = vec![endpoint, RespValue::Integer(i64::from(self.port))];

        let expected_node_id = if self.legacy_shape {
            None
        } else {
            self.node_id.map(|mut node_id| {
                truncate_text(&mut node_id);
                node_id
            })
        };

        if !self.legacy_shape {
            match &expected_node_id {
                Some(node_id) => {
                    fields.push(RespValue::BulkString(Some(node_id.as_bytes().to_vec())))
                }
                None => fields.push(RespValue::BulkString(None)),
            }
            if self.include_metadata {
                fields.push(RespValue::Map(vec![(
                    RespValue::BulkString(Some(b"hostname".to_vec())),
                    RespValue::BulkString(Some(b"host.redis.example".to_vec())),
                )]));
            }
        }

        (
            RespValue::Array(Some(fields)),
            RedisClusterSlotNode {
                endpoint: expected_endpoint,
                port: self.port,
                node_id: expected_node_id.filter(|node_id| !node_id.is_empty()),
            },
        )
    }
}

impl FuzzSlotRange {
    fn into_resp_and_expected(self) -> (RespValue, RedisClusterSlotRange) {
        let start = self.start % (REDIS_CLUSTER_MAX_SLOT + 1);
        let room = REDIS_CLUSTER_MAX_SLOT - start;
        let end = start + (self.width % (room + 1));
        let (master, expected_master) = self.master.into_resp_and_expected();

        let mut fields = vec![
            RespValue::Integer(i64::from(start)),
            RespValue::Integer(i64::from(end)),
            master,
        ];
        let mut expected_replicas = Vec::new();
        for replica in self.replicas.into_iter().take(MAX_REPLICAS) {
            let (replica, expected_replica) = replica.into_resp_and_expected();
            fields.push(replica);
            expected_replicas.push(expected_replica);
        }

        (
            RespValue::Array(Some(fields)),
            RedisClusterSlotRange {
                start,
                end,
                master: expected_master,
                replicas: expected_replicas,
            },
        )
    }
}

impl ClusterSlotsInput {
    fn exercise(self) {
        let mut fields = Vec::new();
        let mut expected = Vec::new();
        for range in self.ranges.into_iter().take(MAX_RANGES) {
            let (range, expected_range) = range.into_resp_and_expected();
            fields.push(range);
            expected.push(expected_range);
        }

        let response = RespValue::Array(Some(fields));
        let encoded = response.encode();
        let decoded = RespValue::try_decode(&encoded)
            .expect("generated CLUSTER SLOTS response should decode")
            .expect("generated CLUSTER SLOTS response should be complete");
        assert_eq!(decoded.1, encoded.len());

        let parsed =
            observe_cluster_slots_parse(&decoded.0).expect("generated CLUSTER SLOTS should parse");
        assert_eq!(parsed, expected);

        exercise_malformed(self.malformed);
    }
}

fn truncate_text(text: &mut String) {
    if text.len() <= MAX_TEXT_BYTES {
        return;
    }
    let mut end = MAX_TEXT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
}

fn valid_node() -> RespValue {
    RespValue::Array(Some(vec![
        RespValue::BulkString(Some(b"127.0.0.1".to_vec())),
        RespValue::Integer(6379),
        RespValue::BulkString(Some(b"node".to_vec())),
    ]))
}

fn exercise_malformed(case: MalformedCase) {
    let (response, expected_message) = match case {
        MalformedCase::ReversedRange => (
            RespValue::Array(Some(vec![RespValue::Array(Some(vec![
                RespValue::Integer(10),
                RespValue::Integer(9),
                valid_node(),
            ]))])),
            "CLUSTER SLOTS range 0 start slot 10 exceeds end slot 9",
        ),
        MalformedCase::SlotOutOfRange => (
            RespValue::Array(Some(vec![RespValue::Array(Some(vec![
                RespValue::Integer(0),
                RespValue::Integer(i64::from(REDIS_CLUSTER_MAX_SLOT) + 1),
                valid_node(),
            ]))])),
            "CLUSTER SLOTS end slot 16384 is outside 0..=16383",
        ),
        MalformedCase::MissingMaster => (
            RespValue::Array(Some(vec![RespValue::Array(Some(vec![
                RespValue::Integer(0),
                RespValue::Integer(1),
            ]))])),
            "CLUSTER SLOTS range 0 must contain start, end, and master node",
        ),
        MalformedCase::BadNodePort => (
            RespValue::Array(Some(vec![RespValue::Array(Some(vec![
                RespValue::Integer(0),
                RespValue::Integer(1),
                RespValue::Array(Some(vec![
                    RespValue::BulkString(Some(b"127.0.0.1".to_vec())),
                    RespValue::Integer(-1),
                ])),
            ]))])),
            "CLUSTER SLOTS master node port -1 is outside u16 range",
        ),
        MalformedCase::NonUtf8Endpoint => (
            RespValue::Array(Some(vec![RespValue::Array(Some(vec![
                RespValue::Integer(0),
                RespValue::Integer(1),
                RespValue::Array(Some(vec![
                    RespValue::BulkString(Some(vec![0xff])),
                    RespValue::Integer(6379),
                ])),
            ]))])),
            "CLUSTER SLOTS master node endpoint is not valid UTF-8",
        ),
    };

    assert_cluster_slots_protocol_error(response, expected_message);
}

fn assert_cluster_slots_protocol_error(response: RespValue, expected_message: &str) {
    match observe_cluster_slots_parse(&response) {
        Err(RedisError::Protocol(message)) => {
            assert_eq!(message, expected_message);
            assert_eq!(
                RedisError::Protocol(message).to_string(),
                format!("Redis protocol error: {expected_message}")
            );
        }
        Err(err) => panic!("expected Redis protocol error {expected_message:?}, got {err:?}"),
        Ok(ranges) => panic!(
            "malformed CLUSTER SLOTS response parsed successfully as {ranges:?}; \
             expected {expected_message:?}"
        ),
    }
}

fn exercise_raw_resp(data: &[u8]) {
    if let Ok(Some((value, decoded_len))) = RespValue::try_decode(data) {
        let result = observe_cluster_slots_parse(&value);
        assert_raw_cluster_slots_parse_observation(&value, decoded_len, data.len(), &result);
    }
}

fn assert_raw_cluster_slots_parse_observation(
    value: &RespValue,
    decoded_len: usize,
    input_len: usize,
    result: &Result<Vec<RedisClusterSlotRange>, RedisError>,
) {
    assert!(
        decoded_len <= input_len,
        "RESP decoder consumed more bytes than raw input: {decoded_len} > {input_len}"
    );

    match result {
        Ok(ranges) => {
            let RespValue::Array(Some(entries)) = value else {
                panic!("raw CLUSTER SLOTS parse accepted a non-array RESP value");
            };
            assert!(
                ranges.len() <= entries.len(),
                "raw CLUSTER SLOTS parse produced more ranges than RESP entries"
            );
        }
        Err(err) => {
            assert!(
                !format!("{err:?}").is_empty(),
                "raw CLUSTER SLOTS parser errors must remain observable"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    exercise_raw_resp(data);

    let mut unstructured = Unstructured::new(data);
    if let Ok(input) = ClusterSlotsInput::arbitrary(&mut unstructured) {
        input.exercise();
    }
});
