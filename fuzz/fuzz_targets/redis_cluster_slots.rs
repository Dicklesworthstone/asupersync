#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::messaging::redis::{
    RedisClusterSlotNode, RedisClusterSlotRange, RespValue, parse_cluster_slots_response,
};
use libfuzzer_sys::fuzz_target;

const MAX_TEXT_BYTES: usize = 64;
const MAX_REPLICAS: usize = 4;
const MAX_RANGES: usize = 16;
const REDIS_CLUSTER_MAX_SLOT: u16 = 16_383;

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
            parse_cluster_slots_response(&decoded.0).expect("generated CLUSTER SLOTS should parse");
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
    let response = match case {
        MalformedCase::ReversedRange => RespValue::Array(Some(vec![RespValue::Array(Some(vec![
            RespValue::Integer(10),
            RespValue::Integer(9),
            valid_node(),
        ]))])),
        MalformedCase::SlotOutOfRange => {
            RespValue::Array(Some(vec![RespValue::Array(Some(vec![
                RespValue::Integer(0),
                RespValue::Integer(i64::from(REDIS_CLUSTER_MAX_SLOT) + 1),
                valid_node(),
            ]))]))
        }
        MalformedCase::MissingMaster => RespValue::Array(Some(vec![RespValue::Array(Some(vec![
            RespValue::Integer(0),
            RespValue::Integer(1),
        ]))])),
        MalformedCase::BadNodePort => RespValue::Array(Some(vec![RespValue::Array(Some(vec![
            RespValue::Integer(0),
            RespValue::Integer(1),
            RespValue::Array(Some(vec![
                RespValue::BulkString(Some(b"127.0.0.1".to_vec())),
                RespValue::Integer(-1),
            ])),
        ]))])),
        MalformedCase::NonUtf8Endpoint => {
            RespValue::Array(Some(vec![RespValue::Array(Some(vec![
                RespValue::Integer(0),
                RespValue::Integer(1),
                RespValue::Array(Some(vec![
                    RespValue::BulkString(Some(vec![0xff])),
                    RespValue::Integer(6379),
                ])),
            ]))]))
        }
    };

    assert!(parse_cluster_slots_response(&response).is_err());
}

fn exercise_raw_resp(data: &[u8]) {
    if let Ok(Some((value, _))) = RespValue::try_decode(data) {
        let _ = parse_cluster_slots_response(&value);
    }
}

fuzz_target!(|data: &[u8]| {
    exercise_raw_resp(data);

    let mut unstructured = Unstructured::new(data);
    if let Ok(input) = ClusterSlotsInput::arbitrary(&mut unstructured) {
        input.exercise();
    }
});
