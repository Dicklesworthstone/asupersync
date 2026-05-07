//! RFC 6330 test vector generator.
//!
//! This generator captures reference vectors from the live `asupersync`
//! RFC 6330 seam instead of maintaining a parallel mock implementation.
//!
//! Usage:
//!   cargo run --quiet --bin generate_rfc6330_vectors > conformance/fixtures/rfc6330_vectors.json

use asupersync::raptorq::{
    rfc6330::{LtTuple, deg, next_prime_ge, rand, repair_indices_for_esi, tuple},
    systematic::SystematicParams,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TestVector<I, O> {
    id: String,
    rfc_section: String,
    description: String,
    input: I,
    expected: O,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TupleInput {
    k: usize,
    x: u32,
    systematic_index: usize,
    lt_width: usize,
    pi_count: usize,
    pi_modulus: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SerializableLtTuple {
    d: usize,
    a: usize,
    b: usize,
    d1: usize,
    a1: usize,
    b1: usize,
}

impl From<LtTuple> for SerializableLtTuple {
    fn from(value: LtTuple) -> Self {
        Self {
            d: value.d,
            a: value.a,
            b: value.b,
            d1: value.d1,
            a1: value.a1,
            b1: value.b1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TupleExpectation {
    tuple: SerializableLtTuple,
    indices: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct VectorSuite {
    generated_at: String,
    generator_version: String,
    rand_vectors: Vec<TestVector<(u32, u8, u32), u32>>,
    deg_vectors: Vec<TestVector<u32, usize>>,
    tuple_vectors: Vec<TestVector<TupleInput, TupleExpectation>>,
    metadata: HashMap<String, String>,
}

fn now_epoch_seconds_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX_EPOCH")
        .as_secs()
        .to_string()
}

fn build_tuple_vector(
    id: &str,
    description: &str,
    k: usize,
    x: u32,
) -> TestVector<TupleInput, TupleExpectation> {
    let params = SystematicParams::try_for_source_block(k, 1024)
        .expect("tuple test case must derive RFC parameters");
    let pi_modulus = next_prime_ge(params.p);
    let live_tuple = tuple(params.j, params.w, params.p, pi_modulus, x);
    let indices = repair_indices_for_esi(params.j, params.w, params.p, x);

    TestVector {
        id: id.to_string(),
        rfc_section: "5.3.5.3".to_string(),
        description: description.to_string(),
        input: TupleInput {
            k,
            x,
            systematic_index: params.j,
            lt_width: params.w,
            pi_count: params.p,
            pi_modulus,
        },
        expected: TupleExpectation {
            tuple: live_tuple.into(),
            indices,
        },
    }
}

fn build_suite() -> VectorSuite {
    let rand_test_cases = [
        ((0, 0, 256), "RFC golden vector: zero seed, byte modulus"),
        ((1, 0, 256), "RFC golden vector: low seed, byte modulus"),
        (
            (42, 1, 100),
            "RFC golden vector: mixed seed, decimal modulus",
        ),
        (
            (0xDEAD_BEEF, 0, 1000),
            "RFC golden vector: large seed, decimal modulus",
        ),
        (
            (12_345, 1, 65_536),
            "RFC golden vector: mid seed, 16-bit modulus",
        ),
    ];

    let deg_test_cases = [
        (0, "degree-1 lower boundary"),
        (5_242, "degree-1 upper boundary"),
        (5_243, "degree-2 lower boundary"),
        (529_530, "degree-2 upper boundary"),
        (529_531, "degree-3 lower boundary"),
        (704_294, "degree-4 lower boundary"),
        (1_017_662, "degree-30 lower boundary"),
        (1_048_575, "maximum 20-bit sample"),
    ];

    let mut metadata = HashMap::new();
    metadata.insert(
        "purpose".to_string(),
        "RFC 6330 conformance test vectors from the live asupersync seam".to_string(),
    );
    metadata.insert(
        "rfc_reference".to_string(),
        "https://www.rfc-editor.org/rfc/rfc6330.html".to_string(),
    );
    metadata.insert(
        "generated_at_format".to_string(),
        "unix-epoch-seconds".to_string(),
    );

    let rand_vectors = rand_test_cases
        .iter()
        .enumerate()
        .map(|(idx, ((y, i, m), description))| TestVector {
            id: format!("RFC6330-5.3.5.1-{:03}", idx + 1),
            rfc_section: "5.3.5.1".to_string(),
            description: (*description).to_string(),
            input: (*y, *i, *m),
            expected: rand(*y, *i, *m),
        })
        .collect();

    let deg_vectors = deg_test_cases
        .iter()
        .enumerate()
        .map(|(idx, (value, description))| TestVector {
            id: format!("RFC6330-5.3.5.2-{:03}", idx + 1),
            rfc_section: "5.3.5.2".to_string(),
            description: (*description).to_string(),
            input: *value,
            expected: deg(*value),
        })
        .collect();

    let tuple_vectors = [
        (
            "RFC6330-5.3.5.3-001",
            "K=10 parameter space, X=0",
            10usize,
            0u32,
        ),
        (
            "RFC6330-5.3.5.3-002",
            "K=10 parameter space, X=1",
            10usize,
            1u32,
        ),
        (
            "RFC6330-5.3.5.3-003",
            "K=20 parameter space, X=50",
            20usize,
            50u32,
        ),
        (
            "RFC6330-5.3.5.3-004",
            "K=100 parameter space, X=200",
            100usize,
            200u32,
        ),
    ]
    .into_iter()
    .map(|(id, description, k, x)| build_tuple_vector(id, description, k, x))
    .collect();

    VectorSuite {
        generated_at: now_epoch_seconds_string(),
        generator_version: "asupersync-conformance-generator-0.2.0-live-seam".to_string(),
        rand_vectors,
        deg_vectors,
        tuple_vectors,
        metadata,
    }
}

fn main() {
    let suite = build_suite();
    let total_vectors =
        suite.rand_vectors.len() + suite.deg_vectors.len() + suite.tuple_vectors.len();

    let json_output =
        serde_json::to_string_pretty(&suite).expect("failed to serialize live RFC6330 vectors");
    println!("{json_output}");

    eprintln!("Generated {} rand vectors", suite.rand_vectors.len());
    eprintln!("Generated {} deg vectors", suite.deg_vectors.len());
    eprintln!("Generated {} tuple vectors", suite.tuple_vectors.len());
    eprintln!("Total: {total_vectors} test vectors");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_uses_live_rfc_rand_and_deg_values() {
        let suite = build_suite();
        assert_eq!(suite.rand_vectors[0].expected, 25);
        assert_eq!(suite.rand_vectors[4].expected, 18_106);
        assert_eq!(suite.deg_vectors[6].expected, 30);
        assert_eq!(suite.deg_vectors[7].expected, 30);
    }

    #[test]
    fn suite_derives_real_tuple_parameters_and_indices() {
        let suite = build_suite();
        let vector = &suite.tuple_vectors[0];
        assert_eq!(vector.input.systematic_index, 254);
        assert_eq!(vector.input.lt_width, 17);
        assert_eq!(vector.input.pi_count, 10);
        assert_eq!(
            vector.expected.tuple,
            SerializableLtTuple {
                d: 2,
                a: 4,
                b: 9,
                d1: 2,
                a1: 5,
                b1: 1,
            }
        );
        assert_eq!(vector.expected.indices, vec![9, 13, 18, 23]);
    }

    #[test]
    fn suite_serializes_to_json() {
        let suite = build_suite();
        let json = serde_json::to_string(&suite).expect("suite should serialize");
        assert!(json.contains("RFC6330-5.3.5.1-001"));
        assert!(json.contains("RFC6330-5.3.5.3-004"));
        assert!(!suite.generated_at.is_empty());
    }
}
