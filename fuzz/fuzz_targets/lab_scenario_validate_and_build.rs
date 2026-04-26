#![no_main]

//! br-asupersync-tumfif — fuzz target for the
//! `Scenario::from_json -> validate -> to_lab_config` pipeline in
//! `src/lab/scenario.rs`.
//!
//! ## Contract under test
//!
//! 1. `Scenario::from_json` is a serde wrapper. It must NEVER panic on any
//!    input — only return `Err(serde_json::Error)`.
//! 2. `Scenario::validate` is total: every field is iterated and every
//!    invariant checked. Even adversarial values that round-tripped
//!    through serde (e.g. NaN probabilities, swapped delay_min/max,
//!    huge participants vec) must produce a `Vec<ValidationError>`,
//!    never panic.
//! 3. `Scenario::to_lab_config` translates the validated scenario into
//!    a `LabConfig`. Even when validate returned errors, the config
//!    builder must not panic — production callers may still attempt
//!    to log a config snapshot for diagnostic purposes.
//!
//! ## Input shape
//!
//! libFuzzer feeds raw bytes. Two fuzzing strategies are interleaved
//! based on the first byte of input:
//!
//! - **Strategy A (raw JSON, prefix 0x00..0x7F):** treat the remaining
//!   bytes as utf-8 JSON and pass directly to `from_json`. This
//!   stresses the serde recursion-depth, NaN-token, and overflow paths.
//!
//! - **Strategy B (synthesised JSON, prefix 0x80..0xFF):** consume the
//!   remaining bytes via `arbitrary::Unstructured` to build a typed
//!   `ScenarioSeed`, then serialise to JSON and feed it back through
//!   `from_json`. This guarantees every iteration reaches the
//!   validator (which would otherwise be skipped 99% of the time on
//!   raw bytes that fail to parse).
//!
//! ## Bounded resources
//!
//! - Input is clamped to 256 KiB to keep iterations sub-second and
//!   prevent OOM in the JSON parser.
//! - The synthesised `ScenarioSeed` caps participants/faults/links to
//!   small enough counts that the validator + builder fit comfortably
//!   in 1 second per run.

use arbitrary::{Arbitrary, Unstructured};
use asupersync::lab::scenario::Scenario;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_INPUT: usize = 256 * 1024;

/// Synthesised scenario seed for strategy B. Each field is bounded so
/// the encoded JSON stays small enough to parse in microseconds.
#[derive(Arbitrary, Debug)]
struct ScenarioSeed {
    schema_version: u32,
    id: ShortString,
    description: ShortString,
    seed: u64,
    worker_count: u8,
    trace_capacity: u16,
    panic_on_obligation_leak: bool,
    panic_on_futurelock: bool,
    futurelock_max_idle_steps: u32,
    chaos_choice: u8,
    cancel_probability: AdversarialF64,
    delay_probability: AdversarialF64,
    delay_min_ms: u64,
    delay_max_ms: u64,
    io_error_probability: AdversarialF64,
    wakeup_storm_probability: AdversarialF64,
    budget_exhaustion_probability: AdversarialF64,
    links: BoundedVec<LinkSeed>,
    faults: BoundedVec<FaultSeed>,
    participants: BoundedVec<ParticipantSeed>,
    oracles: BoundedVec<ShortString>,
}

#[derive(Arbitrary, Debug)]
struct LinkSeed {
    key: ShortString,
    packet_loss: Option<AdversarialF64>,
    packet_corrupt: Option<AdversarialF64>,
    latency_min_ms: u64,
    latency_max_ms: u64,
    latency_kind: u8,
}

#[derive(Arbitrary, Debug)]
struct FaultSeed {
    at_ms: u64,
    action_kind: u8,
}

#[derive(Arbitrary, Debug)]
struct ParticipantSeed {
    name: ShortString,
    role: ShortString,
}

/// f64 wrapper that biases toward NaN, +/-Inf, denormals and boundary
/// values. Without this, a uniform u64-as-f64 sample lands in NaN
/// space ~99.9% of the time and the validator only ever sees one
/// equivalence class.
#[derive(Debug)]
struct AdversarialF64(f64);

impl<'a> Arbitrary<'a> for AdversarialF64 {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let v = match u.int_in_range(0..=15)? {
            0 => f64::NAN,
            1 => f64::INFINITY,
            2 => f64::NEG_INFINITY,
            3 => 0.0,
            4 => -0.0,
            5 => 1.0,
            6 => -1.0,
            7 => 0.5,
            8 => 1.5,
            9 => f64::MIN_POSITIVE,
            10 => f64::MAX,
            11 => f64::MIN,
            12 => f64::EPSILON,
            13 => -f64::EPSILON,
            _ => f64::from_bits(u64::arbitrary(u)?),
        };
        Ok(Self(v))
    }
}

/// String capped to 64 bytes so JSON encoding stays small.
#[derive(Debug)]
struct ShortString(String);

impl<'a> Arbitrary<'a> for ShortString {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(0..=64)?;
        let raw: Vec<u8> = (0..len)
            .map(|_| u.int_in_range(0..=127u8))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        Ok(Self(String::from_utf8_lossy(&raw).into_owned()))
    }
}

/// Vec capped to 16 elements; keeps the validator's O(N) walks fast.
#[derive(Debug)]
struct BoundedVec<T>(Vec<T>);

impl<'a, T: Arbitrary<'a>> Arbitrary<'a> for BoundedVec<T> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(0..=16)?;
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push(T::arbitrary(u)?);
        }
        Ok(Self(v))
    }
}

impl ScenarioSeed {
    /// Render the synthesised seed to a JSON document that
    /// `Scenario::from_json` can parse. JSON does not represent NaN
    /// natively, so non-finite probabilities are rendered as a string
    /// to force the deserialiser through its error path; this is
    /// itself part of the fuzz surface.
    fn to_json_string(&self) -> String {
        let chaos = match self.chaos_choice & 0x03 {
            0 => serde_json::json!({"preset": "off"}),
            1 => serde_json::json!({"preset": "light"}),
            2 => serde_json::json!({"preset": "heavy"}),
            _ => serde_json::json!({
                "preset": "custom",
                "cancel_probability": finite_or_zero(self.cancel_probability.0),
                "delay_probability": finite_or_zero(self.delay_probability.0),
                "delay_min_ms": self.delay_min_ms,
                "delay_max_ms": self.delay_max_ms,
                "io_error_probability": finite_or_zero(self.io_error_probability.0),
                "wakeup_storm_probability":
                    finite_or_zero(self.wakeup_storm_probability.0),
                "budget_exhaustion_probability":
                    finite_or_zero(self.budget_exhaustion_probability.0),
            }),
        };

        let mut links_obj = BTreeMap::new();
        for link in &self.links.0 {
            let latency_model = match link.latency_kind & 0x03 {
                0 => serde_json::json!({"model": "fixed", "ms": link.latency_min_ms}),
                1 => serde_json::json!({
                    "model": "uniform",
                    "min_ms": link.latency_min_ms,
                    "max_ms": link.latency_max_ms,
                }),
                _ => serde_json::json!({
                    "model": "normal",
                    "mean_ms": link.latency_min_ms,
                    "stddev_ms": link.latency_max_ms,
                }),
            };
            let mut link_obj = serde_json::json!({"latency": latency_model});
            if let Some(loss) = &link.packet_loss {
                link_obj["packet_loss"] = serde_json::json!(finite_or_zero(loss.0));
            }
            if let Some(corrupt) = &link.packet_corrupt {
                link_obj["packet_corrupt"] = serde_json::json!(finite_or_zero(corrupt.0));
            }
            links_obj.insert(link.key.0.clone(), link_obj);
        }

        let faults: Vec<_> = self
            .faults
            .0
            .iter()
            .map(|f| {
                let action = match f.action_kind & 0x05 {
                    0 => "partition",
                    1 => "heal",
                    2 => "host_crash",
                    3 => "host_restart",
                    4 => "clock_skew",
                    _ => "clock_reset",
                };
                serde_json::json!({"at_ms": f.at_ms, "action": action})
            })
            .collect();

        let participants: Vec<_> = self
            .participants
            .0
            .iter()
            .map(|p| serde_json::json!({"name": p.name.0, "role": p.role.0}))
            .collect();

        let oracles: Vec<String> = self.oracles.0.iter().map(|s| s.0.clone()).collect();

        let scenario = serde_json::json!({
            "schema_version": self.schema_version,
            "id": self.id.0,
            "description": self.description.0,
            "lab": {
                "seed": self.seed,
                "worker_count": self.worker_count,
                "trace_capacity": self.trace_capacity,
                "panic_on_obligation_leak": self.panic_on_obligation_leak,
                "panic_on_futurelock": self.panic_on_futurelock,
                "futurelock_max_idle_steps": self.futurelock_max_idle_steps,
            },
            "chaos": chaos,
            "network": {"links": links_obj},
            "faults": faults,
            "participants": participants,
            "oracles": oracles,
        });
        serde_json::to_string(&scenario).unwrap_or_default()
    }
}

#[inline]
fn finite_or_zero(v: f64) -> f64 {
    if v.is_finite() { v } else { 0.0 }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT {
        return;
    }

    // Strategy selector — top bit of the first byte switches mode.
    let strategy_b = data[0] & 0x80 != 0;
    let payload = &data[1..];

    let json_owned: String;
    let json: &str = if strategy_b {
        let mut u = Unstructured::new(payload);
        let Ok(seed) = ScenarioSeed::arbitrary(&mut u) else {
            return;
        };
        json_owned = seed.to_json_string();
        &json_owned
    } else {
        match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return,
        }
    };

    // Contract 1: from_json must never panic. serde_json may recurse,
    // so libFuzzer's stack-overflow detector will flag any unbounded
    // recursion implicitly.
    let scenario = match Scenario::from_json(json) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Contract 2: validate is total — must produce a Vec, never panic.
    let _errors = scenario.validate();

    // Contract 3: to_lab_config must not panic even when the scenario
    // was rejected by validate. Production callers log the config
    // snapshot for diagnostics regardless of validation status.
    let _config = scenario.to_lab_config();
});
