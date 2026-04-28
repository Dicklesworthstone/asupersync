#![no_main]

use arbitrary::Arbitrary;
use asupersync::transport::aggregator::{PathId, ReordererConfig, SymbolReorderer};
use asupersync::types::{Symbol, Time};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, HashMap, HashSet};

const INITIAL_NEXT_EXPECTED: u64 = 1_u64 << 32;
const MAX_STEPS: usize = 128;
const MAX_PATHS: usize = 4;
const MAX_STREAMS: usize = 8;
const MAX_PAYLOAD_LEN: usize = 32;
const FINAL_FLUSH_NANOS: u64 = 1_000_000_000;

#[derive(Arbitrary, Debug)]
struct SlidingWindowInput {
    max_wait_ms: u8,
    max_buffer_per_object: u8,
    max_sequence_gap: u8,
    steps: Vec<SlidingStep>,
}

#[derive(Arbitrary, Debug)]
enum SlidingStep {
    Deliver {
        advance_ms: u8,
        stream: u8,
        path: u8,
        sequence_plan: SequencePlan,
        payload: Vec<u8>,
    },
    Flush {
        advance_ms: u8,
    },
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum SequencePlan {
    Expected,
    Ahead { gap: u8 },
    ExceedGap { extra: u8 },
    Late { delta: u8 },
    Raw(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct StreamKey {
    object: u64,
    sbn: u8,
}

impl StreamKey {
    fn from_index(index: u8) -> Self {
        let idx = usize::from(index) % MAX_STREAMS;
        Self {
            object: u64::from((idx % 4) as u8 + 1),
            sbn: ((idx / 4) as u8) % 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct SymbolKey {
    stream: StreamKey,
    esi: u32,
}

impl SymbolKey {
    fn to_symbol(self, payload: &[u8]) -> Symbol {
        Symbol::new_for_test(self.stream.object, self.stream.sbn, self.esi, payload)
    }

    fn from_symbol(symbol: &Symbol) -> Self {
        Self {
            stream: StreamKey {
                object: symbol.object_id().low(),
                sbn: symbol.sbn(),
            },
            esi: symbol.esi(),
        }
    }
}

#[derive(Clone, Debug)]
struct BufferedModelSymbol {
    key: SymbolKey,
    received_at: Time,
}

#[derive(Debug)]
struct WindowModelState {
    next_expected: u64,
    buffer: BTreeMap<u64, BufferedModelSymbol>,
}

impl WindowModelState {
    fn new() -> Self {
        Self {
            next_expected: INITIAL_NEXT_EXPECTED,
            buffer: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
struct SlidingWindowModel {
    max_wait_nanos: u64,
    max_buffer_per_object: usize,
    max_sequence_gap: u32,
    states: HashMap<StreamKey, WindowModelState>,
    in_order_deliveries: u64,
    reordered_deliveries: u64,
    timeout_deliveries: u64,
}

impl SlidingWindowModel {
    fn new(max_wait_nanos: u64, max_buffer_per_object: usize, max_sequence_gap: u32) -> Self {
        Self {
            max_wait_nanos,
            max_buffer_per_object,
            max_sequence_gap,
            states: HashMap::new(),
            in_order_deliveries: 0,
            reordered_deliveries: 0,
            timeout_deliveries: 0,
        }
    }

    fn next_expected_for(&self, stream: StreamKey) -> u64 {
        self.states
            .get(&stream)
            .map_or(INITIAL_NEXT_EXPECTED, |state| state.next_expected)
    }

    fn materialize_sequence(&self, stream: StreamKey, plan: SequencePlan) -> u32 {
        let next_expected = self.next_expected_for(stream);
        match plan {
            SequencePlan::Expected => next_expected as u32,
            SequencePlan::Ahead { gap } => next_expected.wrapping_add(1 + u64::from(gap)) as u32,
            SequencePlan::ExceedGap { extra } => next_expected
                .wrapping_add(u64::from(self.max_sequence_gap) + 1 + u64::from(extra))
                as u32,
            SequencePlan::Late { delta } => next_expected.wrapping_sub(1 + u64::from(delta)) as u32,
            SequencePlan::Raw(esi) => esi,
        }
    }

    fn process(&mut self, key: SymbolKey, now: Time) -> Vec<SymbolKey> {
        let state = self
            .states
            .entry(key.stream)
            .or_insert_with(WindowModelState::new);
        let mut ready = Vec::new();

        #[allow(clippy::cast_possible_wrap)]
        let diff = key.esi.wrapping_sub(state.next_expected as u32) as i32;

        if diff == 0 {
            ready.push(key);
            state.next_expected = state.next_expected.wrapping_add(1);
            self.in_order_deliveries = self.in_order_deliveries.saturating_add(1);

            while let Some(buffered) = state.buffer.remove(&state.next_expected) {
                ready.push(buffered.key);
                state.next_expected = state.next_expected.wrapping_add(1);
                self.reordered_deliveries = self.reordered_deliveries.saturating_add(1);
            }
            return ready;
        }

        if diff > 0 {
            #[allow(clippy::cast_sign_loss)]
            let gap = diff as u64;
            let seq_unwrapped = state.next_expected + gap;

            if gap <= u64::from(self.max_sequence_gap)
                && state.buffer.len() < self.max_buffer_per_object
            {
                state.buffer.insert(
                    seq_unwrapped,
                    BufferedModelSymbol {
                        key,
                        received_at: now,
                    },
                );
                return ready;
            }

            state.buffer.insert(
                seq_unwrapped,
                BufferedModelSymbol {
                    key,
                    received_at: now,
                },
            );

            for (seq, buffered) in std::mem::take(&mut state.buffer) {
                ready.push(buffered.key);
                self.timeout_deliveries = self.timeout_deliveries.saturating_add(1);
                state.next_expected = seq.wrapping_add(1);
            }
        }

        ready
    }

    fn flush(&mut self, now: Time) -> Vec<SymbolKey> {
        let mut flushed = Vec::new();
        for state in self.states.values_mut() {
            let mut max_timeout_seq = None;

            for (&seq_unwrapped, buffered) in &state.buffer {
                let wait_nanos = now
                    .as_nanos()
                    .saturating_sub(buffered.received_at.as_nanos());
                if wait_nanos >= self.max_wait_nanos {
                    max_timeout_seq = Some(seq_unwrapped);
                }
            }

            if let Some(cutoff) = max_timeout_seq {
                let to_flush = if cutoff == u64::MAX {
                    std::mem::take(&mut state.buffer)
                } else {
                    let keep = state.buffer.split_off(&(cutoff + 1));
                    std::mem::replace(&mut state.buffer, keep)
                };

                for (_, buffered) in to_flush {
                    flushed.push(buffered.key);
                    self.timeout_deliveries = self.timeout_deliveries.saturating_add(1);
                }

                if cutoff >= state.next_expected {
                    state.next_expected = cutoff.wrapping_add(1);
                }
            }

            while let Some(buffered) = state.buffer.remove(&state.next_expected) {
                flushed.push(buffered.key);
                state.next_expected = state.next_expected.wrapping_add(1);
                self.reordered_deliveries = self.reordered_deliveries.saturating_add(1);
            }
        }

        flushed
    }

    fn buffered_count(&self) -> usize {
        self.states.values().map(|state| state.buffer.len()).sum()
    }
}

fn advance_time(now_nanos: &mut u64, advance_ms: u8) -> Time {
    *now_nanos = now_nanos.saturating_add(u64::from(advance_ms).saturating_mul(1_000_000));
    Time::from_nanos(*now_nanos)
}

fn symbol_keys(symbols: &[Symbol]) -> Vec<SymbolKey> {
    symbols.iter().map(SymbolKey::from_symbol).collect()
}

fn record_deliveries(delivered: &mut HashSet<SymbolKey>, ready: &[SymbolKey]) {
    for &key in ready {
        assert!(
            delivered.insert(key),
            "duplicate sliding-window delivery for {key:?}"
        );
    }
}

fuzz_target!(|input: SlidingWindowInput| {
    if input.steps.len() > MAX_STEPS {
        return;
    }

    let max_wait_ms = u64::from(input.max_wait_ms).max(1);
    let max_buffer_per_object = usize::from(input.max_buffer_per_object).clamp(1, 8);
    let max_sequence_gap = u32::from(input.max_sequence_gap).max(1);

    let reorderer = SymbolReorderer::new(ReordererConfig {
        max_buffer_per_object,
        max_wait_time: Time::from_millis(max_wait_ms),
        immediate_delivery: false,
        max_sequence_gap,
    });
    let mut model = SlidingWindowModel::new(
        max_wait_ms.saturating_mul(1_000_000),
        max_buffer_per_object,
        max_sequence_gap,
    );
    let mut now_nanos = 0_u64;
    let mut delivered = HashSet::new();

    for step in input.steps {
        match step {
            SlidingStep::Deliver {
                advance_ms,
                stream,
                path,
                sequence_plan,
                payload,
            } => {
                let now = advance_time(&mut now_nanos, advance_ms);
                let stream = StreamKey::from_index(stream);
                let esi = model.materialize_sequence(stream, sequence_plan);
                let key = SymbolKey { stream, esi };
                let payload = &payload[..payload.len().min(MAX_PAYLOAD_LEN)];
                let symbol = key.to_symbol(payload);
                let path = PathId::new((u64::from(path) % MAX_PATHS as u64) + 1);

                let expected = model.process(key, now);
                let actual = reorderer.process(symbol, path, now);
                let actual_keys = symbol_keys(&actual);

                assert_eq!(
                    actual_keys, expected,
                    "sliding-window process output diverged for {key:?}"
                );
                record_deliveries(&mut delivered, &actual_keys);
            }
            SlidingStep::Flush { advance_ms } => {
                let now = advance_time(&mut now_nanos, advance_ms);
                let expected = model.flush(now);
                let actual = reorderer.flush_timeouts(now);
                let actual_keys = symbol_keys(&actual);

                assert_eq!(
                    actual_keys, expected,
                    "sliding-window flush output diverged"
                );
                record_deliveries(&mut delivered, &actual_keys);
            }
        }
    }

    let final_now = Time::from_nanos(now_nanos.saturating_add(FINAL_FLUSH_NANOS));
    let expected_final = model.flush(final_now);
    let actual_final = reorderer.flush_timeouts(final_now);
    let actual_final_keys = symbol_keys(&actual_final);
    assert_eq!(
        actual_final_keys, expected_final,
        "final sliding-window flush diverged"
    );
    record_deliveries(&mut delivered, &actual_final_keys);

    let stats = reorderer.stats();
    assert_eq!(stats.objects_tracked, model.states.len());
    assert_eq!(stats.symbols_buffered, model.buffered_count());
    assert_eq!(stats.symbols_buffered, 0);
    assert_eq!(stats.in_order_deliveries, model.in_order_deliveries);
    assert_eq!(stats.reordered_deliveries, model.reordered_deliveries);
    assert_eq!(stats.timeout_deliveries, model.timeout_deliveries);
});
