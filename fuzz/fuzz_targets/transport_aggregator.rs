#![no_main]

use arbitrary::Arbitrary;
use asupersync::transport::aggregator::{
    AggregatorConfig, DeduplicatorConfig, MultipathAggregator, PathCharacteristics, ReordererConfig,
};
use asupersync::types::{Symbol, Time};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, HashMap, HashSet};

const MAX_OPERATIONS: usize = 128;
const MAX_PATHS: usize = 4;
const MAX_OBJECTS: u8 = 8;
const MAX_PAYLOAD_LEN: usize = 32;
const FINAL_FLUSH_NANOS: u64 = 1_000_000_000;
const DEDUP_ENTRY_TTL_SECS: u64 = 1_000_000;

#[derive(Arbitrary, Debug)]
struct TransportAggregatorInput {
    flush_interval_ms: u8,
    max_wait_ms: u8,
    max_buffer_per_object: u8,
    max_sequence_gap: u8,
    path_count: u8,
    operations: Vec<AggregatorOperation>,
}

#[derive(Arbitrary, Debug)]
enum AggregatorOperation {
    Process {
        advance_ms: u8,
        object: u8,
        sbn: u8,
        esi: u32,
        path_index: u8,
        payload: Vec<u8>,
    },
    Flush {
        advance_ms: u8,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct SymbolKey {
    object: u64,
    sbn: u8,
    esi: u32,
}

impl SymbolKey {
    fn from_symbol(symbol: &Symbol) -> Self {
        Self {
            object: symbol.object_id().low(),
            sbn: symbol.sbn(),
            esi: symbol.esi(),
        }
    }

    fn from_input(object: u8, sbn: u8, esi: u32) -> Self {
        Self {
            object: u64::from((object % MAX_OBJECTS) + 1),
            sbn: sbn % 2,
            esi,
        }
    }

    fn to_symbol(self, payload: &[u8]) -> Symbol {
        Symbol::new_for_test(self.object, self.sbn, self.esi, payload)
    }
}

#[derive(Clone, Debug)]
struct BufferedModelSymbol {
    key: SymbolKey,
    received_at: Time,
}

#[derive(Debug)]
struct ObjectModelState {
    next_expected: u64,
    buffer: BTreeMap<u64, BufferedModelSymbol>,
}

impl ObjectModelState {
    fn new() -> Self {
        Self {
            next_expected: 1_u64 << 32,
            buffer: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
struct AggregatorModel {
    flush_interval_nanos: u64,
    max_wait_nanos: u64,
    max_buffer_per_object: usize,
    max_sequence_gap: u32,
    last_flush_nanos: u64,
    total_processed: u64,
    unique_symbols: u64,
    duplicates_detected: u64,
    seen_objects: HashSet<u64>,
    seen_symbols: HashSet<SymbolKey>,
    reorder_objects: HashMap<(u64, u8), ObjectModelState>,
}

impl AggregatorModel {
    fn new(
        flush_interval_nanos: u64,
        max_wait_nanos: u64,
        max_buffer_per_object: usize,
        max_sequence_gap: u32,
    ) -> Self {
        Self {
            flush_interval_nanos,
            max_wait_nanos,
            max_buffer_per_object,
            max_sequence_gap,
            last_flush_nanos: 0,
            total_processed: 0,
            unique_symbols: 0,
            duplicates_detected: 0,
            seen_objects: HashSet::new(),
            seen_symbols: HashSet::new(),
            reorder_objects: HashMap::new(),
        }
    }

    fn process(&mut self, key: SymbolKey, now: Time) -> (Vec<SymbolKey>, bool) {
        self.total_processed += 1;

        if !self.seen_symbols.insert(key) {
            self.duplicates_detected += 1;
            return (Vec::new(), true);
        }

        self.unique_symbols += 1;
        self.seen_objects.insert(key.object);

        let state = self
            .reorder_objects
            .entry((key.object, key.sbn))
            .or_insert_with(ObjectModelState::new);
        let mut ready = Vec::new();

        #[allow(clippy::cast_possible_wrap)]
        let diff = key.esi.wrapping_sub(state.next_expected as u32) as i32;

        if diff == 0 {
            ready.push(key);
            state.next_expected = state.next_expected.wrapping_add(1);
            while let Some(buffered) = state.buffer.remove(&state.next_expected) {
                ready.push(buffered.key);
                state.next_expected = state.next_expected.wrapping_add(1);
            }
            return (ready, false);
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
                return (ready, false);
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
                state.next_expected = seq.wrapping_add(1);
            }
        }

        (ready, false)
    }

    fn flush(&mut self, now: Time) -> Vec<SymbolKey> {
        if now.as_nanos().saturating_sub(self.last_flush_nanos) < self.flush_interval_nanos {
            return Vec::new();
        }
        self.last_flush_nanos = now.as_nanos();

        let mut flushed = Vec::new();
        for state in self.reorder_objects.values_mut() {
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
                }

                if cutoff >= state.next_expected {
                    state.next_expected = cutoff.wrapping_add(1);
                }
            }

            while let Some(buffered) = state.buffer.remove(&state.next_expected) {
                flushed.push(buffered.key);
                state.next_expected = state.next_expected.wrapping_add(1);
            }
        }

        flushed
    }

    fn buffered_count(&self) -> usize {
        self.reorder_objects
            .values()
            .map(|state| state.buffer.len())
            .sum()
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
        assert!(delivered.insert(key), "duplicate delivery for {key:?}");
    }
}

fuzz_target!(|input: TransportAggregatorInput| {
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    let flush_interval_ms = u64::from(input.flush_interval_ms).max(1);
    let max_wait_ms = u64::from(input.max_wait_ms).max(1);
    let max_buffer_per_object = usize::from(input.max_buffer_per_object).clamp(1, 8);
    let max_sequence_gap = u32::from(input.max_sequence_gap).max(1);
    let path_count = usize::from(input.path_count).clamp(1, MAX_PATHS);

    let config = AggregatorConfig {
        dedup: DeduplicatorConfig {
            max_symbols_per_object: MAX_OPERATIONS,
            max_objects: usize::from(MAX_OBJECTS),
            entry_ttl: Time::from_secs(DEDUP_ENTRY_TTL_SECS),
            track_path: true,
        },
        reorder: ReordererConfig {
            max_buffer_per_object,
            max_wait_time: Time::from_millis(max_wait_ms),
            immediate_delivery: false,
            max_sequence_gap,
        },
        flush_interval: Time::from_millis(flush_interval_ms),
        ..AggregatorConfig::default()
    };

    let aggregator = MultipathAggregator::new(config);
    let mut paths = Vec::with_capacity(path_count);
    for index in 0..path_count {
        let path = aggregator.paths().create_path(
            format!("path-{index}"),
            format!("127.0.0.1:{}", 9000 + index),
            PathCharacteristics::default(),
        );
        paths.push(path);
    }

    let mut model = AggregatorModel::new(
        flush_interval_ms.saturating_mul(1_000_000),
        max_wait_ms.saturating_mul(1_000_000),
        max_buffer_per_object,
        max_sequence_gap,
    );
    let mut now_nanos = 0_u64;
    let mut delivered = HashSet::new();

    for operation in input.operations {
        match operation {
            AggregatorOperation::Process {
                advance_ms,
                object,
                sbn,
                esi,
                path_index,
                payload,
            } => {
                let now = advance_time(&mut now_nanos, advance_ms);
                let key = SymbolKey::from_input(object, sbn, esi);
                let payload = &payload[..payload.len().min(MAX_PAYLOAD_LEN)];
                let symbol = key.to_symbol(payload);
                let path = paths[usize::from(path_index) % paths.len()];

                let (expected_ready, expected_duplicate) = model.process(key, now);
                let actual = aggregator.process(symbol, path, now);
                let actual_ready = symbol_keys(&actual.ready);

                assert_eq!(actual.path, path, "aggregator reported wrong path");
                assert_eq!(
                    actual.was_duplicate, expected_duplicate,
                    "duplicate classification diverged for {key:?}"
                );
                assert_eq!(
                    actual_ready, expected_ready,
                    "process output diverged for {key:?}"
                );
                record_deliveries(&mut delivered, &actual_ready);
            }
            AggregatorOperation::Flush { advance_ms } => {
                let now = advance_time(&mut now_nanos, advance_ms);
                let expected = model.flush(now);
                let actual = aggregator.flush(now);
                let actual_ready = symbol_keys(&actual);
                assert_eq!(actual_ready, expected, "flush output diverged");
                record_deliveries(&mut delivered, &actual_ready);
            }
        }
    }

    let final_now = Time::from_nanos(now_nanos.saturating_add(FINAL_FLUSH_NANOS));
    let expected_final = model.flush(final_now);
    let actual_final = aggregator.flush(final_now);
    let actual_final_ready = symbol_keys(&actual_final);
    assert_eq!(actual_final_ready, expected_final, "final flush diverged");
    record_deliveries(&mut delivered, &actual_final_ready);

    let stats = aggregator.stats();
    assert_eq!(stats.total_processed, model.total_processed);
    assert_eq!(stats.dedup.unique_symbols, model.unique_symbols);
    assert_eq!(stats.dedup.duplicates_detected, model.duplicates_detected);
    assert_eq!(stats.dedup.objects_tracked, model.seen_objects.len());
    assert_eq!(stats.dedup.symbols_tracked as u64, model.unique_symbols);
    assert_eq!(stats.reorder.objects_tracked, model.reorder_objects.len());
    assert_eq!(stats.reorder.symbols_buffered, model.buffered_count());
    assert_eq!(stats.reorder.symbols_buffered, 0);
});
