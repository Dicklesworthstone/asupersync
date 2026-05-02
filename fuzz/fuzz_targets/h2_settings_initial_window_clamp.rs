#![no_main]

use arbitrary::Arbitrary;
use asupersync::http::h2::{
    ErrorCode, Setting, Settings, SettingsBuilder, StreamStore,
    settings::{
        DEFAULT_INITIAL_WINDOW_SIZE, DEFAULT_MAX_HEADER_LIST_SIZE, MAX_INITIAL_WINDOW_SIZE,
    },
};
use libfuzzer_sys::fuzz_target;

const INVALID_INITIAL_WINDOW_SIZE: u32 = MAX_INITIAL_WINDOW_SIZE + 1;
const MAX_STREAMS: usize = 8;
const BOUNDARY_VALUES: [u32; 3] = [
    MAX_INITIAL_WINDOW_SIZE - 1,
    MAX_INITIAL_WINDOW_SIZE,
    INVALID_INITIAL_WINDOW_SIZE,
];

#[derive(Debug, Arbitrary)]
struct InitialWindowClampCase {
    stream_count: u8,
    stream_consumed: Vec<u32>,
    extra_values: Vec<BoundaryChoice>,
    use_server_store: bool,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum BoundaryChoice {
    MaxMinusOne,
    Max,
    Invalid,
    NearMax { distance: u16 },
}

fuzz_target!(|case: InitialWindowClampCase| {
    drive_initial_window_boundary_case(case);
});

fn drive_initial_window_boundary_case(case: InitialWindowClampCase) {
    let mut store = StreamStore::new(
        !case.use_server_store,
        DEFAULT_INITIAL_WINDOW_SIZE,
        DEFAULT_MAX_HEADER_LIST_SIZE,
    );
    let stream_count = usize::from(case.stream_count).min(MAX_STREAMS).max(1);
    let stream_ids = allocate_streams(&mut store, stream_count);

    for (index, stream_id) in stream_ids.iter().copied().enumerate() {
        let consumed = case
            .stream_consumed
            .get(index)
            .copied()
            .unwrap_or((index as u32).saturating_mul(17))
            % (DEFAULT_INITIAL_WINDOW_SIZE + 1);
        store
            .get_mut(stream_id)
            .expect("allocated stream must be present")
            .consume_send_window(consumed);
    }

    let mut values = Vec::from(BOUNDARY_VALUES);
    values.extend(
        case.extra_values
            .into_iter()
            .take(8)
            .map(BoundaryChoice::value),
    );

    for value in values {
        assert_builder_clamps(value);
        apply_and_verify_boundary(&mut store, &stream_ids, value);
    }
}

fn allocate_streams(store: &mut StreamStore, stream_count: usize) -> Vec<u32> {
    let mut ids = Vec::with_capacity(stream_count);
    for _ in 0..stream_count {
        let stream_id = store
            .allocate_stream_id()
            .expect("bounded sequential stream allocation should succeed");
        ids.push(stream_id);
    }
    ids
}

fn assert_builder_clamps(value: u32) {
    let settings = SettingsBuilder::new().initial_window_size(value).build();
    assert!(
        settings.initial_window_size <= MAX_INITIAL_WINDOW_SIZE,
        "SettingsBuilder must clamp INITIAL_WINDOW_SIZE to the RFC maximum"
    );
    assert_eq!(
        settings.initial_window_size,
        value.min(MAX_INITIAL_WINDOW_SIZE),
        "SettingsBuilder INITIAL_WINDOW_SIZE clamp changed semantics"
    );
}

fn apply_and_verify_boundary(store: &mut StreamStore, stream_ids: &[u32], value: u32) {
    let before_initial = store.initial_window_size();
    let before_windows = snapshot_windows(store, stream_ids);

    let mut settings = Settings::new();
    let settings_result = settings.apply(Setting::InitialWindowSize(value));

    if value > MAX_INITIAL_WINDOW_SIZE {
        let settings_error = settings_result.expect_err("2^31 INITIAL_WINDOW_SIZE must reject");
        assert_eq!(
            settings_error.code,
            ErrorCode::FlowControlError,
            "invalid INITIAL_WINDOW_SIZE must be a FLOW_CONTROL_ERROR"
        );
        assert_eq!(
            settings.initial_window_size, DEFAULT_INITIAL_WINDOW_SIZE,
            "failed Settings::apply must not mutate settings"
        );

        let store_result = store.set_initial_window_size(value);
        let store_error = store_result.expect_err("2^31 stream window update must reject");
        assert_eq!(
            store_error.code,
            ErrorCode::FlowControlError,
            "invalid stream initial-window update must be FLOW_CONTROL_ERROR"
        );
        assert_eq!(
            store.initial_window_size(),
            before_initial,
            "failed StreamStore update must not change the stored initial window"
        );
        assert_eq!(
            snapshot_windows(store, stream_ids),
            before_windows,
            "failed StreamStore update must not change stream windows"
        );
        return;
    }

    settings_result.expect("valid boundary INITIAL_WINDOW_SIZE must apply");
    assert_eq!(
        settings.initial_window_size, value,
        "valid boundary setting must be stored exactly"
    );

    let expected = expected_windows(before_initial, value, &before_windows);
    store
        .set_initial_window_size(value)
        .expect("valid boundary stream window update must not overflow");
    assert_eq!(
        store.initial_window_size(),
        value,
        "StreamStore initial window must match accepted setting"
    );
    assert_eq!(
        snapshot_windows(store, stream_ids),
        expected,
        "stream flow-control windows must shift by the exact i64-computed delta"
    );
}

fn snapshot_windows(store: &StreamStore, stream_ids: &[u32]) -> Vec<(u32, i32)> {
    stream_ids
        .iter()
        .copied()
        .map(|stream_id| {
            let window = store
                .get(stream_id)
                .expect("allocated stream must be present")
                .send_window();
            (stream_id, window)
        })
        .collect()
}

fn expected_windows(
    before_initial: u32,
    new_initial: u32,
    before_windows: &[(u32, i32)],
) -> Vec<(u32, i32)> {
    let delta = i64::from(new_initial) - i64::from(before_initial);
    before_windows
        .iter()
        .copied()
        .map(|(stream_id, before_window)| {
            let shifted = i64::from(before_window) + delta;
            let shifted = i32::try_from(shifted)
                .expect("boundary sequence should stay within signed flow-window range");
            (stream_id, shifted)
        })
        .collect()
}

impl BoundaryChoice {
    fn value(self) -> u32 {
        match self {
            Self::MaxMinusOne => MAX_INITIAL_WINDOW_SIZE - 1,
            Self::Max => MAX_INITIAL_WINDOW_SIZE,
            Self::Invalid => INVALID_INITIAL_WINDOW_SIZE,
            Self::NearMax { distance } => {
                MAX_INITIAL_WINDOW_SIZE.saturating_sub(u32::from(distance))
            }
        }
    }
}
