#![no_main]

//! Stateful rewind/re-read oracle for `asupersync::trace::file::TraceReader`.
//!
//! Bead asupersync-t5hwlb. The existing trace-file fuzz targets
//! (`trace_file_parsing.rs`, `trace_file_durability.rs`) exercise adversarial
//! byte streams and write→read round-trips, but neither drives the stateful
//! `rewind()` → re-read contract:
//!
//!   1. After `read_event` has succeeded N times, `rewind()` must reset the
//!      reader to `events_start_pos`, set `events_read = 0`, and (for compressed
//!      files) clear `decompressed_buffer` + `buffer_pos`.
//!   2. A second `read_event` loop after `rewind()` MUST yield the same event
//!      sequence byte-for-byte (via `rmp_serde` round-trip equality) as the
//!      first pass.
//!   3. A partial first pass followed by `rewind()` followed by a second full
//!      pass must NOT skip, duplicate, or reorder any event.
//!
//! An adversarial file that exploits a subtle state bug — leftover bytes in
//! `decompressed_buffer`, an off-by-one `events_read` reset, or a seek target
//! that is not `events_start_pos` — would slip past crash-only coverage. This
//! harness catches it by comparing the pass-1 and pass-2 event-sequence
//! vectors for semantic equality.
//!
//! Archetype: stateful (shadow model = the first-pass event vector).

use asupersync::trace::file::{
    CompressionMode, TraceFileConfig, TraceFileError, TraceReader, TraceWriter,
};
use asupersync::trace::replay::{CompactTaskId, ReplayEvent, TraceMetadata};
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU64, Ordering};

/// Upper bound on generated events per fuzz iteration. Keeps exec/s above the
/// ≥100 ops/s stateful floor even on slow workers.
const MAX_EVENTS: usize = 128;

/// Upper bound on input bytes. Guards against OOM and per-iter timeouts.
const MAX_INPUT: usize = 64 * 1024;

fn observe_writer_result(context: &str, result: Result<(), TraceFileError>) -> bool {
    match result {
        Ok(()) => true,
        Err(TraceFileError::Io(_))
        | Err(TraceFileError::Serialize(_))
        | Err(TraceFileError::Compression(_))
        | Err(TraceFileError::AlreadyFinished)
        | Err(TraceFileError::MetadataNotWritten)
        | Err(TraceFileError::MetadataAlreadyWritten)
        | Err(TraceFileError::MetadataCorrupt) => false,
        Err(error) => panic!("{context} returned unexpected trace writer error: {error:?}"),
    }
}

fn expect_file_rewind(context: &str, result: Result<(), TraceFileError>) {
    if let Err(error) = result {
        panic!("{context} failed on a file-backed TraceReader: {error:?}");
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 || data.len() > MAX_INPUT {
        return;
    }

    // Derive event count, compression mode, and split-point offsets from the
    // fuzzer input. All derived values are bounded so exec/s stays stable.
    let n_events = 1 + (data[0] as usize) % MAX_EVENTS;
    let compression = match data[1] & 0x3 {
        0 => CompressionMode::None,
        _ => CompressionMode::Lz4 { level: 1 },
    };
    let k1 = (data[2] as usize) % (n_events + 1);
    let k2 = (data[3] as usize) % (n_events + 1);

    // Build a valid trace on a per-iteration tempfile because TraceWriter
    // owns its Write half (only Path-based constructors are public). We
    // reopen via TraceReader::open on the same tempfile so the rewind/re-read
    // oracle runs against the production path-based reader.
    //
    // Filename includes a per-iter atomic counter + the process PID so
    // parallel fuzz workers don't collide in /tmp. We remove the file on
    // every exit path via RAII guard so the disk doesn't fill up during
    // long campaigns.
    static ITER: AtomicU64 = AtomicU64::new(0);
    let iter = ITER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "asupersync_fuzz_trace_{}_{}.bin",
        std::process::id(),
        iter,
    ));
    struct RmOnDrop(std::path::PathBuf);
    impl Drop for RmOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _rm = RmOnDrop(path.clone());

    let config = TraceFileConfig::default().with_compression(compression);
    let mut writer = match TraceWriter::create_with_config(&path, config) {
        Ok(w) => w,
        Err(_) => return,
    };

    let seed = u64::from_le_bytes([
        data.get(4).copied().unwrap_or(0),
        data.get(5).copied().unwrap_or(0),
        data.get(6).copied().unwrap_or(0),
        data.get(7).copied().unwrap_or(0),
        0,
        0,
        0,
        0,
    ]);
    if !observe_writer_result(
        "rewind metadata write",
        writer.write_metadata(&TraceMetadata::new(seed)),
    ) {
        return;
    }

    // Deterministic event corpus: alternate two shapes so a state bug that
    // swaps neighboring events shows up as a discriminable type mismatch on
    // the round-trip comparison.
    for i in 0..n_events {
        let event = if i & 1 == 0 {
            // CompactTaskId is a transparent u64 wrapper (packed
            // index<<32 | generation). Use the i-th index / gen=0 so the
            // generated id is trivially distinguishable across events.
            ReplayEvent::task_scheduled(CompactTaskId((i as u64) << 32), i as u64)
        } else {
            ReplayEvent::TimeAdvanced {
                from_nanos: i as u64,
                to_nanos: (i as u64).saturating_add(1),
            }
        };
        if !observe_writer_result("rewind event write", writer.write_event(&event)) {
            return;
        }
    }
    if !observe_writer_result("rewind finish", writer.finish()) {
        return;
    }

    // ---- Pass 1: baseline read-all ----
    let mut reader = match TraceReader::open(&path) {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut pass1: Vec<ReplayEvent> = Vec::with_capacity(n_events);
    loop {
        match reader.read_event() {
            Ok(Some(e)) => pass1.push(e),
            Ok(None) => break,
            Err(_) => return,
        }
    }
    assert_eq!(
        pass1.len(),
        n_events,
        "pass-1 event count diverged from writer count"
    );

    // ---- Pass 2: partial-read(k1) → rewind → read-all ----
    let mut reader2 = match TraceReader::open(&path) {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut partial: Vec<ReplayEvent> = Vec::with_capacity(k1);
    for _ in 0..k1 {
        match reader2.read_event() {
            Ok(Some(e)) => partial.push(e),
            Ok(None) => break,
            Err(_) => return,
        }
    }
    assert_eq!(
        partial.as_slice(),
        &pass1[..partial.len()],
        "prefix read diverged from pass-1 prefix before rewind"
    );

    // Rewind MAY fail on a non-seekable reader; TraceReader::open is seekable, so this
    // branch is a bug — flag loudly rather than silently returning.
    expect_file_rewind("first rewind", reader2.rewind());
    assert_eq!(
        reader2.events_read(),
        0,
        "rewind did not reset events_read to 0"
    );

    let mut pass2: Vec<ReplayEvent> = Vec::with_capacity(n_events);
    loop {
        match reader2.read_event() {
            Ok(Some(e)) => pass2.push(e),
            Ok(None) => break,
            Err(_) => return,
        }
    }
    assert_eq!(
        pass2, pass1,
        "post-rewind full read diverged from pass-1 (stateful-rewind bug)"
    );

    // ---- Pass 3: rewind-again → partial-read(k2) must match pass-1 prefix ----
    expect_file_rewind("second rewind", reader2.rewind());
    let mut tail: Vec<ReplayEvent> = Vec::with_capacity(k2);
    for _ in 0..k2 {
        match reader2.read_event() {
            Ok(Some(e)) => tail.push(e),
            Ok(None) => break,
            Err(_) => return,
        }
    }
    assert_eq!(
        tail.as_slice(),
        &pass1[..tail.len()],
        "post-second-rewind prefix diverged from pass-1"
    );
});
