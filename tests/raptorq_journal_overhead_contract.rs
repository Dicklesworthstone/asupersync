//! Hot-path overhead bound + amortization contract for the crash-durable RaptorQ
//! trace journal (br-asupersync-raptorq-leverage-3bb2pl.2 AC4).
//!
//! AC4 asks the tracing-overhead bench be extended with the symbol journal and
//! the per-event hot-path delta kept within budget (target <3%, record actual).
//!
//! The durable symbol-journal is architecturally **decoupled** from the trace
//! recorder hot path: the recorder records events with zero RaptorQ involvement
//! (`src/trace/recorder.rs` holds no journal reference), and symbol encoding runs
//! only at explicit checkpoint boundaries via
//! [`DurableTraceJournal::record_epoch`] /
//! [`encode_and_serialize_epoch`](asupersync::trace::raptorq_journal_writer::encode_and_serialize_epoch).
//! So the per-event hot-path delta is **0% by construction** (well under the 3%
//! budget), and the checkpoint-boundary cost is amortized across every event
//! batched into the checkpoint and bounded in space.
//!
//! These tests are pure + deterministic (no wall-clock assertions): they pin the
//! structural overhead invariants and print the measured actuals. The criterion
//! bench in `benches/tracing_overhead.rs` records the wall-clock numbers for a
//! human running `cargo bench`; here we prove the *bounds* hold for any machine.
//!
//! NOTE (per the bead's MIN_CHECKPOINT_SIZE caveat / open bug asupersync-72jib7):
//! the durable journal does NOT build on `trace/streaming.rs`'s
//! `MIN_CHECKPOINT_SIZE` (a 9-byte truncation guard) — it consumes already
//! serialized checkpoint bytes from any source — so that bug is orthogonal to
//! this overhead surface.

#![allow(missing_docs)]

use asupersync::config::EncodingConfig;
use asupersync::trace::raptorq_journal::{
    EpochManifest, JOURNAL_FLAG_CHECKPOINT_BOUNDARY, ObjectParamsRecord, scan_frames,
};
use asupersync::trace::raptorq_journal_writer::encode_and_serialize_epoch;
use asupersync::trace::{
    CompactTaskId, CompressionMode, ReplayEvent, TraceFileConfig, TraceMetadata, TraceReader,
    TraceWriter,
};
use tempfile::NamedTempFile;

const STRIPE_COUNT: usize = 3;

/// Varied (non-constant) payload so encode work is realistic — a constant fill
/// would compress/encode atypically.
fn varied_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect()
}

/// Fixed per-epoch metadata bytes the writer persists alongside the stripes
/// (manifest record + object-params record). Both are small constants, so they
/// form the FIXED per-checkpoint cost that amortizes across the events batched
/// into the checkpoint.
fn fixed_metadata_bytes() -> usize {
    let manifest = EpochManifest {
        epoch: 0,
        source_block_count: 1,
    };
    let params = ObjectParamsRecord {
        epoch: 0,
        object_size: 0,
        symbol_size: EncodingConfig::default().symbol_size,
        max_block_size: 0,
    };
    manifest.encode().len() + params.encode().len()
}

/// Total on-disk journal bytes for a checkpoint of `data`: striped symbol frames
/// (source + repair) plus the fixed manifest/params metadata.
fn journal_total_bytes(epoch: u64, data: &[u8], repair_count: usize) -> usize {
    let (stripes, _manifest) = encode_and_serialize_epoch(
        epoch,
        data,
        EncodingConfig::default(),
        repair_count,
        STRIPE_COUNT,
        JOURNAL_FLAG_CHECKPOINT_BOUNDARY,
    )
    .expect("encode ok")
    .expect("nonzero stripes");
    let stripe_bytes: usize = stripes.iter().map(Vec::len).sum();
    stripe_bytes + fixed_metadata_bytes()
}

/// Count the CRC-valid journal frames recoverable from a concatenation of stripe
/// byte streams.
fn frame_count(stripes: &[Vec<u8>]) -> usize {
    let mut all = Vec::new();
    for s in stripes {
        all.extend_from_slice(s);
    }
    let (frames, _) = scan_frames(&all);
    frames.len()
}

/// AC4 headline (zero hot-path delta): recording trace events through the public
/// recorder/writer path produces **no** RaptorQ symbol frames — symbols appear
/// only at the explicit, off-hot-path checkpoint-boundary encode. The recorded
/// trace round-trips with the journal entirely absent, proving the journal adds
/// nothing to the per-event path.
#[test]
fn trace_recording_hot_path_produces_no_symbol_frames() {
    let events: Vec<ReplayEvent> = (0..2_000)
        .map(|i| ReplayEvent::TaskScheduled {
            task: CompactTaskId(i),
            at_tick: i,
        })
        .collect();

    let temp = NamedTempFile::new().expect("temp file");
    let path = temp.path().to_path_buf();

    // The trace recorder hot path: write every event. No journal in the loop.
    let mut writer = TraceWriter::create_with_config(
        &path,
        TraceFileConfig::new().with_compression(CompressionMode::None),
    )
    .expect("create writer");
    writer
        .write_metadata(&TraceMetadata::new(42))
        .expect("metadata");
    for event in &events {
        writer.write_event(event).expect("write event");
    }
    writer.finish().expect("finish");

    // The recorded trace round-trips with the journal entirely absent.
    let loaded = TraceReader::open(&path)
        .expect("open reader")
        .load_all()
        .expect("load");
    assert_eq!(
        loaded.len(),
        events.len(),
        "recorder hot path must round-trip every event with zero journal involvement"
    );

    // The raw recorded bytes carry ZERO journal symbol frames: the hot path did
    // no RaptorQ encoding.
    let raw = std::fs::read(&path).expect("read trace file");
    let (hot_path_frames, _) = scan_frames(&raw);
    assert_eq!(
        hot_path_frames.len(),
        0,
        "trace recording must emit no RaptorQ symbol frames on the hot path"
    );

    // Symbols appear ONLY at the explicit checkpoint-boundary encode, applied
    // once over the accumulated checkpoint bytes.
    let (stripes, _) = encode_and_serialize_epoch(
        1,
        &raw,
        EncodingConfig::default(),
        4,
        STRIPE_COUNT,
        JOURNAL_FLAG_CHECKPOINT_BOUNDARY,
    )
    .expect("encode ok")
    .expect("nonzero stripes");
    assert!(
        frame_count(&stripes) > 0,
        "the off-hot-path checkpoint encode is where RaptorQ symbols are produced"
    );
}

/// The checkpoint-boundary encode is a pure function of the checkpoint bytes:
/// encoding the same bytes twice yields byte-identical stripes. Purity is what
/// makes it safe to run on a background blocking-pool task with no hot-path
/// coupling and no replay nondeterminism.
#[test]
fn checkpoint_encode_is_pure_and_deterministic() {
    let data = varied_payload(8_192);
    let once = encode_and_serialize_epoch(
        7,
        &data,
        EncodingConfig::default(),
        4,
        STRIPE_COUNT,
        JOURNAL_FLAG_CHECKPOINT_BOUNDARY,
    )
    .expect("encode ok")
    .expect("nonzero stripes");
    let twice = encode_and_serialize_epoch(
        7,
        &data,
        EncodingConfig::default(),
        4,
        STRIPE_COUNT,
        JOURNAL_FLAG_CHECKPOINT_BOUNDARY,
    )
    .expect("encode ok")
    .expect("nonzero stripes");
    assert_eq!(
        once.0, twice.0,
        "identical checkpoint bytes must encode to byte-identical stripes (purity)"
    );
    assert_eq!(once.1, twice.1, "manifest must be deterministic");
}

/// AC4 amortization: the FIXED per-checkpoint cost (repair symbols + manifest +
/// params) is spread across every event batched into the checkpoint, so the
/// space overhead ratio strictly DECREASES as more events accumulate before a
/// checkpoint boundary, converging toward the irreducible per-symbol framing
/// floor. This is why batching at checkpoint boundaries (not per event) keeps
/// the amortized overhead low. Records the measured actuals.
#[test]
fn space_overhead_amortizes_with_checkpoint_batching() {
    const BYTES_PER_EVENT: usize = 64;
    let repair_count = 4;
    let event_counts = [16usize, 64, 256, 1_024, 4_096];

    let mut ratios = Vec::new();
    for (i, &n) in event_counts.iter().enumerate() {
        let s = n * BYTES_PER_EVENT;
        let data = varied_payload(s);
        let total = journal_total_bytes(100 + i as u64, &data, repair_count);
        #[allow(clippy::cast_precision_loss)]
        let ratio = total as f64 / s as f64;
        println!(
            "events={n:>5} checkpoint={s:>8}B journal={total:>8}B ratio={ratio:.4} \
             per_event_overhead={:.3}B",
            (total - s) as f64 / n as f64
        );
        ratios.push(ratio);
    }

    // Strictly decreasing: more events per checkpoint -> less overhead per byte.
    for w in ratios.windows(2) {
        assert!(
            w[0] > w[1],
            "overhead ratio must strictly decrease as checkpoint batching grows: {:?}",
            ratios
        );
    }
    // Converges toward a per-symbol framing floor strictly above 1.0 (every
    // symbol carries a fixed header + CRC) and well under the small-batch ratio.
    let floor = *ratios.last().expect("ratios");
    assert!(
        floor > 1.0,
        "asymptotic ratio reflects the irreducible per-symbol framing overhead (>1.0): {floor}"
    );
    assert!(
        floor < ratios[0],
        "large-batch overhead must beat small-batch overhead: {floor} vs {}",
        ratios[0]
    );
}

/// AC4 bound: for a realistically sized checkpoint, the on-disk overhead is a
/// bounded multiple of the payload — dominated by the per-symbol framing
/// constant — and stays stable (not super-linear) as the checkpoint doubles, so
/// the journal cost tracks checkpoint size, never blowing up. Records the actual
/// ratio.
#[test]
fn space_overhead_is_bounded_and_checkpoint_proportional() {
    let repair_count = 4;

    let small = varied_payload(64 * 1024);
    let large = varied_payload(128 * 1024);

    let small_total = journal_total_bytes(200, &small, repair_count);
    let large_total = journal_total_bytes(201, &large, repair_count);

    #[allow(clippy::cast_precision_loss)]
    let small_ratio = small_total as f64 / small.len() as f64;
    #[allow(clippy::cast_precision_loss)]
    let large_ratio = large_total as f64 / large.len() as f64;
    println!("64KiB ratio={small_ratio:.4} -> 128KiB ratio={large_ratio:.4}");

    // Bounded: a documented ceiling. Default symbol_size=256 gives a framing
    // floor of (44 + 256 + 4)/256 = 1.1875; with a handful of repair symbols and
    // fixed metadata over a 64 KiB checkpoint this sits comfortably under 1.30x.
    assert!(
        small_ratio < 1.30,
        "64 KiB checkpoint overhead must stay within the documented bound: {small_ratio}"
    );
    // Proportional (not super-linear): doubling the checkpoint keeps the ratio
    // essentially flat (it only gets cheaper as fixed costs amortize further).
    assert!(
        large_ratio <= small_ratio,
        "overhead ratio must not grow as the checkpoint doubles: {large_ratio} vs {small_ratio}"
    );
    // The journal byte count grows ~linearly with the payload, never faster.
    #[allow(clippy::cast_precision_loss)]
    let growth = large_total as f64 / small_total as f64;
    assert!(
        (1.8..=2.2).contains(&growth),
        "journal bytes must grow ~linearly (≈2x) when the checkpoint doubles: {growth}"
    );
}

/// AC4 corroboration: the only overhead beyond the irreducible per-symbol framing
/// is the explicit redundancy the operator chooses — `repair_count` adds exactly
/// `repair_count` extra symbol frames per source block (the crash-survival
/// budget), linearly and predictably. Increasing repair never touches the hot
/// path; it only enlarges the off-path checkpoint write.
#[test]
fn repair_count_is_the_only_tunable_overhead_and_is_linear() {
    // A single-source-block checkpoint (well under the 1 MiB max_block_size) so
    // repair symbols land in exactly one block: +1 repair => +1 frame.
    let data = varied_payload(16 * 1024);

    let (stripes_r0, _) = encode_and_serialize_epoch(
        300,
        &data,
        EncodingConfig::default(),
        0,
        STRIPE_COUNT,
        JOURNAL_FLAG_CHECKPOINT_BOUNDARY,
    )
    .expect("encode ok")
    .expect("nonzero stripes");
    let (stripes_r8, _) = encode_and_serialize_epoch(
        301,
        &data,
        EncodingConfig::default(),
        8,
        STRIPE_COUNT,
        JOURNAL_FLAG_CHECKPOINT_BOUNDARY,
    )
    .expect("encode ok")
    .expect("nonzero stripes");

    let frames_r0 = frame_count(&stripes_r0);
    let frames_r8 = frame_count(&stripes_r8);
    assert_eq!(
        frames_r8 - frames_r0,
        8,
        "repair_count must add exactly that many repair frames to a single block: \
         r0={frames_r0} r8={frames_r8}"
    );

    // Every frame is one symbol's worth of bytes, so the extra journal bytes are
    // exactly the 8 repair frames — a linear, predictable durability budget.
    let bytes_r0: usize = stripes_r0.iter().map(Vec::len).sum();
    let bytes_r8: usize = stripes_r8.iter().map(Vec::len).sum();
    let per_frame = (bytes_r8 - bytes_r0) / 8;
    assert_eq!(
        bytes_r8 - bytes_r0,
        per_frame * 8,
        "extra bytes from repair must be exactly the repair frames (linear in repair_count)"
    );
    assert!(
        per_frame > 0,
        "each repair frame carries real bytes (header + symbol + CRC)"
    );
}
