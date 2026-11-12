//! `QuicStream::acknowledged_send_offset`: the offset below which every byte
//! written with `write_bytes` is acknowledged. Drives the real stream queues
//! through the public `StreamTable` API (emit, ACK release, loss requeue,
//! retransmit coalescing, local reset); no packets or peer are involved.

use asupersync::bytes::Bytes;
use asupersync::net::quic_native::streams::{StreamId, StreamRole, StreamTable};

fn table_with_records(lengths: &[usize]) -> (StreamTable, StreamId) {
    let mut table = StreamTable::new(StreamRole::Client, 4, 4, 1 << 20, 1 << 20);
    let id = table.open_local_bidi().expect("open bidi");
    for (index, &len) in lengths.iter().enumerate() {
        let byte = u8::try_from(index).expect("small test");
        table
            .stream_mut(id)
            .expect("stream")
            .write_bytes(Bytes::from(vec![byte; len]), false)
            .expect("write record");
    }
    (table, id)
}

fn acknowledged(table: &StreamTable, id: StreamId) -> Option<u64> {
    table.stream(id).expect("stream").acknowledged_send_offset()
}

/// Emit every queued frame, at most `max` bytes each; return their offsets.
fn emit_all(table: &mut StreamTable, id: StreamId, max: usize) -> Vec<u64> {
    let stream = table.stream_mut(id).expect("stream");
    std::iter::from_fn(|| {
        stream
            .pop_pending_stream_frame(max)
            .map(|frame| frame.offset)
    })
    .collect()
}

#[test]
fn offset_advances_only_through_a_contiguous_acknowledged_prefix() {
    let (mut table, id) = table_with_records(&[100, 100, 100]);
    assert_eq!(
        acknowledged(&table, id),
        Some(0),
        "queued is not acknowledged"
    );
    assert_eq!(emit_all(&mut table, id, 100), [0, 100, 200]);
    assert_eq!(
        acknowledged(&table, id),
        Some(0),
        "sent is not acknowledged"
    );

    let stream = table.stream_mut(id).expect("stream");
    stream.release_sent_stream_frame(200);
    assert_eq!(
        acknowledged(&table, id),
        Some(0),
        "an ACK above the first gap must not advance the offset"
    );
    table
        .stream_mut(id)
        .expect("stream")
        .release_sent_stream_frame(0);
    assert_eq!(acknowledged(&table, id), Some(100));
    table
        .stream_mut(id)
        .expect("stream")
        .release_sent_stream_frame(100);
    assert_eq!(acknowledged(&table, id), Some(300));
    assert_eq!(table.stream(id).expect("stream").send_offset, 300);
}

#[test]
fn a_lost_frame_holds_the_offset_until_its_retransmission_is_acknowledged() {
    let (mut table, id) = table_with_records(&[100, 100]);
    assert_eq!(emit_all(&mut table, id, 100), [0, 100]);
    let stream = table.stream_mut(id).expect("stream");
    stream.release_sent_stream_frame(100);
    stream
        .requeue_sent_stream_frame(0)
        .expect("requeue lost frame");
    assert_eq!(acknowledged(&table, id), Some(0));

    assert_eq!(emit_all(&mut table, id, 100), [0], "retransmission");
    assert_eq!(acknowledged(&table, id), Some(0));
    table
        .stream_mut(id)
        .expect("stream")
        .release_sent_stream_frame(0);
    assert_eq!(acknowledged(&table, id), Some(200));
}

#[test]
fn a_coalesced_retransmission_releases_every_frame_it_carries() {
    let (mut table, id) = table_with_records(&[100, 100, 100]);
    assert_eq!(emit_all(&mut table, id, 100), [0, 100, 200]);
    let stream = table.stream_mut(id).expect("stream");
    // Requeue pushes to the front: this leaves [0, 100] queued in order,
    // and the next emission merges both into one frame at offset 0.
    stream.requeue_sent_stream_frame(100).expect("requeue");
    stream.requeue_sent_stream_frame(0).expect("requeue");
    assert_eq!(emit_all(&mut table, id, 300), [0], "one merged frame");
    table
        .stream_mut(id)
        .expect("stream")
        .release_sent_stream_frame(200);
    assert_eq!(acknowledged(&table, id), Some(0));
    table
        .stream_mut(id)
        .expect("stream")
        .release_sent_stream_frame(0);
    assert_eq!(acknowledged(&table, id), Some(300));
}

#[test]
fn an_unemitted_frame_put_back_is_still_unacknowledged() {
    let (mut table, id) = table_with_records(&[100]);
    let stream = table.stream_mut(id).expect("stream");
    let frame = stream.pop_pending_stream_frame(100).expect("frame");
    stream.requeue_unemitted_stream_frame(frame);
    assert_eq!(acknowledged(&table, id), Some(0));
}

#[test]
fn a_fin_after_acknowledged_data_does_not_hold_the_data_offset() {
    let (mut table, id) = table_with_records(&[100]);
    assert_eq!(emit_all(&mut table, id, 100), [0]);
    let stream = table.stream_mut(id).expect("stream");
    stream.release_sent_stream_frame(0);
    stream.finish_send().expect("fin");
    assert_eq!(acknowledged(&table, id), Some(100));
}

#[test]
fn a_local_reset_reports_no_acknowledged_offset() {
    let (mut table, id) = table_with_records(&[100, 100]);
    assert_eq!(emit_all(&mut table, id, 100), [0, 100]);
    let stream = table.stream_mut(id).expect("stream");
    stream.release_sent_stream_frame(0);
    assert_eq!(acknowledged(&table, id), Some(100));
    table
        .stream_mut(id)
        .expect("stream")
        .reset_send(7, 200)
        .expect("reset");
    assert_eq!(
        acknowledged(&table, id),
        None,
        "abandoned bytes are not acknowledged"
    );
}
