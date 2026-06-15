//! QUIC STREAM application-data path: reliable ordered byte transfer
//! (br-asupersync-arq-quic-epic-b0k8qo.1.3, A3).
//!
//! Proves the data-plane acceptance criteria against the production
//! `AtpStream` API (`queue_send` -> `get_send_data` -> `QuicFrame::Stream`
//! payload -> `receive_data` reassembly):
//!
//!   * `quic_stream_multiframe_roundtrip_with_loss_retransmit_and_reorder`:
//!     a multi-frame byte payload is chunked into STREAM frames, delivered
//!     OUT OF ORDER with one frame DROPPED then RETRANSMITTED, and the FIN
//!     frame delivered last — the receiver reassembles the exact original
//!     bytes in order, and `can_receive()` flips to false (FIN => EOF).
//!   * `quic_stream_send_blocked_when_flow_control_starved`: a stream marked
//!     flow-control-blocked yields no send data (the STREAM_DATA_BLOCKED
//!     condition) and resumes once unblocked.
//!
//! Each frame is traced in the ATP_QUIC_TRACE shape (offset/len/fin/
//! retransmit) the bead requires. The AsyncRead+AsyncWrite adapter that lets
//! `FrameTransport<S>` ride on a stream unchanged is the remaining A3 work
//! (tracked on the bead); this slice pins the byte-transfer/reassembly core
//! the adapter sits on top of.

#![cfg(feature = "test-internals")]

use asupersync::bytes::Bytes;
use asupersync::net::atp::streams::{AtpStream, StreamId, StreamPriority};

fn test_cx() -> asupersync::cx::Cx {
    asupersync::cx::Cx::for_testing()
}

/// Chunk size small enough that a 200-byte payload spans many STREAM frames.
const FRAME_PAYLOAD: u64 = 8;
const PAYLOAD_LEN: usize = 200;

/// A3 headline: multi-frame byte payload round-trips one bidi stream with a
/// lost+retransmitted STREAM frame and out-of-order delivery -> bytes intact,
/// ordered, and FIN delivers EOF.
#[test]
fn quic_stream_multiframe_roundtrip_with_loss_retransmit_and_reorder() {
    let cx = test_cx();
    let payload: Vec<u8> = (0..PAYLOAD_LEN as u16).map(|b| b as u8).collect();

    // Send side: buffer the whole payload with FIN, then drain it into the
    // STREAM frames the wire would carry.
    let mut sender = AtpStream::new(StreamId::new(0), true, StreamPriority::Control, true);
    assert!(
        sender
            .queue_send(&cx, Bytes::from(payload.clone()), true)
            .is_ok(),
        "queue_send with FIN must succeed"
    );

    let mut frames: Vec<(u64, Bytes, bool)> = Vec::new();
    while let Some((offset, data, fin)) = sender.get_send_data(FRAME_PAYLOAD) {
        cx.trace(&format!(
            "ATP_QUIC_TRACE stream_frame_sent offset={offset} len={} fin={fin}",
            data.len()
        ));
        frames.push((offset, data, fin));
    }

    assert!(
        frames.len() > 2,
        "payload must span multiple frames: {frames:?}"
    );
    let fin_idx = frames.len() - 1;
    assert!(frames[fin_idx].2, "last emitted frame must carry FIN");
    assert!(
        frames[..fin_idx].iter().all(|(_, _, fin)| !fin),
        "only the final frame carries FIN"
    );
    let drop_idx = 3usize; // a middle data frame we will lose then retransmit

    // Receive side: deliver every non-FIN frame except the dropped one in
    // REVERSE order (out-of-order), accumulating only what reassembly can
    // deliver contiguously.
    let mut receiver = AtpStream::new(StreamId::new(0), true, StreamPriority::Control, false);
    let mut received: Vec<u8> = Vec::new();

    let deliver = |receiver: &mut AtpStream, idx: usize, retransmit: bool, out: &mut Vec<u8>| {
        let (offset, data, fin) = &frames[idx];
        cx.trace(&format!(
            "ATP_QUIC_TRACE stream_frame_recv offset={offset} len={} fin={fin} retransmit={retransmit}",
            data.len()
        ));
        let deliverable = receiver
            .receive_data(&cx, *offset, data.clone(), *fin)
            .unwrap();
        for chunk in deliverable {
            out.extend_from_slice(&chunk);
        }
    };

    for idx in (0..fin_idx).rev() {
        if idx == drop_idx {
            continue; // lost in transit
        }
        deliver(&mut receiver, idx, false, &mut received);
    }

    // Only the contiguous prefix before the gap is deliverable so far.
    assert_eq!(
        received.len(),
        drop_idx * FRAME_PAYLOAD as usize,
        "bytes past the lost frame stay buffered until it is retransmitted"
    );

    // Retransmit the lost frame: the gap fills and the buffered suffix flushes.
    deliver(&mut receiver, drop_idx, true, &mut received);
    // FIN frame arrives last, completing the stream.
    deliver(&mut receiver, fin_idx, false, &mut received);

    assert_eq!(received, payload, "reassembled bytes intact and ordered");
    assert!(
        !receiver.can_receive(),
        "FIN must deliver EOF (receiver no longer accepts data)"
    );
}

/// A3 flow control: a stream that is flow-control blocked produces no send
/// data (STREAM_DATA_BLOCKED), and resumes emitting once the window reopens.
#[test]
fn quic_stream_send_blocked_when_flow_control_starved() {
    let cx = test_cx();
    let mut sender = AtpStream::new(StreamId::new(0), true, StreamPriority::Control, true);
    assert!(
        sender
            .queue_send(&cx, Bytes::from_static(b"control-channel-bytes"), false)
            .is_ok()
    );

    sender.mark_send_blocked();
    cx.trace("ATP_QUIC_TRACE stream_data_blocked reason=flow_control");
    assert!(
        sender.get_send_data(FRAME_PAYLOAD).is_none(),
        "a flow-control-starved stream must not emit STREAM data"
    );

    sender.mark_send_unblocked();
    let resumed = sender.get_send_data(FRAME_PAYLOAD);
    assert!(
        resumed.is_some(),
        "send must resume once the flow-control window reopens"
    );
    let (offset, data, _fin) = resumed.unwrap();
    assert_eq!(offset, 0, "first resumed frame starts at offset 0");
    assert!(!data.is_empty(), "resumed frame carries buffered bytes");
}
