//! Per-response deadlines for DATA held by the peer's HTTP/2 flow control.

use super::*;

pub(super) struct H2FlowControlProgress {
    deadlines: BTreeMap<u32, Time>,
    armed: HashSet<u32>,
    pending_flush: HashSet<u32>,
    timeout: Duration,
}

impl H2FlowControlProgress {
    pub(super) fn new(timeout: Duration) -> Self {
        Self {
            deadlines: BTreeMap::new(),
            armed: HashSet::new(),
            pending_flush: HashSet::new(),
            timeout,
        }
    }

    pub(super) fn retain_live(&mut self, conn: &Connection) {
        self.deadlines.retain(|stream_id, _| {
            conn.stream(*stream_id)
                .is_some_and(|stream| stream.error_code().is_none())
        });
        self.armed
            .retain(|stream_id| self.deadlines.contains_key(stream_id));
    }

    pub(super) fn tracks(&self, stream_id: u32) -> bool {
        self.deadlines.contains_key(&stream_id)
    }

    pub(super) fn queued_data(&mut self, stream_id: u32) {
        self.pending_flush.insert(stream_id);
    }

    pub(super) fn flushed(&mut self, now: Time) {
        for stream_id in self.pending_flush.drain() {
            if let Some(deadline) = self.deadlines.get_mut(&stream_id) {
                *deadline = now + self.timeout;
            }
        }
    }

    pub(super) fn armed_deadline(&self) -> Option<(u32, Time)> {
        self.deadlines
            .iter()
            .filter(|(stream_id, _)| self.armed.contains(*stream_id))
            .min_by_key(|(stream_id, deadline)| (**deadline, **stream_id))
            .map(|(&stream_id, &deadline)| (stream_id, deadline))
    }

    pub(super) fn next_deadline(
        &mut self,
        conn: &Connection,
        response_guards: &HashMap<u32, Arc<InFlightRequestGuard>>,
        produced_bodies: &BTreeMap<u32, ActiveProducedBody>,
        now: Time,
    ) -> Option<(u32, Time)> {
        // A successful transport pump leaves only flow-control-blocked DATA
        // (and headers ordered behind it) in a buffered response's queue.
        // Produced responses can instead be parked before polling their body,
        // with no DATA yet in the connection queue. Cover that gate as well.
        let blocked: HashSet<u32> = conn
            .flow_control_blocked_data_streams()
            .filter(|stream_id| {
                response_guards.contains_key(stream_id) || produced_bodies.contains_key(stream_id)
            })
            .chain(produced_bodies.iter().filter_map(|(&stream_id, state)| {
                let terminal_only = matches!(
                    state.producer_outcome,
                    Some(Http2ProducerOutcome::Finished { total_bytes, .. })
                        if total_bytes == state.emitted_bytes
                );
                (!state.body_eof
                    && state.pending_trailers.is_none()
                    && !terminal_only
                    && conn.available_send_capacity(stream_id) == 0)
                    .then_some(stream_id)
            }))
            .collect();

        self.deadlines.retain(|stream_id, _| {
            response_guards.contains_key(stream_id) || produced_bodies.contains_key(stream_id)
        });
        for stream_id in &blocked {
            self.deadlines
                .entry(*stream_id)
                .or_insert(now + self.timeout);
        }
        // Keep an old deadline while credit is temporarily available, but do
        // not arm its timer then: an idle producer is not a peer credit stall.
        // If sibling DATA spends that credit without this response progressing,
        // the previous deadline still applies when the response blocks again.
        self.armed = blocked;
        self.armed_deadline()
    }
}

pub(super) async fn write_with_deadline(
    framed: &mut Framed<H2Transport, ListenerFrameCodec>,
    signal: &ShutdownSignal,
    write_timeout: Duration,
    operation: H2WriteOperation,
    flow_deadline: Option<(u32, Time)>,
) -> Result<(), H2PumpWriteError> {
    let write = bounded_h2_write(framed, signal, write_timeout, operation);
    match flow_deadline {
        Some((stream_id, deadline)) => match crate::time::timeout_at(deadline, write).await {
            Ok(result) => result.map_err(H2PumpWriteError::Transport),
            Err(_) => Err(H2PumpWriteError::FlowControl(stream_id)),
        },
        None => write.await.map_err(H2PumpWriteError::Transport),
    }
}

pub(super) fn reset_flow_control_stream(
    stream_id: u32,
    conn: &mut Connection,
    cx: &Cx,
    owners: &H2RequestOwners,
    produced: &mut BTreeMap<u32, ActiveProducedBody>,
    pushes: &mut HashMap<u32, Vec<u32>>,
    #[cfg(feature = "http2-streaming")] incoming: &mut Option<StreamingRequests>,
) {
    record_h2_body_diagnostic_code(
        stream_id,
        WebBodyDiagnostic::Timeout.code(),
        "response DATA exceeded its peer flow-control progress timeout",
    );
    owners.cancel(stream_id, h2_request_cancel_reason(cx, CancelKind::Timeout));
    #[cfg(feature = "http2-streaming")]
    if let Some(incoming) = incoming {
        incoming.fail(
            stream_id,
            crate::http::h1::stream::IncomingBodyError::Cancelled {
                kind: CancelKind::Timeout,
            },
        );
    }
    conn.reset_stream(stream_id, ErrorCode::Cancel);
    cancel_produced_body(
        produced,
        stream_id,
        "HTTP/2 response exhausted its peer flow-control progress timeout",
    );
    reset_associated_pushes(conn, pushes, stream_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::{Bytes, BytesMut};
    use crate::http::h2::frame::{
        HeadersFrame, PingFrame, Setting, SettingsFrame, WindowUpdateFrame,
    };
    use crate::http::h2::hpack::Encoder as HpackEncoder;

    #[test]
    fn only_affected_stream_data_renews_its_credit_deadline() {
        let mut conn = Connection::server(Settings::server());
        conn.process_frame(Frame::Settings(SettingsFrame::new(vec![
            Setting::InitialWindowSize(0),
        ])))
        .unwrap();
        let mut encoder = HpackEncoder::new();
        let mut guards = HashMap::new();
        for stream_id in [1, 3] {
            let mut headers = BytesMut::new();
            encoder.encode(
                &[
                    Header::new(":method", "GET"),
                    Header::new(":scheme", "http"),
                    Header::new(":path", "/"),
                    Header::new(":authority", "localhost"),
                ],
                &mut headers,
            );
            conn.process_frame(Frame::Headers(HeadersFrame::new(
                stream_id,
                headers.freeze(),
                true,
                true,
            )))
            .unwrap();
            conn.send_headers(stream_id, vec![Header::new(":status", "200")], false)
                .unwrap();
            conn.send_data(stream_id, Bytes::from_static(b"blocked"), true)
                .unwrap();
            guards.insert(stream_id, Arc::new(InFlightRequestGuard::acquire(None)));
        }
        while let Some(frame) = conn.next_frame() {
            assert!(
                !matches!(frame, Frame::Data(_)),
                "zero peer credit holds all response DATA"
            );
        }
        let timeout = Duration::from_nanos(10);
        let mut progress = H2FlowControlProgress::new(timeout);
        let bodies = BTreeMap::new();
        assert_eq!(
            progress.next_deadline(&conn, &guards, &bodies, Time::from_nanos(10),),
            Some((1, Time::from_nanos(20)))
        );
        conn.process_frame(Frame::Ping(PingFrame::new([0; 8])))
            .unwrap();
        assert!(matches!(conn.next_frame(), Some(Frame::Ping(_))));
        assert!(conn.next_frame().is_none());
        assert_eq!(
            progress.next_deadline(&conn, &guards, &bodies, Time::from_nanos(15),),
            Some((1, Time::from_nanos(20)))
        );

        for (stream_id, now) in [(3, 15), (1, 19)] {
            conn.process_frame(Frame::WindowUpdate(WindowUpdateFrame::new(stream_id, 1)))
                .unwrap();
            let Some(Frame::Data(data)) = conn.next_frame() else {
                panic!("one byte of credit emits DATA");
            };
            assert_eq!(data.stream_id, stream_id);
            assert_eq!(data.data.len(), 1);
            assert!(conn.next_frame().is_none());
            progress.queued_data(data.stream_id);
            progress.flushed(Time::from_nanos(now));
            let _ = progress.next_deadline(&conn, &guards, &bodies, Time::from_nanos(now));
        }
        assert_eq!(progress.deadlines.get(&1), Some(&Time::from_nanos(29)));
        assert_eq!(progress.deadlines.get(&3), Some(&Time::from_nanos(25)));
        assert_eq!(
            progress.next_deadline(&conn, &guards, &bodies, Time::from_nanos(25),),
            Some((3, Time::from_nanos(25))),
            "expiry remains absolute at exact equality"
        );
        for stream_id in [1, 3] {
            conn.reset_stream(stream_id, ErrorCode::Cancel);
        }
        while conn.next_frame().is_some() {}
        release_flushed_response_guards(&conn, &mut guards);
        assert!(
            progress
                .next_deadline(&conn, &guards, &bodies, Time::from_nanos(26),)
                .is_none()
        );
        assert!(
            progress.deadlines.is_empty(),
            "retired responses retain no deadline state"
        );
    }
}
