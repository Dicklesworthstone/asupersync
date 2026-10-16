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
        // A pushed response (a server-initiated, even stream) has no request
        // guard, but its DATA waits on the same peer credit; untracked, a push
        // that never got credit kept the connection from idling or closing.
        let tracked = |stream_id: u32| {
            response_guards.contains_key(&stream_id)
                || produced_bodies.contains_key(&stream_id)
                || stream_id.is_multiple_of(2)
        };
        // A successful transport pump leaves only flow-control-blocked DATA
        // (and headers ordered behind it) in a buffered response's queue.
        // Produced responses can instead be parked before polling their body,
        // with no DATA yet in the connection queue. Cover that gate as well.
        let blocked: HashSet<u32> = conn
            .flow_control_blocked_data_streams()
            .filter(|&stream_id| tracked(stream_id))
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

        self.deadlines.retain(|&stream_id, _| {
            tracked(stream_id) && (!stream_id.is_multiple_of(2) || conn.stream(stream_id).is_some())
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
#[path = "flow_control_inline_tests.rs"]
mod tests;
