//! Bounded, acknowledged-only QPACK encoding for native HTTP/3 sessions.

use parking_lot::Mutex;

use super::super::h3_native::{
    QpackFieldPlan, qpack_encode_encoder_instruction, qpack_encode_field_section,
    qpack_encode_field_section_with_context,
};
use super::{
    Arc, Bytes, Cx, H3ConnectionState, H3NativeError, H3QpackMode, H3Settings,
    H3UniStreamType, NativeH3SessionError, NativeQuicConnectionError, Poll,
    QpackEncoderInstruction, QpackInstructionStreamState, QuicConnection,
    RequestWriterWake, StreamDirection, StreamId, StreamTableError, TaskContext,
    VecDeque,
};

const MAX_ENCODER_BYTES: usize = 64 * 1024;
const MAX_OUTBOUND_SECTIONS: usize = 4096;

#[derive(Debug)]
struct EncoderState {
    capacity: usize,
    peer_limits: Option<(u64, u64)>,
    qpack: Option<QpackInstructionStreamState>,
    instructions: VecDeque<u8>,
    encoder_stream: Option<StreamId>,
    prefix_queued: bool,
}

/// Shared only with prepared HEADERS, whose drop must release unsent references.
#[derive(Debug, Clone)]
pub(super) struct NativeH3DynamicSend {
    state: Arc<Mutex<EncoderState>>,
    wake: Arc<RequestWriterWake>,
}

/// A prepared section protects entries before the first QUIC byte is accepted.
/// Once exposed, peer decoder feedback owns the references, even after reset.
#[derive(Debug)]
pub(super) struct PreparedQpackSection {
    sender: NativeH3DynamicSend,
    token: Option<u64>,
}

impl PreparedQpackSection {
    pub(super) fn write(
        &mut self,
        cx: &Cx,
        connection: &mut QuicConnection,
        stream_id: StreamId,
        wire: Bytes,
        fin: bool,
    ) -> Result<(), NativeH3SessionError> {
        let Some(token) = self.token else {
            return connection.write_stream(cx, stream_id, wire, fin).map_err(Into::into);
        };
        // Cancellation evidence can call user sinks. Keep that checkpoint
        // outside the shared encoder lock, then use callback-free admission.
        cx.checkpoint().map_err(|_| NativeQuicConnectionError::Cancelled)?;
        let mut state = self.sender.state.lock();
        let qpack = state.qpack.as_mut().expect("prepared section owns encoder state");
        qpack.validate_prepared_outbound_field_section(token)?;
        // No encoder/decoder mutation can intervene between validation and
        // exposure. A failed transport admission leaves the token unexposed.
        connection.write_stream_after_checkpoint(stream_id, wire, fin)?;
        qpack.commit_prepared_outbound_field_section(token)?;
        self.token = None;
        Ok(())
    }
}

impl Drop for PreparedQpackSection {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            if let Some(qpack) = self.sender.state.lock().qpack.as_mut() {
                qpack.discard_prepared_outbound_field_section(token);
            }
        }
    }
}

impl NativeH3DynamicSend {
    #[cfg(test)]
    pub(super) fn prepared_section_count(&self) -> usize {
        self.state.lock().qpack.as_ref()
            .map_or(0, QpackInstructionStreamState::prepared_outbound_section_count)
    }

    #[cfg(test)]
    pub(super) fn outstanding_section_count(&self, stream_id: StreamId) -> usize {
        self.state.lock().qpack.as_ref().map_or(0, |qpack| {
            qpack.decoder_feedback().stream_outstanding_section_count(stream_id.0)
        })
    }

    #[cfg(test)]
    pub(super) fn outstanding_reference_count(&self) -> usize {
        self.state.lock().qpack.as_ref().map_or(0, |qpack| {
            qpack.decoder_feedback().outstanding_reference_count()
        })
    }

    #[cfg(test)]
    pub(super) fn active_table_capacity(&self) -> usize {
        self.state.lock().qpack.as_ref().map_or(0, |qpack| {
            qpack.context().dynamic_table().capacity()
        })
    }

    #[cfg(test)]
    pub(super) fn queued_encoder_bytes(&self) -> usize {
        self.state.lock().instructions.len()
    }

    #[cfg(test)]
    pub(super) fn known_received_count(&self) -> u64 {
        self.state.lock().qpack.as_ref().map_or(0, QpackInstructionStreamState::known_received_count)
    }

    #[cfg(test)]
    pub(super) fn encoder_stream(&self) -> Option<StreamId> {
        self.state.lock().encoder_stream
    }

    pub(super) fn new(capacity: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(EncoderState {
                capacity,
                peer_limits: None,
                qpack: None,
                instructions: VecDeque::new(),
                encoder_stream: None,
                prefix_queued: false,
            })),
            wake: Arc::new(RequestWriterWake::default()),
        }
    }

    pub(super) fn configure_peer(&self, settings: &H3Settings) -> Result<(), H3NativeError> {
        let mut state = self.state.lock();
        let limits = (
            settings.qpack_max_table_capacity.unwrap_or(0),
            settings.qpack_blocked_streams.unwrap_or(0),
        );
        // Session clones can share prepared writers. Never replace their
        // table or invalidate tokens when a clone observes the same SETTINGS.
        if let Some(previous) = state.peer_limits {
            return if previous == limits {
                Ok(())
            } else {
                Err(H3NativeError::QpackPolicy("qpack encoder peer settings already configured"))
            };
        }
        // An unaddressable peer allowance remains permission to use literals.
        // Never truncate it: the exact maximum determines the wire RIC modulus.
        let Ok(peer_capacity) = usize::try_from(settings.qpack_max_table_capacity.unwrap_or(0)) else {
            state.peer_limits = Some(limits);
            return Ok(());
        };
        let mut qpack = QpackInstructionStreamState::from_local_and_peer_settings(
            H3QpackMode::DynamicTableAllowed,
            &H3Settings::default(),
            settings,
        )?.with_outbound_section_limit(MAX_OUTBOUND_SECTIONS)?;
        let active_capacity = state.capacity.min(peer_capacity);
        if active_capacity != 0 {
            qpack.apply_local_encoder_instruction(
                &QpackEncoderInstruction::SetDynamicTableCapacity {
                    capacity: active_capacity as u64,
                },
            )?;
        }
        state.qpack = Some(qpack);
        state.peer_limits = Some(limits);
        Ok(())
    }

    pub(super) fn check_live(&self) -> Result<(), H3NativeError> {
        match self.state.lock().qpack.as_ref().and_then(QpackInstructionStreamState::first_failure) {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    pub(super) fn prepare(
        &self,
        stream_id: StreamId,
        static_plan: Vec<QpackFieldPlan>,
    ) -> Result<(Vec<u8>, Option<PreparedQpackSection>), H3NativeError> {
        let mut state = self.state.lock();
        let Some(qpack) = state.qpack.as_mut() else {
            return Ok((qpack_encode_field_section(&static_plan)?, None));
        };
        if let Some(error) = qpack.first_failure() {
            return Err(error.clone());
        }
        let known = qpack.known_received_count();
        let mut plan = static_plan.clone();
        for field in &mut plan {
            if let QpackFieldPlan::Literal { name, value } = field
                && cacheable_name(name)
                && let Some(entry) = qpack.context().dynamic_table().find_entry(name, value)
                && entry.insertion_id() < known
            {
                *field = QpackFieldPlan::DynamicIndex(entry.insertion_id());
            }
        }
        let mut wire = qpack_encode_field_section_with_context(&plan, Some(qpack.context()))?;
        let token = match qpack.prepare_outbound_field_section(stream_id.0, &wire) {
            Ok(token) => token,
            Err(H3NativeError::QpackPolicy(
                "qpack outbound section limit exceeded" | "qpack pending section limit exceeded",
            )) => {
                wire = qpack_encode_field_section(&static_plan)?;
                None
            }
            Err(error) => return Err(error),
        };
        // Pin the chosen references before optional inserts can evict entries.
        // Warming is opportunistic: table/queue pressure never delays headers.
        let before = state.instructions.len();
        for field in static_plan {
            if let QpackFieldPlan::Literal { name, value } = field
                && cacheable_name(&name)
            {
                if let Err(error) = state.maybe_insert(name, value) {
                    if let Some(token) = token {
                        state.qpack.as_mut().expect("peer settings configured")
                            .discard_prepared_outbound_field_section(token);
                    }
                    return Err(error);
                }
            }
        }
        let queued = state.instructions.len() != before;
        drop(state);
        let prepared = token.map(|token| PreparedQpackSection {
            sender: self.clone(),
            token: Some(token),
        });
        if queued {
            self.wake.wake();
        }
        Ok((wire, prepared))
    }

    /// Returns false until peer SETTINGS create the direction's context.
    pub(super) fn feed_decoder(
        &self,
        connection: &H3ConnectionState,
        stream_id: StreamId,
        bytes: &[u8],
    ) -> Result<bool, H3NativeError> {
        let mut state = self.state.lock();
        let Some(qpack) = state.qpack.as_mut() else {
            return Ok(false);
        };
        connection.feed_qpack_instruction_stream_bytes(qpack, stream_id.0, bytes)?;
        Ok(true)
    }

    /// Each drive queues at most one prefix; only accepted bytes are discarded.
    pub(super) fn drive(
        &self,
        cx: &Cx,
        connection: &mut QuicConnection,
        mut task_cx: Option<&mut TaskContext<'_>>,
    ) -> Result<(), NativeH3SessionError> {
        self.check_live()?;
        if let Some(task_cx) = task_cx.as_deref_mut() {
            self.wake.register(task_cx);
        }
        let (encoder_stream, empty) = {
            let state = self.state.lock();
            (state.encoder_stream, state.instructions.is_empty())
        };
        let stream_id = match encoder_stream {
            Some(stream_id) => stream_id,
            None if empty => return Ok(()),
            None => {
                let stream_id = if let Some(task_cx) = task_cx.as_deref_mut() {
                    match connection.poll_open_uni_stream(cx, task_cx) {
                        Poll::Ready(result) => result?,
                        Poll::Pending => return Ok(()),
                    }
                } else {
                    match connection.open_uni_stream(cx) {
                        Ok(stream_id) => stream_id,
                        Err(NativeQuicConnectionError::StreamTable(
                            StreamTableError::StreamLimitExceeded {
                                direction: StreamDirection::Unidirectional,
                                limit,
                            },
                        )) if limit < (1u64 << 60) => return Ok(()),
                        Err(error) => return Err(error.into()),
                    }
                };
                self.state.lock().encoder_stream = Some(stream_id);
                stream_id
            }
        };
        if connection.inner().streams().stream(stream_id).is_ok_and(|stream| {
            stream.stop_sending_error_code.is_some()
                || stream.send_reset.is_some()
                || stream.send_final_size.is_some()
        }) {
            return Err(NativeH3SessionError::CriticalStreamClosed {
                stream_id,
                stream_type: H3UniStreamType::QpackEncoder,
            });
        }
        if let Some(task_cx) = task_cx.as_deref_mut() {
            match connection.inner_mut().poll_stream_send_closed(cx, stream_id, task_cx) {
                Poll::Ready(Ok(())) => {
                    return Err(NativeH3SessionError::CriticalStreamClosed {
                        stream_id,
                        stream_type: H3UniStreamType::QpackEncoder,
                    });
                }
                Poll::Ready(Err(error)) => return Err(error.into()),
                Poll::Pending => {}
            }
        }
        if self.state.lock().instructions.is_empty() {
            return Ok(());
        }
        let capacity = if let Some(task_cx) = task_cx.as_deref_mut() {
            match connection.poll_stream_write_ready(cx, stream_id, 1, task_cx) {
                Poll::Ready(result) => result?,
                Poll::Pending => return Ok(()),
            }
        } else {
            if connection.has_pending_stream_frames(stream_id) {
                return Ok(());
            }
            connection.inner().stream_send_credit_remaining(stream_id)
                .min(connection.inner().streams().connection_send_remaining())
        };
        let wire: Vec<u8> = self.state.lock().instructions.iter()
            .take(usize::try_from(capacity).unwrap_or(usize::MAX)).copied().collect();
        if wire.is_empty() {
            return Ok(());
        }
        let count = wire.len();
        connection.write_stream(cx, stream_id, Bytes::from(wire), false)?;
        let pending = {
            let mut state = self.state.lock();
            state.instructions.drain(..count);
            !state.instructions.is_empty()
        };
        if pending && let Some(task_cx) = task_cx {
            match connection.poll_stream_write_ready(cx, stream_id, 1, task_cx) {
                Poll::Ready(Err(error)) => return Err(error.into()),
                Poll::Ready(Ok(_)) => task_cx.waker().wake_by_ref(),
                Poll::Pending => {}
            }
        }
        Ok(())
    }
}

impl EncoderState {
    fn maybe_insert(&mut self, name: String, value: String) -> Result<(), H3NativeError> {
        let qpack = self.qpack.as_mut().expect("peer settings configured");
        let table = qpack.context().dynamic_table();
        if table.find_entry(&name, &value).is_some()
            || name.len().saturating_add(value.len()).saturating_add(32) > table.capacity()
        {
            return Ok(());
        }
        let instruction = QpackEncoderInstruction::InsertWithoutNameReference { name, value };
        let mut wire = Vec::new();
        if !self.prefix_queued {
            wire.push(0x02);
            qpack_encode_encoder_instruction(&mut wire, &QpackEncoderInstruction::SetDynamicTableCapacity {
                capacity: table.capacity() as u64,
            })?;
        }
        qpack_encode_encoder_instruction(&mut wire, &instruction)?;
        if wire.len() > MAX_ENCODER_BYTES.saturating_sub(self.instructions.len()) {
            return Ok(());
        }
        // Failed local insertions are transactional table-pressure results;
        // no instruction is emitted and the current section remains valid.
        match qpack.apply_local_encoder_instruction(&instruction) {
            Ok(_) => {}
            Err(H3NativeError::InvalidFrame(
                "qpack dynamic table entry exceeds capacity"
                | "qpack dynamic table insert blocked by referenced entries",
            )) => return Ok(()),
            Err(error) => return Err(error),
        }
        self.instructions.extend(wire);
        self.prefix_queued = true;
        Ok(())
    }
}

fn cacheable_name(name: &str) -> bool {
    matches!(name, "accept" | "accept-encoding" | "content-type" | "content-encoding" | "cache-control" | "vary")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_sink::EvidenceSink;
    use crate::http::h3_native::H3ConnectionConfig;
    use crate::net::atp::protocol::quic_frames::QuicFrame;
    use crate::net::atp::protocol::varint::VarInt;
    use crate::net::quic_native::{NativeQuicConnectionConfig, PacketNumberSpace};
    use crate::types::Budget;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn encoder_fixture(
        cx: &Cx,
        max_local_uni: u64,
        connection_send_limit: u64,
    ) -> (NativeH3DynamicSend, QuicConnection) {
        let mut connection = QuicConnection::client(NativeQuicConnectionConfig {
            max_local_uni,
            connection_send_limit,
            ..NativeQuicConnectionConfig::default()
        });
        connection.begin_handshake(cx).unwrap();
        connection.mark_handshake_keys_available(cx).unwrap();
        connection.mark_app_keys_available(cx).unwrap();
        connection.record_verified_server_identity();
        connection.confirm_handshake(cx).unwrap();
        assert_eq!(connection.open_uni_stream(cx).unwrap(), StreamId(2));
        let sender = NativeH3DynamicSend::new(256);
        sender.configure_peer(&H3Settings {
            qpack_max_table_capacity: Some(4096),
            qpack_blocked_streams: Some(0),
            ..H3Settings::default()
        }).unwrap();
        let (_, section) = sender.prepare(StreamId(0), vec![QpackFieldPlan::Literal {
            name: "accept".to_owned(),
            value: "application/retained-encoder-instructions".to_owned(),
        }]).unwrap();
        assert!(section.is_none());
        assert!(!sender.state.lock().instructions.is_empty());
        (sender, connection)
    }

    fn process_frame(cx: &Cx, connection: &mut QuicConnection, frame: QuicFrame) {
        connection.inner_mut().process_frame(
            cx, &frame, PacketNumberSpace::ApplicationData,
        ).unwrap();
    }

    fn drain_encoder(cx: &Cx, connection: &mut QuicConnection, wire: &mut Vec<u8>) {
        for frame in connection.inner_mut().generate_stream_frames_for(
            cx, PacketNumberSpace::ApplicationData, StreamId(6), 65_536,
        ).unwrap() {
            let QuicFrame::Stream { stream_id, offset, data, fin } = frame else {
                panic!("encoder queue produced a non-STREAM frame");
            };
            assert_eq!(stream_id.value(), 6);
            assert_eq!(offset.map_or(0, VarInt::value), wire.len() as u64);
            assert!(!fin, "QPACK encoder is a critical stream");
            wire.extend_from_slice(&data);
        }
    }

    fn assert_one_peer_insertion(wire: &[u8]) {
        assert_eq!(wire[0], 2);
        let mut peer = QpackInstructionStreamState::from_local_and_peer_settings(
            H3QpackMode::DynamicTableAllowed,
            &H3Settings {
                qpack_max_table_capacity: Some(4096),
                qpack_blocked_streams: Some(0),
                ..H3Settings::default()
            },
            &H3Settings::default(),
        ).unwrap();
        peer.register_stream(6, H3UniStreamType::QpackEncoder).unwrap();
        let mut instructions = 0;
        for byte in &wire[1..] {
            instructions += peer.feed_encoder_stream_bytes(6, &[*byte]).unwrap().instructions_processed();
        }
        assert_eq!(instructions, 2, "one capacity instruction and one insertion");
        let table = peer.received_context().dynamic_table();
        assert_eq!(table.capacity(), 256);
        assert_eq!(table.insertion_counter(), 1);
        let entry = table.get_by_insertion_id(0).unwrap();
        assert_eq!(entry.name(), "accept");
        assert_eq!(entry.value(), "application/retained-encoder-instructions");
    }

    #[test]
    fn encoder_waits_for_stream_count_credit_without_reallocating_or_replaying() {
        let cx = Cx::for_testing();
        let (sender, mut connection) = encoder_fixture(&cx, 1, 65_536);
        let retained = sender.state.lock().instructions.clone();
        let counter = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut task = TaskContext::from_waker(&waker);
        for _ in 0..3 {
            sender.drive(&cx, &mut connection, None).unwrap();
            sender.drive(&cx, &mut connection, Some(&mut task)).unwrap();
            assert_eq!(sender.state.lock().instructions, retained);
            assert!(sender.encoder_stream().is_none());
            assert!(connection.inner().streams().stream(StreamId(6)).is_err());
        }
        assert_eq!(counter.0.load(Ordering::SeqCst), 0, "admission stalls must park");
        for (bidirectional, limit) in [(true, 129), (false, 1)] {
            process_frame(&cx, &mut connection, QuicFrame::MaxStreams {
                bidirectional,
                maximum_streams: VarInt::from_u64_unchecked(limit),
            });
        }
        assert_eq!(counter.0.load(Ordering::SeqCst), 0);
        process_frame(&cx, &mut connection, QuicFrame::MaxStreams {
            bidirectional: false,
            maximum_streams: VarInt::from_u64_unchecked(2),
        });
        assert!(counter.0.swap(0, Ordering::SeqCst) > 0, "MAX_STREAMS must wake the owner");
        sender.drive(&cx, &mut connection, Some(&mut task)).unwrap();
        assert_eq!(sender.encoder_stream(), Some(StreamId(6)));
        assert_eq!(sender.queued_encoder_bytes(), 0);
        let mut wire = Vec::new();
        drain_encoder(&cx, &mut connection, &mut wire);
        assert_eq!(wire, retained.into_iter().collect::<Vec<_>>());
        assert_one_peer_insertion(&wire);
        counter.0.store(0, Ordering::SeqCst);
        for _ in 0..3 {
            sender.drive(&cx, &mut connection, Some(&mut task)).unwrap();
            drain_encoder(&cx, &mut connection, &mut wire);
        }
        assert_eq!(counter.0.load(Ordering::SeqCst), 0);
        assert_eq!(connection.pending_stream_data_bytes(StreamId(6)), 0);
        assert_one_peer_insertion(&wire);
        assert_eq!(connection.open_uni_stream(&cx).unwrap_err(),
            NativeQuicConnectionError::StreamTable(StreamTableError::StreamLimitExceeded {
                direction: StreamDirection::Unidirectional,
                limit: 2,
            }),
        );
    }

    #[test]
    fn encoder_retains_credit_blocked_suffix_and_wakes_on_empty_queue_stop() {
        let cx = Cx::for_testing();
        let (sender, mut connection) = encoder_fixture(&cx, 2, 0);
        let retained: Vec<u8> = sender.state.lock().instructions.iter().copied().collect();
        let counter = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut task = TaskContext::from_waker(&waker);
        sender.drive(&cx, &mut connection, Some(&mut task)).unwrap();
        let encoder = sender.encoder_stream().unwrap();
        assert_eq!(encoder, StreamId(6));
        connection.inner_mut().set_fresh_stream_send_limit(&cx, encoder, 0).unwrap();
        for _ in 0..3 {
            sender.drive(&cx, &mut connection, Some(&mut task)).unwrap();
        }
        assert_eq!(counter.0.load(Ordering::SeqCst), 0);
        process_frame(&cx, &mut connection, QuicFrame::MaxStreamData {
            stream_id: VarInt::from_u64_unchecked(encoder.0),
            maximum_stream_data: VarInt::from_u64_unchecked(1),
        });
        assert!(counter.0.swap(0, Ordering::SeqCst) > 0);
        sender.drive(&cx, &mut connection, Some(&mut task)).unwrap();
        assert_eq!(sender.queued_encoder_bytes(), retained.len());
        assert_eq!(connection.pending_stream_data_bytes(encoder), 0);
        assert_eq!(counter.0.load(Ordering::SeqCst), 0);
        process_frame(&cx, &mut connection, QuicFrame::MaxData {
            maximum_data: VarInt::from_u64_unchecked(1),
        });
        assert!(counter.0.swap(0, Ordering::SeqCst) > 0);
        sender.drive(&cx, &mut connection, Some(&mut task)).unwrap();
        assert_eq!(connection.pending_stream_data_bytes(encoder), 1);
        assert_eq!(sender.state.lock().instructions.iter().copied().collect::<Vec<_>>(), retained[1..]);
        for frame in [
            QuicFrame::MaxData {
                maximum_data: VarInt::from_u64_unchecked(retained.len() as u64),
            },
            QuicFrame::MaxStreamData {
                stream_id: VarInt::from_u64_unchecked(encoder.0),
                maximum_stream_data: VarInt::from_u64_unchecked(retained.len() as u64),
            },
        ] {
            process_frame(&cx, &mut connection, frame);
        }
        counter.0.store(0, Ordering::SeqCst);
        for _ in 0..3 {
            sender.drive(&cx, &mut connection, Some(&mut task)).unwrap();
        }
        assert_eq!(counter.0.load(Ordering::SeqCst), 0, "queued STREAM prefix must park its successor");
        assert_eq!(connection.pending_stream_data_bytes(encoder), 1);
        assert_eq!(sender.queued_encoder_bytes(), retained.len() - 1);
        let mut wire = Vec::new();
        drain_encoder(&cx, &mut connection, &mut wire);
        assert_eq!(wire, [2]);
        assert!(counter.0.swap(0, Ordering::SeqCst) > 0, "packet assembly must wake the queued suffix");
        sender.drive(&cx, &mut connection, Some(&mut task)).unwrap();
        drain_encoder(&cx, &mut connection, &mut wire);
        assert_eq!(wire, retained);
        assert_eq!(sender.queued_encoder_bytes(), 0);
        assert_one_peer_insertion(&wire);
        sender.drive(&cx, &mut connection, Some(&mut task)).unwrap();
        counter.0.store(0, Ordering::SeqCst);
        process_frame(&cx, &mut connection, QuicFrame::StopSending {
            stream_id: VarInt::from_u64_unchecked(encoder.0),
            error_code: VarInt::from_u64_unchecked(0x010c),
        });
        assert!(counter.0.load(Ordering::SeqCst) > 0, "critical STOP must wake even an empty encoder");
        assert_eq!(sender.drive(&cx, &mut connection, Some(&mut task)),
            Err(NativeH3SessionError::CriticalStreamClosed {
                stream_id: encoder,
                stream_type: H3UniStreamType::QpackEncoder,
            }),
        );
        assert_eq!(sender.queued_encoder_bytes(), 0);
    }

    #[test]
    fn encoder_preserves_critical_wake_after_queuing_its_final_instruction() {
        let cx = Cx::for_testing();
        let (sender, mut connection) = encoder_fixture(&cx, 2, 65_536);
        let counter = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut task = TaskContext::from_waker(&waker);
        sender.drive(&cx, &mut connection, Some(&mut task)).unwrap();
        let encoder = sender.encoder_stream().unwrap();
        assert_eq!(sender.queued_encoder_bytes(), 0);
        assert!(connection.pending_stream_data_bytes(encoder) > 0);
        assert_eq!(counter.0.load(Ordering::SeqCst), 0);
        // No second drive or packet-assembly wake can repair a lost watcher.
        process_frame(&cx, &mut connection, QuicFrame::StopSending {
            stream_id: VarInt::from_u64_unchecked(encoder.0),
            error_code: VarInt::from_u64_unchecked(0x010c),
        });
        assert!(counter.0.load(Ordering::SeqCst) > 0);
        assert_eq!(sender.drive(&cx, &mut connection, Some(&mut task)),
            Err(NativeH3SessionError::CriticalStreamClosed {
                stream_id: encoder,
                stream_type: H3UniStreamType::QpackEncoder,
            }),
        );
    }

    #[derive(Debug)]
    struct ReentrantEvidence {
        sender: NativeH3DynamicSend,
        calls: AtomicU64,
        unlocked: AtomicBool,
    }

    impl EvidenceSink for ReentrantEvidence {
        fn emit(&self, _: &franken_evidence::EvidenceLedger) {
            self.calls.fetch_add(1, Ordering::Relaxed);
            // A failed try_lock records the old deadlock without hanging the
            // test. A free lock exercises actual reentry into the send state.
            let unlocked = self.sender.state.try_lock().is_some();
            if !unlocked {
                self.unlocked.store(false, Ordering::Relaxed);
            } else {
                self.sender.check_live().unwrap();
            }
        }

        fn next_evidence_ts(&self) -> u64 {
            self.calls.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn checkpoint_evidence_can_reenter_encoder_before_transport_admission() {
        for cancelled in [false, true] {
            let sender = NativeH3DynamicSend::new(256);
            sender.configure_peer(&H3Settings {
                qpack_max_table_capacity: Some(256),
                qpack_blocked_streams: Some(0),
                ..H3Settings::default()
            }).unwrap();
            let plan = vec![QpackFieldPlan::Literal {
                name: "accept".to_owned(),
                value: "application/reentrant-checkpoint".to_owned(),
            }];
            assert!(sender.prepare(StreamId(0), plan.clone()).unwrap().1.is_none());
            let mut mapping = H3ConnectionState::with_config(H3ConnectionConfig::default());
            mapping.on_remote_uni_stream_type(3, 3).unwrap();
            assert!(sender.feed_decoder(&mapping, StreamId(3), &[1]).unwrap());
            let (wire, mut section) = sender.prepare(StreamId(0), plan).unwrap();
            assert_eq!(sender.prepared_section_count(), 1);
            let healthy = Cx::for_testing();
            let mut connection = QuicConnection::client(NativeQuicConnectionConfig::default());
            connection.begin_handshake(&healthy).unwrap();
            connection.mark_handshake_keys_available(&healthy).unwrap();
            connection.mark_app_keys_available(&healthy).unwrap();
            connection.record_verified_server_identity();
            connection.confirm_handshake(&healthy).unwrap();
            let stream = connection.open_bidi_stream(&healthy).unwrap();
            assert_eq!(stream, StreamId(0));
            let evidence = Arc::new(ReentrantEvidence {
                sender: sender.clone(),
                calls: AtomicU64::new(0),
                unlocked: AtomicBool::new(true),
            });
            let cx = if cancelled {
                Cx::for_testing()
            } else {
                Cx::for_testing_with_budget(Budget::new().with_poll_quota(0))
            }.with_evidence_sink(Some(evidence.clone()));
            if cancelled {
                cx.set_cancel_requested(true);
            }
            assert_eq!(
                section.as_mut().unwrap().write(
                    &cx, &mut connection, stream, Bytes::from(wire), false,
                ),
                Err(NativeH3SessionError::Transport(NativeQuicConnectionError::Cancelled)),
            );
            assert!(evidence.calls.load(Ordering::Relaxed) > 0);
            assert!(evidence.unlocked.load(Ordering::Relaxed));
            assert_eq!(connection.pending_stream_data_bytes(stream), 0);
            assert_eq!(sender.prepared_section_count(), 1);
            assert_eq!(sender.outstanding_reference_count(), 0);
            drop(section);
            assert_eq!(sender.prepared_section_count(), 0);
        }
    }
}
