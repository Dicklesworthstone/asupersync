use super::*;
use super::super::ScheduleCaptureRecorder;
use crate::trace::buffer::TraceBufferHandle;
use crate::trace::capture::ScheduleCaptureError;
use crate::trace::replay::{CompactTaskId, ProductionCancellationPhase};
use crate::types::RegionId;

fn capture(cancelled: bool) -> ScheduleCaptureSnapshot {
    let trace = TraceBufferHandle::new(128);
    let recorder = ScheduleCaptureRecorder::new(trace.clone(), 2);
    let task = TaskId::new_for_test(3, 7);
    let caller = TaskId::new_for_test(4, 9);
    let region = RegionId::new_for_test(5, 2);
    trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, caller, region));
    recorder.note_caller_task(caller);
    trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
    recorder.record(Some(0), |seq| TraceEvent::poll(seq, Time::ZERO, task, region));
    let reason = cancelled.then(|| {
        CancelReason::user("archive-private-reason")
            .with_region(region)
            .with_task(task)
            .with_cause(CancelReason::timeout())
    });
    if let Some(reason) = &reason {
        recorder.record(Some(0), |seq| TraceEvent::yield_task(seq, Time::ZERO, task, region));
        let start = trace.begin_cancellation_publication(task);
        let mut request_sequence = None;
        trace.record_event(|seq| {
            request_sequence = Some(seq);
            TraceEvent::cancel_request(seq, Time::ZERO, task, region, reason.clone())
        });
        let budget = Budget {
            deadline: Some(Time::from_nanos(123_456)),
            poll_quota: 7,
            cost_quota: Some(17),
            priority: 211,
        };
        trace.finish_cancellation_publication(start, request_sequence, Some(budget), false);
        recorder.record(Some(1), |seq| TraceEvent::poll(seq, Time::ZERO, task, region));
        recorder.record(Some(1), |seq| TraceEvent::new(
            seq,
            Time::ZERO,
            TraceEventKind::CancelAck,
            TraceData::Cancel { task, region, reason: reason.clone() },
        ));
    }
    trace.record_completion_event_with_cancellation(
        if cancelled { Severity::Cancelled } else { Severity::Ok },
        Some(TerminalCancellationState { requested: cancelled, reason }),
        |seq| TraceEvent::complete(seq, Time::ZERO, task, region),
    );
    recorder.snapshot()
}

fn limits() -> ScheduleCaptureArchiveLimits {
    ScheduleCaptureArchiveLimits::new(64 * 1024, 256, 8192, 4096)
}

fn checksum(bytes: &mut [u8]) {
    let split = bytes.len() - DIGEST_LEN;
    let digest: [u8; DIGEST_LEN] = Sha256::digest(&bytes[..split]).into();
    bytes[split..].copy_from_slice(&digest);
}

fn replace_first_record(bytes: &[u8], replacement: &[u8]) -> Vec<u8> {
    let length = usize::try_from(u64::from_le_bytes(
        bytes[HEADER_LEN..HEADER_LEN + 8].try_into().unwrap(),
    )).unwrap();
    let mut changed = bytes[..HEADER_LEN].to_vec();
    changed.extend_from_slice(&u64::try_from(replacement.len()).unwrap().to_le_bytes());
    changed.extend_from_slice(replacement);
    changed.extend_from_slice(&bytes[HEADER_LEN + 8 + length..]);
    checksum(&mut changed);
    changed
}

#[test]
fn archive_round_trip_preserves_full_checked_cancellation_evidence() {
    let original = capture(true);
    let encoded = original.to_bytes(limits()).unwrap();
    let restored = ScheduleCaptureSnapshot::from_bytes(encoded.as_bytes(), limits()).unwrap();
    assert_eq!(restored.events(), original.events());
    assert_eq!(restored.contexts(), original.contexts());
    assert_eq!(restored.caller_tasks(), original.caller_tasks());
    assert_eq!(restored.terminal_outcomes(), original.terminal_outcomes());
    assert_eq!(restored.total_events(), original.total_events());
    assert_eq!(restored.capacity(), original.capacity());
    assert_eq!(restored.worker_count(), original.worker_count());
    assert_eq!(restored.to_bytes(limits()).unwrap().as_bytes(), encoded.as_bytes());
    let source = original.production_schedule_with_cancellation().unwrap();
    let loaded = restored.production_schedule_with_cancellation().unwrap();
    assert_eq!(loaded.spawn_order(), source.spawn_order());
    assert_eq!(loaded.cancellation_events(), source.cancellation_events());
    assert!(loaded.carries_outcomes());
    assert_eq!(loaded.captured_outcome(CompactTaskId::from(TaskId::new_for_test(3, 7))), Some(Severity::Cancelled));
    let cancellations = loaded.cancellation_events().unwrap();
    assert_eq!(cancellations.len(), 2);
    assert_eq!(cancellations[0].phase(), ProductionCancellationPhase::Request);
    assert_eq!(cancellations[1].phase(), ProductionCancellationPhase::Acknowledgement);
    assert_eq!(cancellations[0].reason().message.as_deref(), Some("archive-private-reason"));
    assert!(cancellations[0].reason().cause.is_some());
    assert_eq!(cancellations[0].cleanup_budget(), Budget {
        deadline: Some(Time::from_nanos(123_456)),
        poll_quota: 7,
        cost_quota: Some(17),
        priority: 211,
    });
    let debug = format!("{encoded:?}");
    assert!(!debug.contains("archive-private-reason"));
    assert!(!debug.contains("123456"));
}

#[test]
fn archive_round_trip_keeps_checked_empty_and_legacy_modes_distinct() {
    let original = capture(false);
    let encoded = original.to_bytes(limits()).unwrap();
    let loaded = ScheduleCaptureSnapshot::from_bytes(encoded.as_bytes(), limits()).unwrap();
    assert!(loaded.production_schedule().unwrap().cancellation_events().is_none());
    assert_eq!(
        loaded.production_schedule_with_cancellation().unwrap().cancellation_events(),
        Some([].as_slice()),
    );
}

#[test]
fn archive_keeps_partial_and_unsupported_evidence_without_upgrading_it() {
    let mut partial = capture(true);
    partial.total_events += 9;
    let archive = partial.to_bytes(limits()).unwrap();
    let restored = ScheduleCaptureSnapshot::from_bytes(archive.as_bytes(), limits()).unwrap();
    assert_eq!(restored.production_schedule().unwrap_err(), ScheduleCaptureError::Truncated { dropped_events: 9 });

    for mutation in 0..4 {
        let mut unsupported = capture(true);
        match mutation {
            0 => unsupported.cancellation_publications.dropped_spans = 1,
            1 => unsupported.cancellation_publications.spans[0].end_sequence = None,
            2 => unsupported.cancellation_publications.spans[0].unsupported_mutation = true,
            _ => unsupported.cancellation_publications.terminals[0].1 = None,
        }
        let original_error = unsupported.production_schedule_with_cancellation().unwrap_err();
        let encoded = unsupported.to_bytes(limits()).unwrap();
        let loaded = ScheduleCaptureSnapshot::from_bytes(encoded.as_bytes(), limits()).unwrap();
        assert_eq!(loaded.production_schedule_with_cancellation().unwrap_err(), original_error);
        assert!(loaded.production_schedule().is_ok());
    }
}

#[test]
fn archive_retains_witnesses_older_than_the_canonical_event_ring() {
    let trace = TraceBufferHandle::new(4);
    let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
    let task = TaskId::new_for_test(1, 8);
    let region = RegionId::new_for_test(2, 9);
    trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
    recorder.record(Some(0), |seq| TraceEvent::poll(seq, Time::ZERO, task, region));
    trace.record_completion_event_with_cancellation(
        Severity::Ok,
        Some(TerminalCancellationState { requested: false, reason: None }),
        |seq| TraceEvent::complete(seq, Time::ZERO, task, region),
    );
    for _ in 0..6 {
        trace.record_event(|seq| TraceEvent::user_trace(seq, Time::ZERO, "later"));
    }
    let original = recorder.snapshot();
    assert!(original.cancellation_publications.terminals[0].0 < original.events()[0].seq);
    let archive = original.to_bytes(limits()).unwrap();
    let restored = ScheduleCaptureSnapshot::from_bytes(archive.as_bytes(), limits()).unwrap();
    assert_eq!(restored.cancellation_publications.terminals.len(), 1);
    assert_eq!(
        restored.cancellation_publications.terminals[0].0,
        original.cancellation_publications.terminals[0].0,
    );
    assert_eq!(restored.production_schedule().unwrap_err(), original.production_schedule().unwrap_err());
}

#[test]
fn archive_rejects_truncation_corruption_unknown_versions_and_trailing_payload() {
    let archive = capture(true).to_bytes(limits()).unwrap();
    let original = archive.as_bytes();
    for length in [0, 8, HEADER_LEN, original.len() - 1] {
        assert!(ScheduleCaptureSnapshot::from_bytes(&original[..length], limits()).is_err());
    }
    let mut corrupt = original.to_vec();
    corrupt[HEADER_LEN + 8] ^= 1;
    assert_eq!(ScheduleCaptureSnapshot::from_bytes(&corrupt, limits()).unwrap_err(), ScheduleCaptureArchiveError::Integrity);
    let mut version = original.to_vec();
    version[8..12].copy_from_slice(&2_u32.to_le_bytes());
    checksum(&mut version);
    assert_eq!(ScheduleCaptureSnapshot::from_bytes(&version, limits()).unwrap_err(), ScheduleCaptureArchiveError::Version(2));
    let mut trailing = original[..original.len() - DIGEST_LEN].to_vec();
    trailing.push(0);
    trailing.extend_from_slice(&[0; DIGEST_LEN]);
    checksum(&mut trailing);
    assert_eq!(ScheduleCaptureSnapshot::from_bytes(&trailing, limits()).unwrap_err(), ScheduleCaptureArchiveError::Invalid("trailing bytes"));
}

#[test]
fn archive_admits_counts_and_record_lengths_before_decoding_allocations() {
    let source = capture(true);
    let archive = source.to_bytes(limits()).unwrap();
    let mut tighter = limits();
    tighter.max_events = source.events().len() - 1;
    assert_eq!(ScheduleCaptureSnapshot::from_bytes(archive.as_bytes(), tighter).unwrap_err(), ScheduleCaptureArchiveError::Limit("events"));
    tighter = limits();
    tighter.max_contexts = 0;
    assert_eq!(ScheduleCaptureSnapshot::from_bytes(archive.as_bytes(), tighter).unwrap_err(), ScheduleCaptureArchiveError::Limit("contexts"));
    tighter = limits();
    tighter.max_caller_tasks = 0;
    assert_eq!(ScheduleCaptureSnapshot::from_bytes(archive.as_bytes(), tighter).unwrap_err(), ScheduleCaptureArchiveError::Limit("caller tasks"));
    tighter = limits();
    tighter.max_cancellation_spans = 0;
    assert_eq!(ScheduleCaptureSnapshot::from_bytes(archive.as_bytes(), tighter).unwrap_err(), ScheduleCaptureArchiveError::Limit("cancellation spans"));
    tighter = limits();
    tighter.max_bytes = archive.as_bytes().len() - 1;
    assert_eq!(ScheduleCaptureSnapshot::from_bytes(archive.as_bytes(), tighter).unwrap_err(), ScheduleCaptureArchiveError::Limit("bytes"));
    tighter = limits();
    tighter.max_reason_bytes = 1;
    assert_eq!(ScheduleCaptureSnapshot::from_bytes(archive.as_bytes(), tighter).unwrap_err(), ScheduleCaptureArchiveError::Limit("reason-bearing record bytes"));
    assert_eq!(source.to_bytes(tighter).unwrap_err(), ScheduleCaptureArchiveError::Limit("reason-bearing record bytes"));

    let mut impossible_count = archive.as_bytes().to_vec();
    impossible_count[44..52].copy_from_slice(&u64::MAX.to_le_bytes());
    checksum(&mut impossible_count);
    assert!(matches!(ScheduleCaptureSnapshot::from_bytes(&impossible_count, limits()), Err(ScheduleCaptureArchiveError::Limit(_))));
    let mut impossible_length = archive.as_bytes().to_vec();
    impossible_length[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    checksum(&mut impossible_length);
    assert!(matches!(ScheduleCaptureSnapshot::from_bytes(&impossible_length, limits()), Err(ScheduleCaptureArchiveError::Limit(_))));

    // All counts are individually admitted, but a tiny payload cannot contain
    // their length prefixes. No record vector should be reserved on this path.
    let mut impossible_payload = archive.as_bytes()[..HEADER_LEN].to_vec();
    for count in 0..6 {
        impossible_payload[44 + count * 8..52 + count * 8].copy_from_slice(&128_u64.to_le_bytes());
    }
    impossible_payload[12..20].copy_from_slice(&128_u64.to_le_bytes());
    impossible_payload.extend_from_slice(&[0; DIGEST_LEN]);
    checksum(&mut impossible_payload);
    assert_eq!(ScheduleCaptureSnapshot::from_bytes(&impossible_payload, limits()).unwrap_err(), ScheduleCaptureArchiveError::Truncated);
}

#[test]
fn archive_refuses_unknown_duplicate_and_noncanonical_record_fields() {
    let archive = capture(false).to_bytes(limits()).unwrap();
    let original = archive.as_bytes();
    let size = usize::try_from(u64::from_le_bytes(original[HEADER_LEN..HEADER_LEN + 8].try_into().unwrap())).unwrap();
    let record = &original[HEADER_LEN + 8..HEADER_LEN + 8 + size];
    for prefix in [br#"{"unknown":1,"#.as_slice(), br#"{"seq":0,"#.as_slice(), b"{ ".as_slice()] {
        let mut replacement = prefix.to_vec();
        replacement.extend_from_slice(&record[1..]);
        let changed = replace_first_record(original, &replacement);
        assert!(matches!(ScheduleCaptureSnapshot::from_bytes(&changed, limits()), Err(ScheduleCaptureArchiveError::Invalid(_))));
    }
}

#[test]
fn archive_refuses_structural_evidence_rewrites_instead_of_normalizing() {
    let mut reversed = capture(true);
    reversed.contexts.reverse();
    assert_eq!(reversed.to_bytes(limits()).unwrap_err(), ScheduleCaptureArchiveError::Invalid("context order"));
    let mut no_event = capture(true);
    no_event.contexts[0].event_sequence = u64::MAX;
    assert!(matches!(no_event.to_bytes(limits()), Err(ScheduleCaptureArchiveError::Invalid(_))));
    let mut bad_worker = capture(true);
    bad_worker.contexts[0].worker_id = Some(bad_worker.worker_count);
    assert_eq!(bad_worker.to_bytes(limits()).unwrap_err(), ScheduleCaptureArchiveError::Invalid("context worker or event category"));

    // A checksum can be recomputed by an attacker, so source structure is
    // checked separately. Rewrite the first Spawn payload to an unrelated type.
    let archive = capture(false).to_bytes(limits()).unwrap();
    let original = archive.as_bytes();
    let size = usize::try_from(u64::from_le_bytes(original[HEADER_LEN..HEADER_LEN + 8].try_into().unwrap())).unwrap();
    let record: TraceEvent = serde_json::from_slice(&original[HEADER_LEN + 8..HEADER_LEN + 8 + size]).unwrap();
    let wrong = TraceEvent { data: TraceData::None, ..record };
    let changed = replace_first_record(original, &serde_json::to_vec(&wrong).unwrap());
    assert_eq!(ScheduleCaptureSnapshot::from_bytes(&changed, limits()).unwrap_err(), ScheduleCaptureArchiveError::Invalid("scheduler event payload"));
}

#[test]
fn archive_preflights_recursive_reasons_before_serializing() {
    let mut deep = capture(false);
    let mut reason = CancelReason::user("deep");
    for _ in 0..MAX_REASON_DEPTH {
        reason = CancelReason::timeout().with_cause(reason);
    }
    deep.cancellation_publications.terminals[0].1 = Some(TerminalCancellationState {
        requested: true,
        reason: Some(reason),
    });
    assert_eq!(deep.to_bytes(limits()).unwrap_err(), ScheduleCaptureArchiveError::Limit("reason depth"));
}

#[test]
fn archive_stream_adapters_round_trip_and_bound_reads_before_eof() {
    let source = capture(true);
    let mut destination = Vec::new();
    source.write_to(&mut destination, limits()).unwrap();
    let mut reader = io::Cursor::new(destination.as_slice());
    let restored = ScheduleCaptureSnapshot::read_from(&mut reader, limits()).unwrap();
    assert_eq!(restored.to_bytes(limits()).unwrap().as_bytes(), destination);

    let mut maximum = limits();
    maximum.max_bytes = destination.len();
    let mut reader = io::Cursor::new(destination.as_slice());
    assert!(ScheduleCaptureSnapshot::read_from(&mut reader, maximum).is_ok());
    destination.push(0);
    let mut reader = io::Cursor::new(destination.as_slice());
    assert_eq!(ScheduleCaptureSnapshot::read_from(&mut reader, maximum).unwrap_err(), ScheduleCaptureArchiveError::Limit("bytes"));
    assert_eq!(reader.position(), u64::try_from(maximum.max_bytes).unwrap() + 1);

    struct Refused;
    impl Read for Refused {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "private-path"))
        }
    }
    let error = ScheduleCaptureSnapshot::read_from(&mut Refused, limits()).unwrap_err();
    assert_eq!(error, ScheduleCaptureArchiveError::Io(io::ErrorKind::PermissionDenied));
    assert!(!format!("{error}").contains("private-path"));
}

#[test]
fn archive_keeps_non_prefix_eviction_after_a_deferred_old_event() {
    let trace = TraceBufferHandle::new(3);
    let recorder = ScheduleCaptureRecorder::new(trace.clone(), 1);
    let task = TaskId::new_for_test(1, 3);
    let region = RegionId::new_for_test(2, 4);
    let delayed_admission = trace.next_seq();
    trace.record_event(|seq| TraceEvent::spawn(seq, Time::ZERO, task, region));
    recorder.record(Some(0), |seq| TraceEvent::poll(seq, Time::ZERO, task, region));
    trace.record_completion_event_with_cancellation(
        Severity::Ok,
        Some(TerminalCancellationState { requested: false, reason: None }),
        |seq| TraceEvent::complete(seq, Time::ZERO, task, region),
    );
    trace.record_event(|seq| TraceEvent::user_trace(seq, Time::ZERO, "after completion"));
    trace.record_event(|seq| TraceEvent::user_trace(seq, Time::ZERO, "after completion again"));
    trace.push_event(TraceEvent::task_admitted(delayed_admission, Time::ZERO, task, region));
    let original = recorder.snapshot();
    let terminal_sequence = original.cancellation_publications.terminals[0].0;
    assert!(terminal_sequence > original.events()[0].seq);
    assert!(!original.events().iter().any(|event| event.seq == terminal_sequence));
    assert_eq!(original.dropped_events(), 3);
    let archive = original.to_bytes(limits()).unwrap();
    let restored = ScheduleCaptureSnapshot::from_bytes(archive.as_bytes(), limits()).unwrap();
    assert_eq!(restored.cancellation_publications.terminals[0].0, terminal_sequence);
    assert_eq!(restored.production_schedule().unwrap_err(), ScheduleCaptureError::Truncated { dropped_events: 3 });

    let mut missing = capture(false);
    missing.cancellation_publications.terminals[0].0 = u64::MAX;
    assert_eq!(missing.to_bytes(limits()).unwrap_err(), ScheduleCaptureArchiveError::Invalid("terminal witness has no completion"));
    let mut wrong = capture(false);
    wrong.cancellation_publications.terminals[0].0 = wrong.events()[0].seq;
    assert_eq!(wrong.to_bytes(limits()).unwrap_err(), ScheduleCaptureArchiveError::Invalid("terminal witness has no completion"));
}

#[test]
fn archive_round_trips_the_maximum_reason_depth_without_truncating() {
    let mut deepest = capture(true);
    let mut reason = CancelReason::user("maximum-depth");
    for _ in 1..MAX_REASON_DEPTH {
        reason = CancelReason::timeout().with_cause(reason);
    }
    for event in &mut deepest.events {
        if let TraceData::Cancel { reason: recorded, .. } = &mut event.data {
            *recorded = reason.clone();
        }
    }
    deepest.cancellation_publications.terminals[0].1 = Some(TerminalCancellationState {
        requested: true,
        reason: Some(reason.clone()),
    });
    let wide = ScheduleCaptureArchiveLimits::new(512 * 1024, 256, 128 * 1024, 128 * 1024);
    let bytes = deepest.to_bytes(wide).unwrap();
    let loaded = ScheduleCaptureSnapshot::from_bytes(bytes.as_bytes(), wide).unwrap();
    let checked = loaded.production_schedule_with_cancellation().unwrap();
    assert_eq!(checked.cancellation_events().unwrap()[0].reason(), &reason);
    assert_eq!(loaded.to_bytes(wide).unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn archive_preserves_vector_clock_storage_and_nested_reason_attribution() {
    use crate::trace::distributed::{LogicalTime, VectorClock};

    let mut source = capture(true);
    let mut clock = VectorClock::new();
    clock.set(&crate::remote::NodeId::new("nonzero-node"), 7);
    let mut clock_json = serde_json::to_value(&clock).unwrap();
    clock_json["entries"].as_object_mut().unwrap()
        .insert("explicit-zero".to_owned(), serde_json::Value::from(0));
    let with_zero: VectorClock = serde_json::from_value(clock_json.clone()).unwrap();
    source.events[0].logical_time = Some(LogicalTime::Vector(with_zero));
    let mut reason = CancelReason::user("nested-private-attribution")
        .with_cause(CancelReason::timeout());
    reason.truncated = true;
    reason.truncated_at_depth = Some(9);
    let last_sequence = source.events.last().unwrap().seq;
    let watched = TaskId::new_for_test(3, 7);
    source.events.push(TraceEvent::new(
        last_sequence + 1,
        Time::from_nanos(41),
        TraceEventKind::DownDelivered,
        TraceData::Down {
            monitor_ref: 99,
            watcher: TaskId::new_for_test(4, 9),
            monitored: watched,
            completion_vt: Time::from_nanos(40),
            reason: crate::monitor::DownReason::Cancelled(reason.clone()),
        },
    ));
    source.total_events += 1;
    let bytes = source.to_bytes(limits()).unwrap();
    let loaded = ScheduleCaptureSnapshot::from_bytes(bytes.as_bytes(), limits()).unwrap();
    let Some(LogicalTime::Vector(clock)) = &loaded.events[0].logical_time else {
        panic!("vector clock retained");
    };
    assert_eq!(serde_json::to_value(clock).unwrap(), clock_json);
    let TraceData::Down { reason: crate::monitor::DownReason::Cancelled(actual), .. } =
        &loaded.events.last().unwrap().data
    else {
        panic!("nested cancellation reason retained");
    };
    assert_eq!(actual, &reason);
    assert_eq!(actual.truncated_at_depth, Some(9));
    assert_eq!(loaded.to_bytes(limits()).unwrap().as_bytes(), bytes.as_bytes());
    assert!(loaded.production_schedule_with_cancellation().is_ok());
}
