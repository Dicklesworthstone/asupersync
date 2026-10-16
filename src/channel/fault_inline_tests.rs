    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::channel::mpsc;
    use crate::evidence_sink::CollectorSink;
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    fn test_cx() -> Cx<crate::cx::cap::All> {
        Cx::for_testing()
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        let waker = std::task::Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        let mut pinned = Box::pin(f);
        loop {
            match pinned.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn test_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[test]
    fn config_defaults_disabled() {
        let config = FaultChannelConfig::new(42);
        assert!(!config.is_enabled());
    }

    #[test]
    fn config_builder() {
        let config = FaultChannelConfig::new(42)
            .with_reorder(0.3, 4)
            .with_duplication(0.1);
        assert!(config.is_enabled());
        assert!((config.reorder_probability - 0.3).abs() < f64::EPSILON);
        assert_eq!(config.reorder_buffer_size, 4);
        assert!((config.duplication_probability - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    #[should_panic(expected = "reorder probability must be in [0.0, 1.0]")]
    fn config_rejects_invalid_reorder_probability() {
        let _ = FaultChannelConfig::new(42).with_reorder(1.5, 4);
    }

    #[test]
    #[should_panic(expected = "reorder buffer size must be > 0")]
    fn config_rejects_zero_buffer_size() {
        let _ = FaultChannelConfig::new(42).with_reorder(0.5, 0);
    }

    #[test]
    #[should_panic(expected = "duplication probability must be in [0.0, 1.0]")]
    fn config_rejects_invalid_duplication_probability() {
        let _ = FaultChannelConfig::new(42).with_duplication(-0.1);
    }

    #[test]
    fn passthrough_when_disabled() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42);
        let (fault_tx, mut rx) = fault_channel::<u32>(16, config, sink);
        let cx = test_cx();

        for i in 0..10 {
            block_on(fault_tx.send(&cx, i)).expect("send failed");
        }

        // All messages should arrive in order.
        for i in 0..10 {
            let val = rx.try_recv().expect("recv failed");
            assert_eq!(val, i);
        }

        let stats = fault_tx.stats();
        assert_eq!(stats.messages_sent, 10);
        assert_eq!(stats.messages_reordered, 0);
        assert_eq!(stats.messages_duplicated, 0);
    }

    #[test]
    fn duplication_sends_twice() {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        // 100% duplication probability.
        let config = FaultChannelConfig::new(42).with_duplication(1.0);
        let (fault_tx, mut rx) = fault_channel::<u32>(32, config, sink);
        let cx = test_cx();

        block_on(fault_tx.send(&cx, 42)).expect("send failed");

        // Should receive the original + duplicate.
        let v1 = rx.try_recv().expect("recv original");
        let v2 = rx.try_recv().expect("recv duplicate");
        assert_eq!(v1, 42);
        assert_eq!(v2, 42);

        let stats = fault_tx.stats();
        assert_eq!(stats.messages_duplicated, 1);

        // Evidence should be logged.
        assert!(!collector.is_empty());
        let entries = collector.entries();
        assert!(entries.iter().any(|e| e.action.contains("duplication")));
    }

    #[test]
    fn reorder_buffers_and_flushes() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        // 100% reorder probability, buffer size 3.
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 3);
        let (fault_tx, mut rx) = fault_channel::<u32>(32, config, sink);
        let cx = test_cx();

        // Send 3 messages — should fill buffer and auto-flush.
        for i in 0..3 {
            block_on(fault_tx.send(&cx, i)).expect("send failed");
        }

        // All 3 should be delivered (but possibly reordered).
        let mut received = Vec::new();
        while let Ok(val) = rx.try_recv() {
            received.push(val);
        }
        assert_eq!(received.len(), 3);
        // All values present (eventual delivery).
        received.sort_unstable();
        assert_eq!(received, vec![0, 1, 2]);

        let stats = fault_tx.stats();
        assert_eq!(stats.messages_reordered, 3);
        assert_eq!(stats.reorder_flushes, 1);
    }

    #[test]
    fn manual_flush_delivers_buffered() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        // 100% reorder, large buffer so auto-flush doesn't trigger.
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 100);
        let (fault_tx, mut rx) = fault_channel::<u32>(32, config, sink);
        let cx = test_cx();

        for i in 0..5 {
            block_on(fault_tx.send(&cx, i)).expect("send failed");
        }
        assert_eq!(fault_tx.buffered_count(), 5);

        // Nothing received yet.
        assert!(rx.try_recv().is_err());

        // Flush should deliver all.
        block_on(fault_tx.flush(&cx)).expect("flush failed");
        assert_eq!(fault_tx.buffered_count(), 0);

        let mut received = Vec::new();
        while let Ok(val) = rx.try_recv() {
            received.push(val);
        }
        assert_eq!(received.len(), 5);
        received.sort_unstable();
        assert_eq!(received, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn flush_reestablishes_reorder_buffer_preallocation() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let buffer_size = 8;
        let config = FaultChannelConfig::new(42).with_reorder(1.0, buffer_size);
        let (fault_tx, _rx) = fault_channel::<u32>(32, config, sink);
        let cx = test_cx();

        for i in 0..3 {
            block_on(fault_tx.send(&cx, i)).expect("send failed");
        }
        block_on(fault_tx.flush(&cx)).expect("flush failed");

        let cap = fault_tx.reorder_buffer.lock().capacity();
        assert!(
            cap >= buffer_size,
            "expected reorder buffer capacity >= {buffer_size}, got {cap}"
        );
    }

    #[test]
    fn deterministic_fault_sequence() {
        // Two senders with the same seed should make identical decisions.
        let sink1: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let sink2: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());

        let config = FaultChannelConfig::new(99)
            .with_reorder(0.5, 4)
            .with_duplication(0.3);

        let (fault_tx1, mut rx1) = fault_channel::<u32>(64, config.clone(), sink1);
        let (fault_tx2, mut rx2) = fault_channel::<u32>(64, config, sink2);
        let cx = test_cx();

        for i in 0..20 {
            block_on(fault_tx1.send(&cx, i)).expect("send1");
            block_on(fault_tx2.send(&cx, i)).expect("send2");
        }
        block_on(fault_tx1.flush(&cx)).expect("flush1");
        block_on(fault_tx2.flush(&cx)).expect("flush2");

        // Collect all received values.
        let mut recv1 = Vec::new();
        let mut recv2 = Vec::new();
        while let Ok(v) = rx1.try_recv() {
            recv1.push(v);
        }
        while let Ok(v) = rx2.try_recv() {
            recv2.push(v);
        }

        // Same seed should produce identical receive sequences.
        assert_eq!(recv1, recv2);
        assert_eq!(
            fault_tx1.stats().messages_reordered,
            fault_tx2.stats().messages_reordered
        );
        assert_eq!(
            fault_tx1.stats().messages_duplicated,
            fault_tx2.stats().messages_duplicated
        );
    }

    #[test]
    fn eventual_delivery_all_messages_arrive() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(77)
            .with_reorder(0.5, 5)
            .with_duplication(0.0);
        let (fault_tx, mut rx) = fault_channel::<u32>(128, config, sink);
        let cx = test_cx();

        let count = 50;
        for i in 0..count {
            block_on(fault_tx.send(&cx, i)).expect("send");
        }
        block_on(fault_tx.flush(&cx)).expect("flush");

        let mut received = Vec::new();
        while let Ok(v) = rx.try_recv() {
            received.push(v);
        }
        // Every message must arrive exactly once.
        received.sort_unstable();
        let expected: Vec<u32> = (0..count).collect();
        assert_eq!(received, expected);
    }

    #[test]
    fn mixed_reorder_and_duplication() {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        let config = FaultChannelConfig::new(42)
            .with_reorder(0.3, 4)
            .with_duplication(0.2);
        let (fault_tx, mut rx) = fault_channel::<u32>(256, config, sink);
        let cx = test_cx();

        let count = 30;
        for i in 0..count {
            block_on(fault_tx.send(&cx, i)).expect("send");
        }
        block_on(fault_tx.flush(&cx)).expect("flush");

        let mut received = Vec::new();
        while let Ok(v) = rx.try_recv() {
            received.push(v);
        }

        // With duplication, we may have more messages than sent.
        // With reorder, order may differ. But all originals must be present.
        let stats = fault_tx.stats();
        assert!(received.len() as u64 >= stats.messages_sent);

        // All original values should appear at least once.
        for i in 0..count {
            assert!(
                received.contains(&i),
                "missing message {i}, received: {received:?}, stats: {stats}"
            );
        }

        // Evidence should be logged for faults.
        let entries = collector.entries();
        assert!(
            !entries.is_empty(),
            "expected evidence entries for injected faults"
        );
    }

    #[test]
    fn reorder_buffering_suppresses_eager_duplication_until_flush() {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        let config = FaultChannelConfig::new(42)
            .with_reorder(1.0, 4)
            .with_duplication(1.0);
        let (fault_tx, mut rx) = fault_channel::<u32>(16, config, sink);
        let cx = test_cx();

        block_on(fault_tx.send(&cx, 7)).expect("send");

        assert_eq!(fault_tx.buffered_count(), 1);
        assert!(
            rx.try_recv().is_err(),
            "buffered reorder send leaked early delivery"
        );
        assert_eq!(
            fault_tx.stats().messages_duplicated,
            0,
            "duplication must not fire when reorder buffered the message"
        );

        let entries = collector.entries();
        assert!(
            entries
                .iter()
                .any(|entry| entry.action == "inject_reorder_buffer")
        );
        assert!(
            entries
                .iter()
                .all(|entry| entry.action != "inject_duplication"),
            "duplication evidence must not appear before flush: {entries:?}"
        );

        block_on(fault_tx.flush(&cx)).expect("flush");
        assert_eq!(rx.try_recv().expect("recv buffered message"), 7);
        assert!(
            rx.try_recv().is_err(),
            "reorder+duplication path delivered extra copy"
        );
    }

    #[test]
    fn empty_flush_is_noop() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 4);
        let (fault_tx, _rx) = fault_channel::<u32>(16, config, sink);
        let cx = test_cx();

        // Flush with nothing buffered should succeed.
        block_on(fault_tx.flush(&cx)).expect("empty flush");
        assert_eq!(fault_tx.stats().reorder_flushes, 0);
    }

    #[test]
    fn send_after_receiver_drop_returns_error() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42);
        let (tx, rx) = mpsc::channel::<u32>(1);
        let fault_tx = FaultSender::new(tx, config, sink);
        let cx = test_cx();

        drop(rx);
        let result = block_on(fault_tx.send(&cx, 1));
        assert!(matches!(result, Err(SendError::Disconnected(_))));
    }

    #[test]
    fn cancelled_send_precedence_matches_mpsc_when_receiver_dropped() {
        let base_cx = test_cx();
        base_cx.set_cancel_requested(true);
        let (base_tx, base_rx) = mpsc::channel::<u32>(1);
        drop(base_rx);

        let base_result = block_on(base_tx.send(&base_cx, 7));
        assert!(
            matches!(base_result, Err(SendError::Cancelled(7))),
            "base mpsc sender should report cancellation before receiver drop"
        );

        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 4);
        let (fault_tx, fault_rx) = fault_channel::<u32>(1, config, sink);
        let fault_cx = test_cx();
        fault_cx.set_cancel_requested(true);
        drop(fault_rx);

        let fault_result = block_on(fault_tx.send(&fault_cx, 7));
        assert!(
            matches!(fault_result, Err(SendError::Cancelled(7))),
            "fault sender should preserve base mpsc cancellation precedence"
        );
        assert_eq!(fault_tx.buffered_count(), 0);
    }

    #[test]
    fn send_after_receiver_drop_with_reorder_returns_error() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 4);
        let (tx, rx) = mpsc::channel::<u32>(1);
        let fault_tx = FaultSender::new(tx, config, sink);
        let cx = test_cx();

        drop(rx);
        let result = block_on(fault_tx.send(&cx, 1));
        assert!(matches!(result, Err(SendError::Disconnected(1))));
        assert_eq!(fault_tx.buffered_count(), 0);
    }

    #[test]
    fn flush_requeues_messages_when_receiver_disconnects() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 10);
        let (fault_tx, rx) = fault_channel::<u32>(4, config, sink);
        let cx = test_cx();

        block_on(fault_tx.send(&cx, 10)).expect("buffer send");
        block_on(fault_tx.send(&cx, 11)).expect("buffer send");
        assert_eq!(fault_tx.buffered_count(), 2);

        drop(rx);
        let flush_result = block_on(fault_tx.flush(&cx));
        assert!(matches!(flush_result, Err(SendError::Disconnected(()))));
        assert_eq!(fault_tx.buffered_count(), 2);
    }

    #[test]
    fn auto_flush_returns_disconnected_for_triggering_message() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 1);
        let (fault_tx, rx) = fault_channel::<u32>(1, config, sink);
        let cx = test_cx();

        block_on(fault_tx.inner().send(&cx, 99)).expect("fill underlying channel");

        let waker = test_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut send_fut = Box::pin(fault_tx.send(&cx, 123));
        assert!(matches!(
            send_fut.as_mut().poll(&mut task_cx),
            Poll::Pending
        ));

        drop(rx);

        assert!(matches!(
            send_fut.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(SendError::Disconnected(123)))
        ));
        assert_eq!(fault_tx.buffered_count(), 0);
    }

    #[test]
    fn auto_flush_returns_cancelled_for_triggering_message() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 1);
        let (fault_tx, _rx) = fault_channel::<u32>(1, config, sink);
        let cx = test_cx();

        block_on(fault_tx.inner().send(&cx, 99)).expect("fill underlying channel");

        let send_cx = test_cx();
        let waker = test_waker();
        let mut task_cx = Context::from_waker(&waker);
        let mut send_fut = Box::pin(fault_tx.send(&send_cx, 123));
        assert!(matches!(
            send_fut.as_mut().poll(&mut task_cx),
            Poll::Pending
        ));

        send_cx.set_cancel_requested(true);

        assert!(matches!(
            send_fut.as_mut().poll(&mut task_cx),
            Poll::Ready(Err(SendError::Cancelled(123)))
        ));
        assert_eq!(fault_tx.buffered_count(), 0);
    }

    #[test]
    fn cancelled_send_returns_error_without_buffering() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 1);
        let (fault_tx, mut rx) = fault_channel::<u32>(8, config, sink);
        let cancelled_cx = test_cx();
        cancelled_cx.set_cancel_requested(true);

        // Cancelled Cx fails fast — message is not buffered.
        let send_result = block_on(fault_tx.send(&cancelled_cx, 2));
        assert!(matches!(send_result, Err(SendError::Cancelled(2))));
        assert_eq!(fault_tx.buffered_count(), 0);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn evidence_entries_are_valid() {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        let config = FaultChannelConfig::new(42)
            .with_reorder(1.0, 2)
            .with_duplication(1.0);
        let (fault_tx, _rx) = fault_channel::<u32>(64, config, sink);
        let cx = test_cx();

        // Send enough to trigger both reorder flush and duplication.
        // With reorder=1.0 everything goes to buffer, so duplication
        // won't trigger (reorder takes precedence). Send with reorder
        // first, then reconfigure. For simplicity, test reorder evidence.
        for i in 0..4 {
            block_on(fault_tx.send(&cx, i)).expect("send");
        }

        let entries = collector.entries();
        for entry in &entries {
            assert_eq!(entry.component, "channel_fault");
            assert!(entry.action.starts_with("inject_"));
            assert!(entry.is_valid(), "invalid evidence: {entry:?}");
        }
    }

    #[test]
    fn evidence_timestamps_follow_deterministic_event_sequence() {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 2);
        let (fault_tx, _rx) = fault_channel::<u32>(16, config, sink);
        let cx = test_cx();

        block_on(fault_tx.send(&cx, 1)).expect("send");
        block_on(fault_tx.send(&cx, 2)).expect("send");

        let entries = collector.entries();
        let timestamps: Vec<u64> = entries.iter().map(|entry| entry.ts_unix_ms).collect();
        assert_eq!(timestamps, vec![1, 2, 3]);
    }

    #[test]
    fn duplication_evidence_only_recorded_after_successful_delivery() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        // Duplication enabled, reorder disabled so duplication path is taken.
        let config = FaultChannelConfig::new(42).with_duplication(1.0);
        let (fault_tx, rx) = fault_channel::<u32>(8, config, sink);
        let cx = test_cx();

        // Send one message (original + dup both succeed).
        block_on(fault_tx.send(&cx, 1)).expect("send");
        let stats = fault_tx.stats();
        assert_eq!(stats.messages_duplicated, 1);

        // Drop receiver, then send again. Original succeeds but dup fails.
        drop(rx);
        // Original send also fails now since receiver is dropped.
        let _ = block_on(fault_tx.send(&cx, 2));

        let stats = fault_tx.stats();
        // Duplication count should not increment when the dup delivery fails.
        assert_eq!(
            stats.messages_duplicated, 1,
            "duplication evidence must not be recorded when delivery fails"
        );
    }

    #[test]
    fn flush_evidence_only_recorded_after_first_delivery() {
        let collector = Arc::new(CollectorSink::new());
        let sink: Arc<dyn EvidenceSink> = collector.clone();
        let config = FaultChannelConfig::new(42).with_reorder(1.0, 8);
        let (fault_tx, rx) = fault_channel::<u32>(8, config, sink);
        let cx = test_cx();

        block_on(fault_tx.send(&cx, 1)).expect("buffer send");
        block_on(fault_tx.send(&cx, 2)).expect("buffer send");
        assert_eq!(fault_tx.buffered_count(), 2);

        drop(rx);
        let flush_result = block_on(fault_tx.flush(&cx));
        assert!(matches!(flush_result, Err(SendError::Disconnected(()))));

        let stats = fault_tx.stats();
        assert_eq!(
            stats.reorder_flushes, 0,
            "flush evidence must not be recorded when no message was delivered"
        );

        let entries = collector.entries();
        assert!(
            entries
                .iter()
                .all(|entry| entry.action != "inject_reorder_flush"),
            "no reorder_flush evidence when flush delivered nothing: {entries:?}"
        );
    }

    // =========================================================================
    // Pure data-type tests (wave 42 – CyanBarn)
    // =========================================================================

    #[test]
    fn fault_channel_config_debug_clone() {
        let config = FaultChannelConfig::new(42)
            .with_reorder(0.3, 8)
            .with_duplication(0.1);
        let cloned = config.clone();
        assert_eq!(cloned.seed, 42);
        assert_eq!(cloned.reorder_buffer_size, 8);
        let dbg = format!("{config:?}");
        assert!(dbg.contains("FaultChannelConfig"));
    }

    #[test]
    fn fault_channel_stats_debug_clone_default_display() {
        let def = FaultChannelStats::default();
        assert_eq!(def.messages_sent, 0);
        assert_eq!(def.messages_reordered, 0);
        assert_eq!(def.messages_duplicated, 0);
        assert_eq!(def.reorder_flushes, 0);
        let cloned = def.clone();
        assert_eq!(cloned.messages_sent, 0);
        let dbg = format!("{def:?}");
        assert!(dbg.contains("FaultChannelStats"));
        let display = format!("{def}");
        assert!(display.contains("sent: 0"));
    }

    #[test]
    fn fault_channel_convenience_constructor() {
        let sink: Arc<dyn EvidenceSink> = Arc::new(CollectorSink::new());
        let config = FaultChannelConfig::new(42)
            .with_reorder(0.5, 4)
            .with_duplication(0.2);
        let (fault_tx, mut rx) = fault_channel::<String>(16, config, sink);
        let cx = test_cx();

        block_on(fault_tx.send(&cx, "hello".to_string())).expect("send");
        block_on(fault_tx.flush(&cx)).expect("flush");

        let mut received = Vec::new();
        while let Ok(v) = rx.try_recv() {
            received.push(v);
        }
        assert!(received.contains(&"hello".to_string()));
    }
