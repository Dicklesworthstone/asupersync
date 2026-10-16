    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::trace::event::{TraceData, TraceEventKind};
    use crate::types::Time;

    fn make_event(seq: u64) -> TraceEvent {
        TraceEvent::new(
            seq,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message(format!("event {seq}")),
        )
    }

    #[test]
    fn push_and_iterate() {
        let mut buf = TraceBuffer::new(4);
        buf.push(make_event(1));
        buf.push(make_event(2));
        buf.push(make_event(3));

        let seqs: Vec<_> = buf.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn overflow_wraps() {
        let mut buf = TraceBuffer::new(3);
        buf.push(make_event(1));
        buf.push(make_event(2));
        buf.push(make_event(3));
        buf.push(make_event(4)); // Overwrites 1
        buf.push(make_event(5)); // Overwrites 2

        let seqs: Vec<_> = buf.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![3, 4, 5]);
    }

    #[test]
    fn trace_buffer_debug() {
        let buf = TraceBuffer::new(4);
        let dbg = format!("{buf:?}");
        assert!(dbg.contains("TraceBuffer"));
    }

    #[test]
    fn trace_buffer_new_capacity() {
        let buf = TraceBuffer::new(16);
        assert_eq!(buf.capacity(), 16);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert!(!buf.is_full());
    }

    #[test]
    fn trace_buffer_capacity_clamps_to_one() {
        let buf = TraceBuffer::new(0);
        assert_eq!(buf.capacity(), 1);
    }

    #[test]
    fn trace_buffer_is_full() {
        let mut buf = TraceBuffer::new(2);
        assert!(!buf.is_full());
        buf.push(make_event(1));
        assert!(!buf.is_full());
        buf.push(make_event(2));
        assert!(buf.is_full());
    }

    #[test]
    fn trace_buffer_clear() {
        let mut buf = TraceBuffer::new(4);
        buf.push(make_event(1));
        buf.push(make_event(2));
        assert_eq!(buf.len(), 2);
        buf.clear();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert!(buf.last().is_none());
    }

    #[test]
    fn trace_buffer_last_empty() {
        let buf = TraceBuffer::new(4);
        assert!(buf.last().is_none());
    }

    #[test]
    fn trace_buffer_regrows_and_wraps_after_clear() {
        // Exercises the lazy-growth re-use path: fill to capacity (physical
        // Vec fully grown + wrapped), clear (Vec::clear resets physical len
        // but keeps allocation), then push past capacity again so the ring
        // must re-grow from empty and wrap a second time.
        let mut buf = TraceBuffer::new(3);
        for seq in 1..=5 {
            buf.push(make_event(seq)); // ends holding 3,4,5
        }
        assert_eq!(buf.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![3, 4, 5]);
        assert!(buf.is_full());

        buf.clear();
        assert_eq!(buf.len(), 0);
        assert!(!buf.is_full());
        assert_eq!(buf.capacity(), 3);

        // Re-grow from empty and wrap again.
        for seq in 10..=14 {
            buf.push(make_event(seq)); // ends holding 12,13,14
        }
        assert_eq!(
            buf.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![12, 13, 14]
        );
        assert_eq!(buf.last().unwrap().seq, 14);
        assert!(buf.is_full());
    }

    #[test]
    fn trace_buffer_last_returns_newest() {
        let mut buf = TraceBuffer::new(4);
        buf.push(make_event(10));
        buf.push(make_event(20));
        buf.push(make_event(30));
        assert_eq!(buf.last().unwrap().seq, 30);
    }

    #[test]
    fn trace_buffer_default() {
        let buf = TraceBuffer::default();
        assert_eq!(buf.capacity(), 1024);
        assert!(buf.is_empty());
    }

    #[test]
    fn trace_buffer_iter_empty() {
        let buf = TraceBuffer::new(4);
        assert_eq!(buf.iter().count(), 0);
    }

    #[test]
    fn trace_buffer_handle_debug() {
        let handle = TraceBufferHandle::new(8);
        let dbg = format!("{handle:?}");
        assert!(dbg.contains("TraceBufferHandle"));
    }

    #[test]
    fn trace_buffer_handle_clone() {
        let handle = TraceBufferHandle::new(8);
        handle.push_event(make_event(1));
        let handle2 = handle.clone();
        // Cloned handle shares the same buffer
        assert_eq!(handle.len(), 1);
        assert_eq!(handle2.len(), 1);
    }

    #[test]
    fn trace_buffer_handle_next_seq_increments() {
        let handle = TraceBufferHandle::new(4);
        assert_eq!(handle.next_seq(), 0);
        assert_eq!(handle.next_seq(), 1);
        assert_eq!(handle.next_seq(), 2);
    }

    #[test]
    fn trace_buffer_handle_push_and_snapshot() {
        let handle = TraceBufferHandle::new(4);
        handle.push_event(make_event(10));
        handle.push_event(make_event(20));
        let snap = handle.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].seq, 10);
        assert_eq!(snap[1].seq, 20);
    }

    #[test]
    fn trace_buffer_handle_push_advances_sequence_allocator() {
        let handle = TraceBufferHandle::new(4);
        handle.push_event(make_event(10));
        handle.record_event(make_event);

        let seqs: Vec<_> = handle.snapshot().iter().map(|event| event.seq).collect();
        assert_eq!(seqs, vec![10, 11]);
    }

    #[test]
    fn trace_buffer_handle_len_and_is_empty() {
        let handle = TraceBufferHandle::new(4);
        assert!(handle.is_empty());
        assert_eq!(handle.len(), 0);
        assert_eq!(handle.total_pushed(), 0);
        handle.push_event(make_event(1));
        assert!(!handle.is_empty());
        assert_eq!(handle.len(), 1);
        assert_eq!(handle.total_pushed(), 1);
    }

    #[test]
    fn trace_buffer_handle_snapshot_empty() {
        let handle = TraceBufferHandle::new(4);
        let snap = handle.snapshot();
        assert!(snap.is_empty());
    }

    #[test]
    fn trace_buffer_handle_total_pushed_tracks_evictions() {
        let handle = TraceBufferHandle::new(2);
        handle.push_event(make_event(1));
        handle.push_event(make_event(2));
        handle.push_event(make_event(3));
        assert_eq!(handle.total_pushed(), 3);
        assert_eq!(handle.len(), 2);
        let snap = handle.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].seq, 2);
        assert_eq!(snap[1].seq, 3);
    }

    #[test]
    fn trace_buffer_handle_record_event_serializes_seq_and_insertion() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;
        use std::time::Duration;

        let handle = Arc::new(TraceBufferHandle::new(8));
        let slow_started = Arc::new(AtomicBool::new(false));

        let slow_handle = Arc::clone(&handle);
        let slow_started_flag = Arc::clone(&slow_started);
        let slow = thread::spawn(move || {
            slow_handle.record_event(|seq| {
                slow_started_flag.store(true, Ordering::Release);
                thread::sleep(Duration::from_millis(25));
                make_event(seq)
            });
        });

        while !slow_started.load(Ordering::Acquire) {
            thread::yield_now();
        }

        let fast_handle = Arc::clone(&handle);
        let fast = thread::spawn(move || {
            fast_handle.record_event(make_event);
        });

        slow.join().expect("slow trace recorder thread");
        fast.join().expect("fast trace recorder thread");

        let seqs: Vec<_> = handle.snapshot().iter().map(|event| event.seq).collect();
        assert_eq!(seqs, vec![0, 1]);
    }
