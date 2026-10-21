use super::*;
use std::future::Future;
use std::task::Waker;

fn budget(bytes: usize, chunk: usize, reads: usize) -> StreamBudget {
    StreamBudget::new(FetchStreamLimits::new(FetchBytesLimits::new(0, bytes, reads), chunk))
}

#[test]
fn total_limit_counts_previously_delivered_chunks() {
    let mut budget = budget(5, 3, 4);
    assert_eq!(budget.copy_buffer(3).unwrap().len(), 3);
    budget.commit(3).unwrap();
    assert_eq!(budget.copy_buffer(3), Err(FetchBytesError::ResponseLimit { limit: 5 }));
    assert_eq!(budget.received(), 3);
    budget.copy_buffer(2).unwrap();
    budget.commit(2).unwrap();
    assert_eq!(budget.received(), 5);
}

#[test]
fn chunk_limit_is_independent_of_total_transfer_limit() {
    let budget = budget(1_000_000, 4, 10);
    assert_eq!(budget.copy_buffer(5), Err(FetchBytesError::ChunkLimit { limit: 4 }));
    assert_eq!(budget.received(), 0);
}

#[test]
fn zero_chunk_limit_accepts_empty_chunks_but_not_payloads() {
    let budget = budget(10, 0, 3);
    assert_eq!(budget.copy_buffer(0), Ok(Vec::new()));
    assert_eq!(budget.copy_buffer(1), Err(FetchBytesError::ChunkLimit { limit: 0 }));
}

#[test]
fn every_host_read_including_empty_and_eof_uses_work_budget() {
    let mut budget = budget(0, 0, 2);
    budget.begin_read().unwrap();
    budget.commit(0).unwrap();
    budget.begin_read().unwrap();
    assert_eq!(budget.begin_read(), Err(FetchBytesError::ReadLimit { limit: 2 }));
}

#[test]
fn zero_read_budget_refuses_without_incrementing() {
    let mut budget = budget(100, 100, 0);
    for _ in 0..3 {
        assert_eq!(budget.begin_read(), Err(FetchBytesError::ReadLimit { limit: 0 }));
    }
}

#[test]
fn total_length_overflow_fails_before_allocation() {
    let mut budget = budget(usize::MAX, usize::MAX, 2);
    budget.commit(usize::MAX).unwrap();
    assert_eq!(budget.copy_buffer(1), Err(FetchBytesError::LengthOverflow));
    assert_eq!(budget.received(), usize::MAX);
}

#[test]
fn allocating_a_destination_does_not_report_delivery() {
    let mut budget = budget(16, 16, 3);
    let _discarded = budget.copy_buffer(16).unwrap();
    assert_eq!(budget.received(), 0);
    budget.commit(8).unwrap();
    assert_eq!(budget.received(), 8);
}

#[test]
fn rejected_commit_does_not_advance_the_delivered_prefix() {
    let mut budget = budget(4, 4, 2);
    budget.commit(3).unwrap();
    assert_eq!(budget.commit(2), Err(FetchBytesError::ResponseLimit { limit: 4 }));
    assert_eq!(budget.received(), 3);
}

#[test]
fn native_streaming_fails_without_admitting_a_handle() {
    crate::reset_dispatcher_for_tests();
    let runtime = crate::with_dispatcher(|d| d.runtime_create(None)).unwrap();
    let request = WasmFetchRequest {
        scope: runtime, url: "https://example.invalid/".into(), method: "GET".into(),
        credentials: false, body: None,
    };
    let mut open = Box::pin(fetch_stream(request,
        FetchStreamLimits::new(FetchBytesLimits::new(0, 10, 2), 10), None));
    assert!(matches!(open.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(FetchBytesError::UnsupportedHost))));
    crate::DISPATCHER.with(|d| assert_eq!(d.borrow().handles().memory_report().live_handles, 1));
    crate::runtime_close_impl(serde_json::to_string(&runtime).unwrap(), None).unwrap();
}
