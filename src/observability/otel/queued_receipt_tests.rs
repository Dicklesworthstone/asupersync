//! Completion ownership, accounting, and synchronous observation boundaries.

use super::super::{
    Destination, OTLP_EXPORT_QUEUE_MAX_BATCHES, OTLP_EXPORT_QUEUE_MAX_BYTES, OtlpGrpcExporter,
    OtlpGrpcSignal,
};
use super::*;
use crate::grpc::Channel;
use std::panic::{AssertUnwindSafe, catch_unwind, panic_any};
use std::sync::Weak;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Wake;

fn transport() -> Arc<OtlpGrpcExporter> {
    let mut connect = std::pin::pin!(Channel::connect("http://127.0.0.1:4317"));
    let Poll::Ready(Ok(channel)) = connect
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("native channel construction performs no I/O");
    };
    Arc::new(OtlpGrpcExporter::new(channel).unwrap())
}

fn destination(exporter: Arc<OtlpGrpcExporter>) -> Destination {
    Destination::Grpc {
        exporter,
        retry_policy: None,
    }
}

fn admit(queue: &Arc<ExportQueue>, count: usize) -> OtlpGrpcQueueReceipt {
    queue
        .admit_encoded_with_receipt(
            destination(transport()),
            OtlpGrpcSignal::Metrics,
            vec![Vec::new(); count],
        )
        .unwrap()
}

fn varint(mut value: usize, bytes: &mut Vec<u8>) {
    while value >= 128 {
        bytes.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
        value >>= 7;
    }
    bytes.push(u8::try_from(value).unwrap());
}

fn response(rejected: u8, diagnostic: &str) -> OtlpGrpcResponse {
    assert!(rejected < 128);
    // Independent OTLP protobuf: outer partial_success field 1, then
    // rejected_data_points field 1 and error_message field 2.
    let mut partial = vec![0x08, rejected, 0x12];
    varint(diagnostic.len(), &mut partial);
    partial.extend_from_slice(diagnostic.as_bytes());
    let mut body = vec![0x0a];
    varint(partial.len(), &mut body);
    body.extend_from_slice(&partial);
    OtlpGrpcResponse::from_encoded_for_test(OtlpGrpcSignal::Metrics, &body).unwrap()
}

fn poll(
    receipt: &mut OtlpGrpcQueueReceipt,
) -> Poll<Result<OtlpGrpcExportReport, OtlpGrpcQueueReceiptError>> {
    Pin::new(receipt).poll(&mut Context::from_waker(Waker::noop()))
}

fn acknowledge(delivery: &mut super::super::Delivery<'_>, rejected: u8, diagnostic: &str) {
    delivery
        .batch
        .as_mut()
        .unwrap()
        .completion
        .as_mut()
        .unwrap()
        .acknowledge(response(rejected, diagnostic));
    delivery.delivered = true;
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct RetirementWitness {
    queue: Weak<ExportQueue>,
    completion: Weak<Completion>,
    exporter: Weak<OtlpGrpcExporter>,
    wakes: Arc<AtomicUsize>,
}

impl Wake for RetirementWitness {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let queue = self.queue.upgrade().unwrap();
        let state = queue
            .state
            .try_lock()
            .expect("receipt wake is outside the queue lock");
        assert_eq!(state.stats.retained_batches, 0);
        assert_eq!(state.stats.retained_bytes, 0);
        drop(state);
        let completion = self.completion.upgrade().unwrap();
        let state = completion
            .state
            .try_lock()
            .expect("receipt wake is outside its lock");
        assert_eq!(state.remaining, 0);
        assert!(state.ready);
        assert!(
            self.exporter.upgrade().is_none(),
            "captured transport retired before publication"
        );
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn success_is_published_after_payload_transport_and_aggregate_credit_retire() {
    let queue = Arc::new(ExportQueue::default());
    let exporter = transport();
    let exporter_weak = Arc::downgrade(&exporter);
    let body = Vec::with_capacity(1024);
    let expected = body.capacity() + exporter.configuration_bytes() + RESERVED_BYTES_PER_BATCH;
    let mut receipt = queue
        .admit_encoded_with_receipt(destination(exporter), OtlpGrpcSignal::Metrics, vec![body])
        .unwrap();
    assert_eq!(queue.state.lock().stats.retained_bytes, expected);
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(RetirementWitness {
        queue: Arc::downgrade(&queue),
        completion: Arc::downgrade(&receipt.completion),
        exporter: exporter_weak,
        wakes: Arc::clone(&wakes),
    }));
    assert!(
        Pin::new(&mut receipt)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    let mut delivery = queue.take().unwrap();
    acknowledge(&mut delivery, 3, "collector diagnostic");
    assert!(
        Pin::new(&mut receipt)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert_eq!(queue.state.lock().stats.retained_batches, 1);
    assert_eq!(wakes.load(Ordering::SeqCst), 0);
    drop(delivery);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    let Poll::Ready(Ok(report)) = poll(&mut receipt) else {
        panic!("retired receipt must be ready")
    };
    assert_eq!(report.responses().len(), 1);
    assert_eq!(report.responses()[0].rejected_items(), 3);
    assert_eq!(
        report.responses()[0].error_message(),
        "collector diagnostic"
    );
}

#[test]
fn failure_keeps_ordered_prior_acknowledgements_and_their_full_reservation() {
    let queue = Arc::new(ExportQueue::default());
    let mut receipt = admit(&queue, 3);
    let mut first = queue.take().unwrap();
    let mut second = queue.take().unwrap();
    let mut last = queue.take().unwrap();
    let last_payload_bytes = last.batch.as_ref().unwrap().bytes;
    let diagnostic = "s".repeat(4096);
    acknowledge(&mut first, 1, &diagnostic);
    acknowledge(&mut second, 2, "second response");
    // Completion order does not change the original collection order.
    drop(second);
    drop(first);
    assert!(poll(&mut receipt).is_pending());
    assert_eq!(
        queue.state.lock().stats.retained_bytes,
        last_payload_bytes + 3 * RESERVED_BYTES_PER_BATCH
    );
    last.batch
        .as_mut()
        .unwrap()
        .completion
        .as_mut()
        .unwrap()
        .fail("otlp.grpc.status", Some(Code::PermissionDenied));
    drop(last);
    assert_eq!(queue.state.lock().stats.retained_bytes, 0);
    let Poll::Ready(Err(error)) = poll(&mut receipt) else {
        panic!("failed collection must resolve")
    };
    assert_eq!(error.code(), "otlp.grpc.status");
    assert_eq!(error.grpc_code(), Some(Code::PermissionDenied));
    assert_eq!(
        error
            .completed_responses()
            .iter()
            .map(OtlpGrpcResponse::rejected_items)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(error.completed_responses()[0].error_message(), diagnostic);
    assert!(!format!("{error} {error:?}").contains("second response"));
    assert!(!format!("{error:?}").contains(&diagnostic));
    let stats = queue.state.lock().stats;
    assert_eq!(stats.delivered_batches, 2);
    assert_eq!(stats.failed_batches, 1);
}

#[test]
fn dropping_observation_preserves_admitted_work_and_releases_completion_ownership() {
    let queue = Arc::new(ExportQueue::default());
    let receipt = admit(&queue, 2);
    let completion = Arc::downgrade(&receipt.completion);
    let before = queue.state.lock().stats;
    drop(receipt);
    assert_eq!(queue.state.lock().stats, before);
    assert!(
        completion.upgrade().is_some(),
        "queue still owns both terminal tokens"
    );
    for _ in 0..2 {
        let mut delivery = queue.take().unwrap();
        acknowledge(&mut delivery, 0, "unobserved warning");
        drop(delivery);
    }
    assert!(completion.upgrade().is_none());
    let stats = queue.state.lock().stats;
    assert_eq!(stats.delivered_batches, 2);
    assert_eq!(stats.failed_batches, 0);
    assert_eq!(stats.retained_batches, 0);
    assert_eq!(stats.retained_bytes, 0);
}

#[test]
fn retained_receipt_does_not_keep_an_abandoned_queue_alive() {
    let queue = Arc::new(ExportQueue::default());
    let weak = Arc::downgrade(&queue);
    let mut receipt = admit(&queue, 2);
    assert!(poll(&mut receipt).is_pending());
    drop(queue);
    assert!(
        weak.upgrade().is_none(),
        "receipt must not form a queue ownership cycle"
    );
    let Poll::Ready(Err(error)) = poll(&mut receipt) else {
        panic!("queue Drop resolves its receipts")
    };
    assert_eq!(error.code(), "otlp.queue.abandoned");
    assert!(error.completed_responses().is_empty());
}

struct DropWitness {
    completion: Weak<Completion>,
    drops: Arc<AtomicUsize>,
}

impl Wake for DropWitness {
    fn wake(self: Arc<Self>) {}
}

impl Drop for DropWitness {
    fn drop(&mut self) {
        if let Some(completion) = self.completion.upgrade() {
            assert!(
                completion.state.try_lock().is_some(),
                "waker destruction cannot hold the completion lock"
            );
        }
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn replacement_and_observer_drop_retire_wakers_outside_the_completion_lock() {
    let queue = Arc::new(ExportQueue::default());
    let mut receipt = admit(&queue, 1);
    let completion = Arc::downgrade(&receipt.completion);
    let drops = Arc::new(AtomicUsize::new(0));
    for expected in 0..2 {
        let waker = Waker::from(Arc::new(DropWitness {
            completion: completion.clone(),
            drops: Arc::clone(&drops),
        }));
        assert!(
            Pin::new(&mut receipt)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(waker);
        assert_eq!(drops.load(Ordering::SeqCst), expected);
    }
    drop(receipt);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(queue.state.lock().stats.retained_batches, 1);
    drop(queue);
    assert!(completion.upgrade().is_none());
}

struct PanicPayloadDrop(Arc<AtomicUsize>);

impl Drop for PanicPayloadDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("a swallowed panic payload must not be dropped during retirement");
    }
}

struct HostileWake {
    panic_on_wake: bool,
    panic_payload_drops: Arc<AtomicUsize>,
}

impl Wake for HostileWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.panic_on_wake {
            panic_any(PanicPayloadDrop(Arc::clone(&self.panic_payload_drops)));
        }
    }
}

impl Drop for HostileWake {
    fn drop(&mut self) {
        if !self.panic_on_wake {
            panic_any(PanicPayloadDrop(Arc::clone(&self.panic_payload_drops)));
        }
    }
}

#[test]
fn hostile_wake_or_destructor_cannot_interrupt_other_collection_retirement() {
    for panic_on_wake in [false, true] {
        let queue = Arc::new(ExportQueue::default());
        let mut hostile = admit(&queue, 1);
        let mut healthy = admit(&queue, 1);
        let panic_payload_drops = Arc::new(AtomicUsize::new(0));
        let bad_waker = Waker::from(Arc::new(HostileWake {
            panic_on_wake,
            panic_payload_drops: Arc::clone(&panic_payload_drops),
        }));
        assert!(
            Pin::new(&mut hostile)
                .poll(&mut Context::from_waker(&bad_waker))
                .is_pending()
        );
        drop(bad_waker);
        let wakes = Arc::new(WakeCount::default());
        let good_waker = Waker::from(Arc::clone(&wakes));
        assert!(
            Pin::new(&mut healthy)
                .poll(&mut Context::from_waker(&good_waker))
                .is_pending()
        );
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(queue))) {
            std::mem::forget(payload);
            panic!("waker callbacks escaped collection retirement");
        }
        assert_eq!(panic_payload_drops.load(Ordering::SeqCst), 0);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert!(matches!(poll(&mut hostile), Poll::Ready(Err(_))));
        assert!(matches!(poll(&mut healthy), Poll::Ready(Err(_))));
    }
}

#[test]
fn receipt_reservations_participate_in_atomic_capacity_admission() {
    let queue = Arc::new(ExportQueue::default());
    let exporter = transport();
    let requests = vec![Vec::with_capacity(1024), Vec::with_capacity(2048)];
    let expected = requests.iter().map(Vec::capacity).sum::<usize>()
        + 2 * exporter.configuration_bytes()
        + 2 * RESERVED_BYTES_PER_BATCH;
    let receipt = queue
        .admit_encoded_with_receipt(destination(exporter), OtlpGrpcSignal::Metrics, requests)
        .unwrap();
    let before = queue.state.lock().stats;
    assert_eq!(before.retained_bytes, expected);
    assert_eq!(before.retained_batches, 2);
    for requests in [
        vec![Vec::new(); OTLP_EXPORT_QUEUE_MAX_BATCHES],
        vec![Vec::with_capacity(OTLP_EXPORT_QUEUE_MAX_BYTES)],
    ] {
        assert!(
            queue
                .admit_encoded_with_receipt(
                    destination(transport()),
                    OtlpGrpcSignal::Metrics,
                    requests,
                )
                .is_err()
        );
        assert_eq!(
            queue.state.lock().stats,
            before,
            "refusal publishes no collection prefix"
        );
    }
    drop(receipt);
    drop(queue);
}

#[test]
fn flush_barrier_waits_for_diagnostic_credit_after_payload_retirement() {
    let _ambient = crate::Cx::set_current(None);
    let queue = Arc::new(ExportQueue::default());
    let mut receipt = admit(&queue, 1);
    {
        let mut state = queue.state.lock();
        state.managed = true;
        state.acknowledged_owner_ready = true;
        state.stats.consumer_active = true;
    }
    let mut delivery = queue.take().unwrap();
    acknowledge(&mut delivery, 0, "warning");
    // Hold the already-acknowledged completion at the exact boundary used by
    // Delivery::drop: payload and batch credit retire before this last token.
    let completion = delivery.batch.as_mut().unwrap().completion.take().unwrap();
    drop(delivery);
    assert_eq!(queue.state.lock().stats.retained_batches, 0);
    assert_eq!(
        queue.state.lock().stats.retained_bytes,
        RESERVED_BYTES_PER_BATCH
    );
    assert!(poll(&mut receipt).is_pending());
    assert!(queue.check_flushed().is_err());
    assert!(
        queue
            .wait_flushed_blocking(Duration::ZERO, false)
            .unwrap_err()
            .to_string()
            .contains("otlp.sdk.flush_timeout")
    );
    drop(completion);
    assert!(matches!(poll(&mut receipt), Poll::Ready(Ok(_))));
    assert!(queue.check_flushed().is_ok());
    assert!(queue.wait_flushed_blocking(Duration::ZERO, false).is_ok());
    // Shutdown additionally waits for the managed owner to retire.
    assert!(
        queue
            .wait_flushed_blocking(Duration::ZERO, true)
            .unwrap_err()
            .to_string()
            .contains("otlp.sdk.flush_timeout")
    );
    queue.state.lock().stats.consumer_active = false;
    assert!(queue.wait_flushed_blocking(Duration::ZERO, true).is_ok());
}

#[test]
fn synchronous_sdk_barriers_refuse_pending_work_on_a_runtime_context() {
    let queue = Arc::new(ExportQueue::default());
    let receipt = admit(&queue, 1);
    let _ambient = crate::Cx::set_current(Some(crate::Cx::for_testing()));
    for shutdown in [false, true] {
        let error = queue
            .wait_flushed_blocking(Duration::from_secs(1), shutdown)
            .unwrap_err();
        assert!(error.to_string().contains("otlp.sdk.blocking_on_runtime"));
    }
    assert!(
        queue.state.lock().sealed,
        "shutdown seals even when synchronous waiting is refused"
    );
    drop(receipt);
    drop(queue);
    let empty = ExportQueue::default();
    assert!(empty.wait_flushed_blocking(Duration::ZERO, false).is_ok());
    assert!(empty.wait_flushed_blocking(Duration::ZERO, true).is_ok());
}

#[test]
fn a_consumer_claim_does_not_authorize_sdk_admission_before_submission_commits() {
    let queue = ExportQueue::default();
    {
        let mut state = queue.state.lock();
        state.managed = true;
        state.stats.consumer_active = true;
    }
    assert!(
        queue
            .ensure_managed_active()
            .unwrap_err()
            .to_string()
            .contains("otlp.sdk.managed_owner_required")
    );
    queue.state.lock().acknowledged_owner_ready = true;
    assert!(queue.ensure_managed_active().is_ok());
    queue.state.lock().sealed = true;
    assert!(
        queue
            .ensure_managed_active()
            .unwrap_err()
            .to_string()
            .contains("otlp.queue.closed")
    );
}
