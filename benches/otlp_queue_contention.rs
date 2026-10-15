//! Bounded OTLP export-queue comparison.
//!
//! This benchmark compares a safe `Mutex<VecDeque<T>>` prototype with the
//! production [`BoundedExportQueue`]. It deliberately makes no fixed
//! performance-improvement claim: the Phase 8b queue experiment records the
//! measured result for each concurrency cell and keeps the incumbent unless
//! the safe prototype wins or ties every required axis.
//!
//! This is evidence for the bounded exporter surface only. Scheduler,
//! blocking-pool, and epoch queues require their own workload evidence.

use asupersync::observability::otlp_trace_exporter::BoundedExportQueue;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;
use std::thread;

const QUEUE_CAPACITY: usize = 1_000;
const TOTAL_OPERATIONS: usize = 65_536;
const THREAD_COUNTS: [usize; 4] = [1, 8, 32, 64];

// Mock span batch for benchmarking.
#[derive(Clone)]
struct BenchSpanBatch {
    id: u64,
    data: Vec<u8>,
}

impl BenchSpanBatch {
    fn new(id: u64, size: usize) -> Self {
        Self {
            id,
            data: vec![0u8; size],
        }
    }
}

// Safe bounded prototype with the production queue's drop-oldest semantics.
mod safe {
    use parking_lot::Mutex;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug)]
    pub struct MutexQueue<T> {
        queue: Mutex<VecDeque<T>>,
        capacity: usize,
        dropped_count: AtomicU64,
    }

    impl<T> MutexQueue<T> {
        pub fn new(capacity: usize) -> Self {
            Self {
                queue: Mutex::new(VecDeque::with_capacity(capacity)),
                capacity,
                dropped_count: AtomicU64::new(0),
            }
        }

        pub fn enqueue(&self, item: T) -> Option<T> {
            let mut queue = self.queue.lock();
            let dropped = if queue.len() == self.capacity {
                let dropped = queue.pop_front();
                self.dropped_count.fetch_add(1, Ordering::Relaxed);
                dropped
            } else {
                None
            };
            queue.push_back(item);
            dropped
        }

        pub fn dequeue(&self) -> Option<T> {
            self.queue.lock().pop_front()
        }

        pub fn len(&self) -> usize {
            self.queue.lock().len()
        }
    }
}

fn bench_queue_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("otlp_queue_contention");
    group.sample_size(10);

    // Fixed total work makes these strong-scaling cells comparable.
    for thread_count in THREAD_COUNTS {
        let operations_per_thread = TOTAL_OPERATIONS / thread_count;
        let total_ops = thread_count * operations_per_thread;

        group.throughput(Throughput::Elements(total_ops as u64));

        group.bench_with_input(
            BenchmarkId::new("safe_mutex_queue", thread_count),
            &thread_count,
            |b, &thread_count| {
                b.iter(|| {
                    let queue = Arc::new(safe::MutexQueue::new(QUEUE_CAPACITY));
                    let handles: Vec<_> = (0..thread_count)
                        .map(|thread_id| {
                            let queue = Arc::clone(&queue);
                            thread::spawn(move || {
                                for i in 0..operations_per_thread {
                                    let batch = BenchSpanBatch::new(
                                        (thread_id * operations_per_thread + i) as u64,
                                        64,
                                    );
                                    black_box(queue.enqueue(batch));

                                    // Match the incumbent cell's mixed producer/drain workload.
                                    if i % 10 == 0 {
                                        if let Some(batch) = queue.dequeue() {
                                            black_box((batch.id, batch.data.len()));
                                        }
                                    }
                                }
                            })
                        })
                        .collect();

                    for handle in handles {
                        handle.join().unwrap();
                    }
                    black_box(queue.len());
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("incumbent_array_queue", thread_count),
            &thread_count,
            |b, &thread_count| {
                b.iter(|| {
                    let queue = Arc::new(BoundedExportQueue::new(QUEUE_CAPACITY));
                    let handles: Vec<_> = (0..thread_count)
                        .map(|thread_id| {
                            let queue = Arc::clone(&queue);
                            thread::spawn(move || {
                                for i in 0..operations_per_thread {
                                    let batch = BenchSpanBatch::new(
                                        (thread_id * operations_per_thread + i) as u64,
                                        64,
                                    );
                                    black_box(queue.enqueue(batch));

                                    if i % 10 == 0 {
                                        if let Some(batch) = queue.dequeue() {
                                            black_box((batch.id, batch.data.len()));
                                        }
                                    }
                                }
                            })
                        })
                        .collect();

                    for handle in handles {
                        handle.join().unwrap();
                    }
                    black_box(queue.len());
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_queue_contention);
criterion_main!(benches);
