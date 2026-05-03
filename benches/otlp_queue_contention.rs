//! Benchmark demonstrating OTLP queue mutex contention fix.
//!
//! **PURPOSE**: Verify 10x+ performance improvement after converting
//! Mutex<VecDeque<T>> to lock-free ArrayQueue<T>.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Mock span batch for benchmarking
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

// Legacy mutex-based queue (original implementation)
mod legacy {
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

        pub fn enqueue(&self, item: T) -> bool {
            let mut queue = self.queue.lock();
            let dropped = if queue.len() >= self.capacity {
                queue.pop_front(); // Drop oldest
                self.dropped_count.fetch_add(1, Ordering::Relaxed);
                true
            } else {
                false
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

// Lock-free queue (new implementation)
mod lock_free {
    use crossbeam_queue::ArrayQueue;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    #[derive(Debug)]
    pub struct LockFreeQueue<T> {
        queue: ArrayQueue<T>,
        capacity: usize,
        current_len: AtomicUsize,
        dropped_count: AtomicU64,
    }

    impl<T> LockFreeQueue<T> {
        pub fn new(capacity: usize) -> Self {
            Self {
                queue: ArrayQueue::new(capacity),
                capacity,
                current_len: AtomicUsize::new(0),
                dropped_count: AtomicU64::new(0),
            }
        }

        pub fn enqueue(&self, item: T) -> bool {
            let mut dropped = false;

            match self.queue.push(item) {
                Ok(()) => {
                    self.current_len.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                Err(returned_item) => {
                    if let Some(_oldest) = self.queue.pop() {
                        self.dropped_count.fetch_add(1, Ordering::Relaxed);
                        self.current_len.fetch_sub(1, Ordering::Relaxed);
                        dropped = true;

                        if let Err(_) = self.queue.push(returned_item) {
                            return dropped;
                        }
                    } else {
                        if let Err(_) = self.queue.push(returned_item) {
                            return dropped;
                        }
                    }
                }
            }

            self.current_len.fetch_add(1, Ordering::Relaxed);
            dropped
        }

        pub fn dequeue(&self) -> Option<T> {
            if let Some(item) = self.queue.pop() {
                self.current_len.fetch_sub(1, Ordering::Relaxed);
                Some(item)
            } else {
                None
            }
        }

        pub fn len(&self) -> usize {
            self.current_len.load(Ordering::Relaxed)
        }
    }
}

fn bench_queue_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("otlp_queue_contention");

    // Test with different thread counts to show contention effects
    for thread_count in [1, 2, 4, 8, 16] {
        let operations_per_thread = 10000;
        let total_ops = thread_count * operations_per_thread;

        group.throughput(Throughput::Elements(total_ops as u64));

        // Benchmark mutex-based queue
        group.bench_with_input(
            BenchmarkId::new("mutex_queue", thread_count),
            &thread_count,
            |b, &thread_count| {
                b.iter(|| {
                    let queue = Arc::new(legacy::MutexQueue::new(1000));
                    let handles: Vec<_> = (0..thread_count)
                        .map(|thread_id| {
                            let queue = Arc::clone(&queue);
                            thread::spawn(move || {
                                for i in 0..operations_per_thread {
                                    let batch = BenchSpanBatch::new(
                                        (thread_id * operations_per_thread + i) as u64,
                                        64
                                    );
                                    queue.enqueue(batch);

                                    // Occasionally dequeue to prevent queue from staying full
                                    if i % 10 == 0 {
                                        let _ = queue.dequeue();
                                    }
                                }
                            })
                        })
                        .collect();

                    for handle in handles {
                        handle.join().unwrap();
                    }
                });
            },
        );

        // Benchmark lock-free queue
        group.bench_with_input(
            BenchmarkId::new("lock_free_queue", thread_count),
            &thread_count,
            |b, &thread_count| {
                b.iter(|| {
                    let queue = Arc::new(lock_free::LockFreeQueue::new(1000));
                    let handles: Vec<_> = (0..thread_count)
                        .map(|thread_id| {
                            let queue = Arc::clone(&queue);
                            thread::spawn(move || {
                                for i in 0..operations_per_thread {
                                    let batch = BenchSpanBatch::new(
                                        (thread_id * operations_per_thread + i) as u64,
                                        64
                                    );
                                    queue.enqueue(batch);

                                    // Occasionally dequeue to prevent queue from staying full
                                    if i % 10 == 0 {
                                        let _ = queue.dequeue();
                                    }
                                }
                            })
                        })
                        .collect();

                    for handle in handles {
                        handle.join().unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_queue_contention);
criterion_main!(benches);