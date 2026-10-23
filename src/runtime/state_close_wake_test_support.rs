//! Shared runtime-lock and quiescence probes for completion close notifications.
use crate::record::region::{RegionCloseOutcome, RegionCloseState};
use crate::runtime::{RuntimeState, TaskTable};
use crate::sync::ContendedMutex;
use crate::types::RegionId;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Wake, Waker};

#[derive(Clone, Copy, Debug)]
pub enum ClosePanic {
    None,
    Wake,
    Drop,
}

/// A nonblocking reentry probe makes the old lock-held delivery fail instead
/// of hanging the entire test process. The second waiter is always healthy.
pub struct CloseProbe {
    state: Weak<ContendedMutex<RuntimeState>>,
    tasks: Option<Weak<ContendedMutex<TaskTable>>>,
    region: RegionId,
    notify: Arc<parking_lot::Mutex<RegionCloseState>>,
    receipt: Arc<parking_lot::Mutex<Option<RegionCloseOutcome>>>,
    heap_drops: Arc<AtomicUsize>,
    wakes: AtomicUsize,
    drops: AtomicUsize,
    state_unlocked: AtomicUsize,
    tasks_unlocked: AtomicUsize,
    retired: AtomicUsize,
    quiescent: AtomicUsize,
}

struct HeapWitness(Arc<AtomicUsize>);

impl Drop for HeapWitness {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl CloseProbe {
    pub(crate) fn install(
        state: &Arc<ContendedMutex<RuntimeState>>,
        tasks: Option<&Arc<ContendedMutex<TaskTable>>>,
        region: RegionId,
        panic: ClosePanic,
    ) -> Arc<Self> {
        let (notify, receipt, heap_drops) = {
            let state = state.lock().unwrap();
            let region = state.region(region).expect("live test region");
            let heap_drops = Arc::new(AtomicUsize::new(0));
            region
                .heap_alloc(HeapWitness(Arc::clone(&heap_drops)))
                .expect("admitted heap witness");
            (
                Arc::clone(&region.close_notify),
                region.close_receipt_handle(),
                heap_drops,
            )
        };
        let probe = Arc::new(Self {
            state: Arc::downgrade(state),
            tasks: tasks.map(Arc::downgrade),
            region,
            notify,
            receipt,
            heap_drops,
            wakes: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
            state_unlocked: AtomicUsize::new(0),
            tasks_unlocked: AtomicUsize::new(0),
            retired: AtomicUsize::new(0),
            quiescent: AtomicUsize::new(0),
        });
        let first = Waker::from(Arc::new(CloseWaiter {
            probe: Arc::clone(&probe),
            panic,
        }));
        let healthy = Waker::from(Arc::new(CloseWaiter {
            probe: Arc::clone(&probe),
            panic: ClosePanic::None,
        }));
        probe.notify.lock().waiters.extend([first, healthy]);
        probe
    }

    fn observe(&self, waking: bool) {
        if waking {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        } else {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(state) = self.state.upgrade() {
            let state = match state.try_lock() {
                Ok(state) => Some(state),
                Err(std::sync::TryLockError::Poisoned(error)) => Some(error.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => None,
            };
            if let Some(state) = state {
                self.state_unlocked.fetch_add(1, Ordering::SeqCst);
                if state.region(self.region).is_none() && state.region_was_closed(self.region) {
                    self.retired.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        if self.tasks.as_ref().is_none_or(|tasks| {
            tasks
                .upgrade()
                .is_some_and(|tasks| tasks.try_lock().is_ok())
        }) {
            self.tasks_unlocked.fetch_add(1, Ordering::SeqCst);
        }
        if self.heap_drops.load(Ordering::SeqCst) == 1
            && self.receipt.lock().is_some()
            && self.notify.lock().closed
        {
            self.quiescent.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub(crate) fn assert_delivered(&self) {
        assert_eq!(
            self.wakes.load(Ordering::SeqCst),
            2,
            "every close waiter wakes"
        );
        assert_eq!(
            self.drops.load(Ordering::SeqCst),
            2,
            "each handle retires once"
        );
        assert_eq!(
            self.state_unlocked.load(Ordering::SeqCst),
            4,
            "wake and drop callbacks may reenter RuntimeState"
        );
        assert_eq!(
            self.tasks_unlocked.load(Ordering::SeqCst),
            4,
            "wake and drop callbacks run outside the dispatch task table"
        );
        assert_eq!(
            self.retired.load(Ordering::SeqCst),
            4,
            "callbacks see completed region removal, not a half-completed walk"
        );
        assert_eq!(
            self.quiescent.load(Ordering::SeqCst),
            4,
            "heap destruction and the close receipt precede every callback"
        );
        assert!(self.notify.lock().waiters.is_empty());
        assert_eq!(self.heap_drops.load(Ordering::SeqCst), 1);
    }

    pub(crate) fn assert_pending(&self) {
        assert_eq!(self.wakes.load(Ordering::SeqCst), 0);
        assert_eq!(self.drops.load(Ordering::SeqCst), 0);
        assert_eq!(self.heap_drops.load(Ordering::SeqCst), 0);
        assert!(!self.notify.lock().closed);
        assert!(self.receipt.lock().is_none());
    }
}

struct CloseWaiter {
    probe: Arc<CloseProbe>,
    panic: ClosePanic,
}

impl Wake for CloseWaiter {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.probe.observe(true);
        assert!(
            !matches!(self.panic, ClosePanic::Wake),
            "close wake sentinel"
        );
    }
}

impl Drop for CloseWaiter {
    fn drop(&mut self) {
        self.probe.observe(false);
        assert!(
            !matches!(self.panic, ClosePanic::Drop),
            "close waker retirement sentinel"
        );
    }
}

pub async fn close_work(
    mut receive: Option<crate::channel::oneshot::Receiver<()>>,
    panic_task: bool,
) -> u8 {
    if let Some(receive) = receive.as_mut() {
        receive.recv_uninterruptible().await.expect("real wake");
    }
    assert!(!panic_task, "close task panic sentinel");
    73
}

pub struct RetirementProbe {
    wakes: AtomicUsize,
    drops: AtomicUsize,
}

impl RetirementProbe {
    pub(crate) fn arm(
        barrier: &crate::runtime::task_handle::RetirementBarrier,
        panic: ClosePanic,
    ) -> Arc<Self> {
        let probe = Arc::new(Self {
            wakes: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::new(RetirementWaiter {
            probe: Arc::clone(&probe),
            panic,
        }));
        assert!(!barrier.register_and_is_open(&waker));
        drop(waker);
        probe
    }

    pub(crate) fn assert_delivered(&self) {
        assert_eq!(self.wakes.load(Ordering::SeqCst), 1);
        assert_eq!(self.drops.load(Ordering::SeqCst), 1);
    }
}

struct RetirementWaiter {
    probe: Arc<RetirementProbe>,
    panic: ClosePanic,
}

impl Wake for RetirementWaiter {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.probe.wakes.fetch_add(1, Ordering::SeqCst);
        assert!(
            !matches!(self.panic, ClosePanic::Wake),
            "retirement wake sentinel"
        );
    }
}

impl Drop for RetirementWaiter {
    fn drop(&mut self) {
        self.probe.drops.fetch_add(1, Ordering::SeqCst);
        assert!(
            !matches!(self.panic, ClosePanic::Drop),
            "retirement drop sentinel"
        );
    }
}
