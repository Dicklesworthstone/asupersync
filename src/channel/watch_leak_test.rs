use asupersync::channel::watch;
use asupersync::cx::Cx;
use asupersync::{RegionId, TaskId};
use asupersync::types::Budget;
use asupersync::util::ArenaIndex;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::pin::Pin;
use std::future::Future;

struct CountWake {
    count: Arc<AtomicUsize>,
}
impl std::task::Wake for CountWake {
    fn wake(self: Arc<Self>) { self.count.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.count.fetch_add(1, Ordering::SeqCst); }
}

fn main() {
    let cx = Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    );
    let (tx, mut rx) = watch::channel(0);

    let drop_flag = Arc::new(AtomicUsize::new(0));
    struct TrackDrop(Arc<AtomicUsize>);
    impl Drop for TrackDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let track = TrackDrop(Arc::clone(&drop_flag));
    
    // Create a waker that captures our track
    let waker_core = Arc::new(CountWake { count: Arc::new(AtomicUsize::new(0)) });
    
    // We can't put TrackDrop in Waker easily without custom waker, so let's just inspect tx waiters count.
    
    let waker = Waker::from(waker_core);
    let mut task_cx = Context::from_waker(&waker);
    
    {
        let mut future = rx.changed(&cx);
        let _ = Pin::new(&mut future).poll(&mut task_cx);
        // future dropped here
    }
    
    let waiters_len = rx.is_closed(); // just to call a method
    println!("Waiters exist after drop? (If we check internal state)");
}
