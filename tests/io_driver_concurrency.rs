#![allow(missing_docs)]

use asupersync::runtime::io_driver::IoDriverHandle;
use asupersync::runtime::reactor::{Events, Interest, Reactor, Source, Token};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[derive(Default)]
struct BlockingReactor {
    poll_started: (Mutex<bool>, Condvar),
    poll_released: (Mutex<bool>, Condvar),
    polls: AtomicUsize,
    registrations: AtomicUsize,
}

impl BlockingReactor {
    fn wait_until_poll_started(&self) {
        let (lock, condvar) = &self.poll_started;
        let mut started = lock.lock().expect("poll_started mutex poisoned");
        while !*started {
            started = condvar
                .wait(started)
                .expect("poll_started condvar poisoned");
        }
    }

    fn release_poll(&self) {
        let (lock, condvar) = &self.poll_released;
        let mut released = lock.lock().expect("poll_released mutex poisoned");
        *released = true;
        condvar.notify_all();
    }

    fn poll_calls(&self) -> usize {
        self.polls.load(Ordering::SeqCst)
    }
}

impl Reactor for BlockingReactor {
    fn register(&self, _source: &dyn Source, _token: Token, _interest: Interest) -> io::Result<()> {
        self.registrations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn modify(&self, _token: Token, _interest: Interest) -> io::Result<()> {
        Ok(())
    }

    fn deregister(&self, _token: Token) -> io::Result<()> {
        let mut current = self.registrations.load(Ordering::SeqCst);
        loop {
            if current == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "token not registered",
                ));
            }
            match self.registrations.compare_exchange(
                current,
                current - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    fn poll(&self, events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
        events.clear();
        self.polls.fetch_add(1, Ordering::SeqCst);

        {
            let (lock, condvar) = &self.poll_started;
            let mut started = lock.lock().expect("poll_started mutex poisoned");
            *started = true;
            condvar.notify_all();
        }

        let (lock, condvar) = &self.poll_released;
        let mut released = lock.lock().expect("poll_released mutex poisoned");
        while !*released {
            released = condvar
                .wait(released)
                .expect("poll_released condvar poisoned");
        }

        Ok(0)
    }

    fn wake(&self) -> io::Result<()> {
        Ok(())
    }

    fn registration_count(&self) -> usize {
        self.registrations.load(Ordering::SeqCst)
    }
}

#[test]
fn io_driver_handle_rejects_follower_poll_while_leader_is_active() {
    let reactor = Arc::new(BlockingReactor::default());
    let handle = IoDriverHandle::new(reactor.clone());
    let leader_handle = handle.clone();

    let leader =
        std::thread::spawn(move || leader_handle.try_turn_with(Some(Duration::ZERO), |_, _| {}));

    reactor.wait_until_poll_started();

    let busy_try = handle
        .try_turn_with(Some(Duration::ZERO), |_, _| {})
        .expect("busy try_turn_with should not fail");
    assert!(busy_try.is_none());

    let busy_turn = handle
        .turn_with(Some(Duration::ZERO), |_, _| {})
        .expect("busy turn_with should not fail");
    assert_eq!(busy_turn, 0);
    assert_eq!(reactor.poll_calls(), 1);

    reactor.release_poll();
    let leader_result = leader.join().expect("leader poll thread panicked");
    assert_eq!(leader_result.expect("leader poll should succeed"), Some(0));

    assert_eq!(handle.stats().polls, 1);
}
