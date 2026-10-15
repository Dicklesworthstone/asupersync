#![no_main]

use arbitrary::Arbitrary;
use asupersync::channel::watch;
use libfuzzer_sys::fuzz_target;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;

const MAX_RECEIVERS: usize = 8;
const MAX_PRE_SEND_YIELDS: u8 = 16;
const MAX_BETWEEN_SEND_YIELDS: u8 = 16;
const MAX_OBSERVATION_ROUNDS: u8 = 32;
const INITIAL_VERSION: u8 = 0;
const FINAL_VERSION: u8 = 3;

#[derive(Debug, Arbitrary)]
struct WatchConcurrentSendInput {
    receiver_count: u8,
    pre_send_yields: u8,
    between_send_yields: u8,
    observation_rounds: u8,
    seed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WatchValue {
    version: u8,
    payload: u64,
}

fuzz_target!(|input: WatchConcurrentSendInput| {
    drive_concurrent_send_and_borrow(input);
});

fn drive_concurrent_send_and_borrow(input: WatchConcurrentSendInput) {
    let receiver_count = (usize::from(input.receiver_count) % MAX_RECEIVERS).saturating_add(1);
    let observation_rounds = input.observation_rounds.min(MAX_OBSERVATION_ROUNDS);
    let pre_send_yields = input.pre_send_yields.min(MAX_PRE_SEND_YIELDS);
    let between_send_yields = input.between_send_yields.min(MAX_BETWEEN_SEND_YIELDS);

    let (sender, first_receiver) = watch::channel(versioned_value(INITIAL_VERSION, input.seed));
    let sender = Arc::new(sender);
    let sender_done = Arc::new(AtomicBool::new(false));
    let final_seen = Arc::new(AtomicUsize::new(0));
    let observations = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(receiver_count + 1));

    let mut receivers = Vec::with_capacity(receiver_count);
    receivers.push(first_receiver);
    for _ in 1..receiver_count {
        receivers.push(sender.subscribe());
    }

    let mut receiver_handles = Vec::with_capacity(receiver_count);
    for mut receiver in receivers {
        let barrier = Arc::clone(&barrier);
        let sender_done = Arc::clone(&sender_done);
        let final_seen = Arc::clone(&final_seen);
        let observations = Arc::clone(&observations);

        receiver_handles.push(thread::spawn(move || {
            barrier.wait();

            for _ in 0..observation_rounds {
                let value = *receiver.borrow_and_update();
                assert!(
                    value.version <= FINAL_VERSION,
                    "watch receiver observed an impossible version: {value:?}"
                );
                observations.fetch_add(1, Ordering::Relaxed);
                thread::yield_now();
            }

            while !sender_done.load(Ordering::Acquire) {
                let value = *receiver.borrow_and_update();
                assert!(
                    value.version <= FINAL_VERSION,
                    "watch receiver observed an impossible version before sender completion: {value:?}"
                );
                observations.fetch_add(1, Ordering::Relaxed);
                thread::yield_now();
            }

            let latest = *receiver.borrow_and_update();
            assert_eq!(
                latest.version, FINAL_VERSION,
                "borrow_and_update must return the latest rapid watch update"
            );
            final_seen.fetch_add(1, Ordering::Release);
        }));
    }

    let sender_handle = {
        let sender = Arc::clone(&sender);
        let sender_done = Arc::clone(&sender_done);
        let barrier = Arc::clone(&barrier);
        let seed = input.seed;

        thread::spawn(move || {
            barrier.wait();
            yield_repeated(pre_send_yields);

            sender
                .send(versioned_value(1, seed))
                .expect("watch sender must publish V1");
            yield_repeated(between_send_yields);
            sender
                .send(versioned_value(2, seed))
                .expect("watch sender must publish V2");
            yield_repeated(between_send_yields);
            sender
                .send(versioned_value(3, seed))
                .expect("watch sender must publish V3");

            sender_done.store(true, Ordering::Release);
        })
    };

    sender_handle
        .join()
        .expect("rapid watch sender thread must not panic");
    for handle in receiver_handles {
        handle
            .join()
            .expect("borrow_and_update receiver thread must not panic");
    }

    assert_eq!(
        final_seen.load(Ordering::Acquire),
        receiver_count,
        "all watch receivers must observe the final V3 update"
    );
    assert!(
        observations.load(Ordering::Relaxed) >= receiver_count,
        "each watch receiver must make at least one borrow_and_update observation"
    );
}

fn versioned_value(version: u8, seed: u64) -> WatchValue {
    WatchValue {
        version,
        payload: seed.rotate_left(u32::from(version)) ^ u64::from(version).wrapping_mul(0x9E37),
    }
}

fn yield_repeated(count: u8) {
    for _ in 0..count {
        thread::yield_now();
    }
}
