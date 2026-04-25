//! Regression tests for `OnceCell::set` during in-flight initialization.

use asupersync::sync::OnceCell;
use std::sync::{Arc, mpsc};
use std::thread;

#[test]
fn set_fails_immediately_while_blocking_initializer_is_in_flight() {
    let cell = Arc::new(OnceCell::<u32>::new());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let cell_clone = Arc::clone(&cell);
    let handle = thread::spawn(move || {
        let res = cell_clone.get_or_init_blocking(|| {
            entered_tx
                .send(())
                .expect("initializer should report entry");
            release_rx.recv().expect("initializer should be released");
            42
        });
        assert_eq!(*res, 42);
    });

    entered_rx
        .recv()
        .expect("initializer should reach INITIALIZING state");

    let set_result = cell.set(99);
    assert_eq!(
        set_result,
        Err(99),
        "set should fail immediately while another thread initializes"
    );

    release_tx
        .send(())
        .expect("initializer release should send");
    handle.join().unwrap();

    assert_eq!(cell.get(), Some(&42));
}

#[test]
fn set_can_succeed_after_in_flight_blocking_initializer_panics() {
    let cell = Arc::new(OnceCell::<u32>::new());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let cell_clone = Arc::clone(&cell);
    let handle = thread::spawn(move || {
        let panic_result = std::panic::catch_unwind(|| {
            cell_clone.get_or_init_blocking(|| {
                entered_tx
                    .send(())
                    .expect("initializer should report entry");
                release_rx.recv().expect("initializer should be released");
                panic!("cancelled");
            });
        });
        assert!(
            panic_result.is_err(),
            "initializer should panic so the cell resets to UNINIT"
        );
    });

    entered_rx
        .recv()
        .expect("initializer should reach INITIALIZING state");

    let in_flight_set_result = cell.set(99);
    assert_eq!(
        in_flight_set_result,
        Err(99),
        "set should fail immediately while initialization is in progress"
    );

    release_tx
        .send(())
        .expect("initializer release should send");
    handle.join().unwrap();

    let set_result = cell.set(99);
    assert_eq!(set_result, Ok(()), "set should succeed after cancellation");
    assert_eq!(cell.get(), Some(&99), "cell should contain 99");
}
