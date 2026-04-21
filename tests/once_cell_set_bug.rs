#![allow(warnings)]
#![allow(clippy::all)]
//! Test for once cell set bug.
use asupersync::sync::OnceCell;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_once_cell_set_while_initializing() {
    let cell = Arc::new(OnceCell::<u32>::new());

    // Thread 1: Start initializing, but take a while
    let cell_clone = Arc::clone(&cell);
    let handle = thread::spawn(move || {
        let res = cell_clone.get_or_init_blocking(|| {
            thread::sleep(Duration::from_millis(50));
            42
        });
        assert_eq!(*res, 42);
    });

    // Give Thread 1 time to enter INITIALIZING state
    thread::sleep(Duration::from_millis(10));

    // Thread 2: Try to set while initialization is in flight.
    // The API is fail-closed and must return Err immediately rather than
    // blocking the thread.
    let set_result = cell.set(99);
    assert_eq!(
        set_result,
        Err(99),
        "set should fail immediately while another thread initializes"
    );

    handle.join().unwrap();

    // After the initializer finishes, the stored value is visible.
    let get_result = cell.get();
    assert_eq!(get_result, Some(&42));
}

#[test]
fn test_once_cell_set_while_initializing_cancelled() {
    let cell = Arc::new(OnceCell::<u32>::new());

    // Thread 1: Start initializing, but panic (simulate cancellation)
    let cell_clone = Arc::clone(&cell);
    let handle = thread::spawn(move || {
        let _ = std::panic::catch_unwind(|| {
            cell_clone.get_or_init_blocking(|| {
                thread::sleep(Duration::from_millis(50));
                panic!("cancelled");
            });
        });
    });

    thread::sleep(Duration::from_millis(10));

    // While initialization is still in flight, set() must fail immediately.
    let in_flight_set_result = cell.set(99);
    assert_eq!(
        in_flight_set_result,
        Err(99),
        "set should fail immediately while initialization is in progress"
    );

    handle.join().unwrap();

    // Once the panicking initializer unwinds, the cell returns to UNINIT and a
    // subsequent set() can safely succeed with no data loss.
    let set_result = cell.set(99);
    assert_eq!(set_result, Ok(()), "set should succeed after cancellation");
    assert_eq!(cell.get(), Some(&99), "cell should contain 99");
}
