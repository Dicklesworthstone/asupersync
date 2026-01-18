use asupersync::channel::mpsc;
use asupersync::cx::Cx;
use asupersync::error::SendError;

#[test]
fn repro_mpsc_cancel_returns_disconnected() {
    let (tx, _rx) = mpsc::channel::<i32>(1);
    let cx = Cx::for_testing();
    
    // Fill channel
    tx.send(&cx, 1).unwrap();
    
    // Request cancellation on the context
    cx.set_cancel_requested(true);
    
    // Try to reserve (which would block since channel is full)
    // It should observe cancellation immediately before blocking
    let result = tx.reserve(&cx);
    
    match result {
        Err(SendError::Cancelled(_)) => {
            // Success: cancellation is now correctly reported
        }
        Err(SendError::Disconnected(_)) => {
            panic!("Got Disconnected, expected Cancelled - bug persists");
        }
        Err(e) => {
            panic!("Unexpected error type: {:?}", e);
        }
        Ok(_) => panic!("Should have failed due to cancellation"),
    }
}
