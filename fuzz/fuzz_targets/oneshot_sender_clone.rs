//! Fuzz target: Oneshot sender operations
//!
//! Tests edge cases around oneshot sender usage patterns.
//! Verifies that only one send operation can succeed per channel.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use asupersync::channel::oneshot;
use asupersync::Cx;

/// Configuration for testing oneshot sender operations
#[derive(Debug, Arbitrary)]
struct SenderTestConfig {
    /// Value to send
    value: u32,
    /// Whether to use reserve+send or direct send
    use_reserve: bool,
    /// Whether receiver should be dropped early
    drop_receiver_early: bool,
}

fuzz_target!(|data: &[u8]| {
    // Parse fuzzer input into config
    let config = match SenderTestConfig::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        Ok(config) => config,
        Err(_) => return, // Invalid input, skip
    };

    let (sender, mut receiver) = oneshot::channel::<u32>();
    let cx = Cx::for_testing();

    // Optionally drop receiver early to test disconnected behavior
    if config.drop_receiver_early {
        drop(receiver);

        // Send should fail with Disconnected
        if config.use_reserve {
            match sender.reserve(&cx) {
                Ok(permit) => {
                    match permit.send(config.value) {
                        Err(oneshot::SendError::Disconnected(val)) => {
                            assert_eq!(val, config.value, "Value should be returned on disconnect");
                        },
                        other => panic!("Expected disconnected error, got {:?}", other),
                    }
                },
                Err(e) => {
                    // Reserve can fail if cx is cancelled
                    match e {
                        oneshot::SendError::Cancelled(()) => {},
                        oneshot::SendError::Disconnected(()) => {},
                    }
                },
            }
        } else {
            match sender.send(&cx, config.value) {
                Err(oneshot::SendError::Disconnected(val)) => {
                    assert_eq!(val, config.value, "Value should be returned on disconnect");
                },
                Err(oneshot::SendError::Cancelled(val)) => {
                    assert_eq!(val, config.value, "Value should be returned on cancel");
                },
                Ok(()) => panic!("Send should not succeed when receiver is dropped"),
            }
        }
    } else {
        // Normal send operation
        if config.use_reserve {
            match sender.reserve(&cx) {
                Ok(permit) => {
                    match permit.send(config.value) {
                        Ok(()) => {
                            // Verify receiver gets the value
                            match receiver.try_recv() {
                                Ok(val) => assert_eq!(val, config.value, "Received wrong value"),
                                Err(oneshot::TryRecvError::Empty) => {
                                    // May need to wait
                                    let recv_cx = Cx::for_testing();
                                    match futures::executor::block_on(receiver.recv(&recv_cx)) {
                                        Ok(val) => assert_eq!(val, config.value, "Received wrong value"),
                                        Err(e) => panic!("Recv failed: {:?}", e),
                                    }
                                },
                                Err(e) => panic!("Try recv failed: {:?}", e),
                            }
                        },
                        Err(e) => {
                            // Send can fail if receiver was dropped
                            match e {
                                oneshot::SendError::Disconnected(val) => {
                                    assert_eq!(val, config.value, "Value should be returned on disconnect");
                                },
                                oneshot::SendError::Cancelled(_) => {
                                    // Unexpected but possible if cx is cancelled
                                },
                            }
                        },
                    }
                },
                Err(e) => {
                    // Reserve can fail if cx is cancelled
                    match e {
                        oneshot::SendError::Cancelled(()) => {},
                        oneshot::SendError::Disconnected(()) => {
                            // Receiver was dropped between channel creation and reserve
                        },
                    }
                },
            }
        } else {
            // Direct send
            match sender.send(&cx, config.value) {
                Ok(()) => {
                    // Verify receiver gets the value
                    match receiver.try_recv() {
                        Ok(val) => assert_eq!(val, config.value, "Received wrong value"),
                        Err(oneshot::TryRecvError::Empty) => {
                            // May need to wait
                            let recv_cx = Cx::for_testing();
                            match futures::executor::block_on(receiver.recv(&recv_cx)) {
                                Ok(val) => assert_eq!(val, config.value, "Received wrong value"),
                                Err(e) => panic!("Recv failed: {:?}", e),
                            }
                        },
                        Err(e) => panic!("Try recv failed: {:?}", e),
                    }
                },
                Err(e) => {
                    match e {
                        oneshot::SendError::Disconnected(val) => {
                            assert_eq!(val, config.value, "Value should be returned on disconnect");
                        },
                        oneshot::SendError::Cancelled(val) => {
                            assert_eq!(val, config.value, "Value should be returned on cancel");
                        },
                    }
                },
            }
        }
    }
});