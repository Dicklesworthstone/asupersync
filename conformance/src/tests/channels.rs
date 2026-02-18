use crate::{
    BroadcastReceiver, BroadcastSender, ConformanceTest, MpscReceiver, MpscSender, OneshotSender,
    RuntimeInterface, TestCategory, TestResult, WatchReceiver, WatchSender, conformance_test,
};

pub fn collect_tests<RT: RuntimeInterface>() -> Vec<ConformanceTest<RT>> {
    vec![
        conformance_test! {
            id: "chan-001",
            name: "MPSC FIFO Ordering",
            description: "Verify that MPSC channel preserves FIFO order for a single producer",
            category: TestCategory::Channels,
            tags: ["mpsc", "ordering"],
            expected: "Messages received in the order sent",
            test: |rt| {
                rt.block_on(async {
                    let (tx, mut rx) = rt.mpsc_channel::<i32>(10);

                    for i in 0..10 {
                        tx.send(i).await.expect("send failed");
                    }
                    drop(tx);

                    for i in 0..10 {
                        match rx.recv().await {
                            Some(val) => {
                                if val != i {
                                    return TestResult::failed(format!("Expected {}, got {}", i, val));
                                }
                            }
                            None => return TestResult::failed("Channel closed prematurely"),
                        }
                    }

                    if rx.recv().await.is_some() {
                        return TestResult::failed("Channel should be empty and closed");
                    }

                    TestResult::passed()
                })
            }
        },
        conformance_test! {
            id: "chan-002",
            name: "MPSC Multi-Producer",
            description: "Verify multiple producers can send to the same channel",
            category: TestCategory::Channels,
            tags: ["mpsc", "concurrency"],
            expected: "All messages received",
            test: |rt| {
                rt.block_on(async {
                    let (tx, mut rx) = rt.mpsc_channel::<usize>(100);
                    let mut handles = Vec::new();

                    for i in 0..5 {
                        let tx = tx.clone();

                        handles.push(rt.spawn(async move {
                            for j in 0..10 {
                                tx.send(i * 10 + j).await.expect("send failed");
                            }
                        }));
                    }
                    drop(tx);

                    for h in handles {
                        h.await;
                    }

                    let mut received = Vec::new();
                    while let Some(val) = rx.recv().await {
                        received.push(val);
                    }

                    if received.len() != 50 {
                        return TestResult::failed(format!("Expected 50 messages, got {}", received.len()));
                    }

                    received.sort_unstable();
                    let expected: Vec<_> = (0..50).collect();

                    if received != expected {
                         return TestResult::failed("Received messages mismatch");
                    }

                    TestResult::passed()
                })
            }
        },
        conformance_test! {
            id: "chan-004",
            name: "Oneshot Success",
            description: "Verify oneshot channel sends and receives a value",
            category: TestCategory::Channels,
            tags: ["oneshot"],
            expected: "Value received",
            test: |rt| {
                rt.block_on(async {
                    let (tx, rx) = rt.oneshot_channel::<i32>();
                    tx.send(42).expect("send failed");
                    match rx.await {
                        Ok(42) => TestResult::passed(),
                        Ok(v) => TestResult::failed(format!("Expected 42, got {}", v)),
                        Err(_) => TestResult::failed("Receive failed"),
                    }
                })
            }
        },
        conformance_test! {
            id: "chan-005",
            name: "Oneshot Sender Dropped",
            description: "Verify error when oneshot sender is dropped",
            category: TestCategory::Channels,
            tags: ["oneshot", "error"],
            expected: "RecvError",
            test: |rt| {
                rt.block_on(async {
                    let (tx, rx) = rt.oneshot_channel::<i32>();
                    drop(tx);
                    match rx.await {
                        Ok(_) => TestResult::failed("Should not receive value"),
                        Err(_) => TestResult::passed(),
                    }
                })
            }
        },
        conformance_test! {
            id: "chan-006",
            name: "Broadcast Basic",
            description: "Verify broadcast sends to all subscribers",
            category: TestCategory::Channels,
            tags: ["broadcast"],
            expected: "All subscribers receive messages",
            test: |rt| {
                rt.block_on(async {
                    let (tx, mut rx1) = rt.broadcast_channel::<i32>(10);
                    let mut rx2 = tx.subscribe();

                    tx.send(10).expect("send failed");
                    tx.send(20).expect("send failed");

                    let v1_1 = rx1.recv().await.expect("rx1 recv 1");
                    let v1_2 = rx1.recv().await.expect("rx1 recv 2");

                    let v2_1 = rx2.recv().await.expect("rx2 recv 1");
                    let v2_2 = rx2.recv().await.expect("rx2 recv 2");

                    if v1_1 != 10 || v1_2 != 20 {
                        return TestResult::failed("rx1 received wrong values");
                    }
                    if v2_1 != 10 || v2_2 != 20 {
                        return TestResult::failed("rx2 received wrong values");
                    }

                    TestResult::passed()
                })
            }
        },
        conformance_test! {
            id: "chan-007",
            name: "Watch Latest Value",
            description: "Verify watch channel holds latest value",
            category: TestCategory::Channels,
            tags: ["watch"],
            expected: "Receiver sees initial and updates",
            test: |rt| {
                rt.block_on(async {
                    let (tx, mut rx) = rt.watch_channel::<i32>(0);

                    if rx.borrow_and_clone() != 0 {
                        return TestResult::failed("Initial value mismatch");
                    }

                    tx.send(1).expect("send failed");
                    rx.changed().await.expect("changed failed");
                    if rx.borrow_and_clone() != 1 {
                        return TestResult::failed("Update 1 mismatch");
                    }

                    tx.send(2).expect("send failed");
                    rx.changed().await.expect("changed failed");
                    if rx.borrow_and_clone() != 2 {
                        return TestResult::failed("Update 2 mismatch");
                    }

                    TestResult::passed()
                })
            }
        },
    ]
}
