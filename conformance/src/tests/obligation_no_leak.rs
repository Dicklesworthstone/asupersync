//! Obligation No-Leak Conformance Test Suite
//!
//! These tests focus on the observable no-leak invariant that the current
//! generic `RuntimeInterface` can express with bounded MPSC channels:
//! cancelled blocked senders must not retain phantom capacity, produce phantom
//! deliveries, or leave follow-on operations stuck behind leaked permits.

use crate::{
    ConformanceTest, MpscReceiver, MpscSender, RuntimeInterface, TestCategory, TestMeta,
    TestResult, checkpoint,
};
use std::time::Duration;

/// Get all no-leak obligation conformance tests.
pub fn all_tests<RT: RuntimeInterface>() -> Vec<ConformanceTest<RT>> {
    vec![
        obnl_001_cancelled_blocked_send_reclaims_capacity::<RT>(),
        obnl_002_repeated_cancelled_sends_do_not_accumulate_leaks::<RT>(),
        obnl_003_closed_receiver_rejects_send_without_hanging::<RT>(),
    ]
}

/// OBNL-001: Cancelling a blocked send reclaims capacity.
///
/// Fill a bounded channel, time out a second sender while it is blocked on
/// capacity, then verify a later send can reuse the reclaimed slot and that no
/// phantom value from the cancelled sender is delivered.
pub fn obnl_001_cancelled_blocked_send_reclaims_capacity<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "obnl-001".to_string(),
            name: "Cancelled blocked send reclaims capacity".to_string(),
            description:
                "A timed-out blocked sender does not permanently consume bounded-channel capacity"
                    .to_string(),
            category: TestCategory::Channels,
            tags: vec![
                "obligation".to_string(),
                "no-leak".to_string(),
                "cancel".to_string(),
                "mpsc".to_string(),
                "bounded".to_string(),
            ],
            expected:
                "Follow-on send succeeds after drain, and the cancelled value is never delivered"
                    .to_string(),
        },
        |rt| {
            rt.block_on(async {
                let (tx, mut rx) = rt.mpsc_channel::<i32>(1);

                if let Err(value) = tx.send(1).await {
                    return TestResult::failed(format!(
                        "Initial fill send should succeed, got Err({value})"
                    ));
                }

                let blocked_tx = tx.clone();
                let cancelled_send = rt
                    .timeout(Duration::from_millis(50), async move {
                        blocked_tx.send(2).await
                    })
                    .await;

                checkpoint(
                    "cancelled_blocked_send",
                    serde_json::json!({
                        "timed_out": cancelled_send.is_err(),
                    }),
                );

                if let Ok(result) = cancelled_send {
                    return TestResult::failed(format!(
                        "Blocked send should time out while capacity is full, got {:?}",
                        result
                    ));
                }

                let first = match rt
                    .timeout(Duration::from_millis(200), async { rx.recv().await })
                    .await
                {
                    Ok(Some(value)) => value,
                    Ok(None) => {
                        return TestResult::failed(
                            "Receiver observed channel closure before draining seeded value",
                        );
                    }
                    Err(_) => {
                        return TestResult::failed(
                            "Receiver failed to drain seeded value after cancelled sender",
                        );
                    }
                };

                if first != 1 {
                    return TestResult::failed(format!(
                        "Expected seeded value 1 after cancellation, got {first}",
                    ));
                }

                let follow_on_send = rt
                    .timeout(Duration::from_millis(200), async { tx.send(3).await })
                    .await;

                checkpoint(
                    "follow_on_send_after_cancel",
                    serde_json::json!({
                        "timed_out": follow_on_send.is_err(),
                        "result": format!("{:?}", follow_on_send),
                    }),
                );

                match follow_on_send {
                    Ok(Ok(())) => {}
                    Ok(Err(value)) => {
                        return TestResult::failed(format!(
                            "Reclaimed-capacity send unexpectedly failed with Err({value})",
                        ));
                    }
                    Err(_) => {
                        return TestResult::failed(
                            "Follow-on send timed out; cancelled sender may have leaked capacity",
                        );
                    }
                }

                drop(tx);

                let second = match rt
                    .timeout(Duration::from_millis(200), async { rx.recv().await })
                    .await
                {
                    Ok(Some(value)) => value,
                    Ok(None) => {
                        return TestResult::failed(
                            "Expected follow-on value after reclaimed send, got channel close",
                        );
                    }
                    Err(_) => {
                        return TestResult::failed(
                            "Timed out waiting for follow-on value after reclaimed send",
                        );
                    }
                };

                if second != 3 {
                    return TestResult::failed(format!(
                        "Expected follow-on value 3, got {second}",
                    ));
                }

                match rt
                    .timeout(Duration::from_millis(200), async { rx.recv().await })
                    .await
                {
                    Ok(None) => TestResult::passed(),
                    Ok(Some(value)) => TestResult::failed(format!(
                        "Cancelled sender produced phantom delivery {value}",
                    )),
                    Err(_) => TestResult::failed(
                        "Channel did not close after draining expected values; leaked waiter is possible",
                    ),
                }
            })
        },
    )
}

/// OBNL-002: Repeated cancelled sends do not accumulate phantom reservations.
///
/// Time out multiple blocked send attempts against the same full bounded
/// channel, then verify a single reclaimed slot still behaves like a single
/// slot and does not surface any cancelled values later.
pub fn obnl_002_repeated_cancelled_sends_do_not_accumulate_leaks<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "obnl-002".to_string(),
            name: "Repeated cancelled sends do not accumulate leaks".to_string(),
            description:
                "Multiple timed-out blocked senders do not leave phantom capacity or phantom deliveries"
                    .to_string(),
            category: TestCategory::Channels,
            tags: vec![
                "obligation".to_string(),
                "no-leak".to_string(),
                "cancel".to_string(),
                "mpsc".to_string(),
                "repeated".to_string(),
            ],
            expected:
                "Later delivery receives only the seeded and explicit follow-on values".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let (tx, mut rx) = rt.mpsc_channel::<i32>(1);

                if let Err(value) = tx.send(10).await {
                    return TestResult::failed(format!(
                        "Initial fill send should succeed, got Err({value})"
                    ));
                }

                for cancelled_value in [20, 30] {
                    let blocked_tx = tx.clone();
                    let cancelled = rt
                        .timeout(Duration::from_millis(50), async move {
                            blocked_tx.send(cancelled_value).await
                        })
                        .await;

                    checkpoint(
                        "repeated_cancelled_send",
                        serde_json::json!({
                            "value": cancelled_value,
                            "timed_out": cancelled.is_err(),
                        }),
                    );

                    if let Ok(result) = cancelled {
                        return TestResult::failed(format!(
                            "Cancelled sender for value {cancelled_value} unexpectedly completed: {:?}",
                            result
                        ));
                    }
                }

                let first = match rt
                    .timeout(Duration::from_millis(200), async { rx.recv().await })
                    .await
                {
                    Ok(Some(value)) => value,
                    Ok(None) => {
                        return TestResult::failed(
                            "Channel closed before draining seeded value after repeated cancellations",
                        );
                    }
                    Err(_) => {
                        return TestResult::failed(
                            "Timed out draining seeded value after repeated cancellations",
                        );
                    }
                };

                if first != 10 {
                    return TestResult::failed(format!(
                        "Expected seeded value 10 after repeated cancellations, got {first}",
                    ));
                }

                match rt
                    .timeout(Duration::from_millis(200), async { tx.send(40).await })
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(value)) => {
                        return TestResult::failed(format!(
                            "Follow-on send after repeated cancellations failed with Err({value})",
                        ));
                    }
                    Err(_) => {
                        return TestResult::failed(
                            "Follow-on send timed out after repeated cancellations; capacity leak is likely",
                        );
                    }
                }

                drop(tx);

                let second = match rt
                    .timeout(Duration::from_millis(200), async { rx.recv().await })
                    .await
                {
                    Ok(Some(value)) => value,
                    Ok(None) => {
                        return TestResult::failed(
                            "Expected explicit follow-on value after repeated cancellations, got close",
                        );
                    }
                    Err(_) => {
                        return TestResult::failed(
                            "Timed out waiting for follow-on value after repeated cancellations",
                        );
                    }
                };

                if second != 40 {
                    return TestResult::failed(format!(
                        "Expected follow-on value 40, got {second}",
                    ));
                }

                match rt
                    .timeout(Duration::from_millis(200), async { rx.recv().await })
                    .await
                {
                    Ok(None) => TestResult::passed(),
                    Ok(Some(value)) => TestResult::failed(format!(
                        "Repeated cancelled senders produced phantom delivery {value}",
                    )),
                    Err(_) => TestResult::failed(
                        "Channel did not close after draining repeated-cancel scenario",
                    ),
                }
            })
        },
    )
}

/// OBNL-003: Closed receivers reject sends promptly.
///
/// A sender targeting a closed receiver should fail promptly rather than hang,
/// which provides an observable clean-abort path for the obligation surface.
pub fn obnl_003_closed_receiver_rejects_send_without_hanging<RT: RuntimeInterface>()
-> ConformanceTest<RT> {
    ConformanceTest::new(
        TestMeta {
            id: "obnl-003".to_string(),
            name: "Closed receiver rejects send without hanging".to_string(),
            description:
                "A clean receiver-side abort fails the send promptly and does not block indefinitely"
                    .to_string(),
            category: TestCategory::Channels,
            tags: vec![
                "obligation".to_string(),
                "abort".to_string(),
                "close".to_string(),
                "mpsc".to_string(),
            ],
            expected: "Send returns Err(value) before timeout after receiver close".to_string(),
        },
        |rt| {
            rt.block_on(async {
                let (tx, rx) = rt.mpsc_channel::<i32>(1);
                drop(rx);

                let send_result = rt
                    .timeout(Duration::from_millis(200), async move { tx.send(99).await })
                    .await;

                checkpoint(
                    "closed_receiver_send",
                    serde_json::json!({
                        "timed_out": send_result.is_err(),
                        "result": format!("{:?}", send_result),
                    }),
                );

                match send_result {
                    Ok(Err(99)) => TestResult::passed(),
                    Ok(Err(other)) => TestResult::failed(format!(
                        "Expected Err(99) after receiver close, got Err({other})",
                    )),
                    Ok(Ok(())) => TestResult::failed(
                        "Send unexpectedly succeeded after receiver was dropped",
                    ),
                    Err(_) => TestResult::failed(
                        "Send hung after receiver close; clean abort path is not observable",
                    ),
                }
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AsyncFile, BroadcastReceiver, BroadcastRecvError, BroadcastSender, OneshotRecvError,
        OneshotSender, TcpListener, TcpStream, TimeoutError, UdpSocket, WatchReceiver,
        WatchRecvError, WatchSender,
    };
    use std::future::Future;
    use std::io;
    use std::marker::PhantomData;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::pin::Pin;
    use std::time::Duration;

    struct CatalogRuntime;

    struct CatalogMpscSender<T>(PhantomData<fn() -> T>);
    struct CatalogMpscReceiver<T>(PhantomData<fn() -> T>);
    struct CatalogOneshotSender<T>(PhantomData<fn() -> T>);
    struct CatalogBroadcastSender<T>(PhantomData<fn() -> T>);
    struct CatalogBroadcastReceiver<T>(PhantomData<fn() -> T>);
    struct CatalogWatchSender<T>(PhantomData<fn() -> T>);
    struct CatalogWatchReceiver<T>(PhantomData<fn() -> T>);
    struct CatalogFile;
    struct CatalogTcpListener;
    struct CatalogTcpStream;
    struct CatalogUdpSocket;

    impl<T> Clone for CatalogMpscSender<T> {
        fn clone(&self) -> Self {
            Self(PhantomData)
        }
    }

    impl<T> Clone for CatalogBroadcastSender<T> {
        fn clone(&self) -> Self {
            Self(PhantomData)
        }
    }

    impl<T> Clone for CatalogWatchReceiver<T> {
        fn clone(&self) -> Self {
            Self(PhantomData)
        }
    }

    impl<T: Send> MpscSender<T> for CatalogMpscSender<T> {
        fn send(&self, _value: T) -> Pin<Box<dyn Future<Output = Result<(), T>> + Send + '_>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }
    }

    impl<T: Send> MpscReceiver<T> for CatalogMpscReceiver<T> {
        fn recv(&mut self) -> Pin<Box<dyn Future<Output = Option<T>> + Send + '_>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }
    }

    impl<T: Send> OneshotSender<T> for CatalogOneshotSender<T> {
        fn send(self, _value: T) -> Result<(), T> {
            panic!("catalog runtime should not execute test bodies")
        }
    }

    impl<T: Send + Clone + 'static> BroadcastSender<T> for CatalogBroadcastSender<T> {
        fn send(&self, _value: T) -> Result<usize, T> {
            panic!("catalog runtime should not execute test bodies")
        }

        fn subscribe(&self) -> Box<dyn BroadcastReceiver<T>> {
            Box::new(CatalogBroadcastReceiver(PhantomData))
        }
    }

    impl<T: Send + Clone + 'static> BroadcastReceiver<T> for CatalogBroadcastReceiver<T> {
        fn recv(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<T, BroadcastRecvError>> + Send + '_>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }
    }

    impl<T: Send + Sync> WatchSender<T> for CatalogWatchSender<T> {
        fn send(&self, _value: T) -> Result<(), T> {
            panic!("catalog runtime should not execute test bodies")
        }
    }

    impl<T: Send + Sync + Clone> WatchReceiver<T> for CatalogWatchReceiver<T> {
        fn changed(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = Result<(), WatchRecvError>> + Send + '_>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn borrow_and_clone(&self) -> T {
            panic!("catalog runtime should not execute test bodies")
        }
    }

    impl AsyncFile for CatalogFile {
        fn write_all<'a>(
            &'a mut self,
            _buf: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn read_exact<'a>(
            &'a mut self,
            _buf: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn read_to_end<'a>(
            &'a mut self,
            _buf: &'a mut Vec<u8>,
        ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn seek<'a>(
            &'a mut self,
            _pos: std::io::SeekFrom,
        ) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn sync_all(&self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn shutdown(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }
    }

    impl TcpListener for CatalogTcpListener {
        type Stream = CatalogTcpStream;

        fn local_addr(&self) -> io::Result<SocketAddr> {
            panic!("catalog runtime should not execute test bodies")
        }

        fn accept(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send + '_>>
        {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }
    }

    impl TcpStream for CatalogTcpStream {
        fn read<'a>(
            &'a mut self,
            _buf: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn read_exact<'a>(
            &'a mut self,
            _buf: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn write_all<'a>(
            &'a mut self,
            _buf: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn shutdown(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }
    }

    impl UdpSocket for CatalogUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            panic!("catalog runtime should not execute test bodies")
        }

        fn send_to<'a>(
            &'a self,
            _buf: &'a [u8],
            _addr: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn recv_from<'a>(
            &'a self,
            _buf: &'a mut [u8],
        ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }
    }

    impl RuntimeInterface for CatalogRuntime {
        type JoinHandle<T: Send + 'static> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
        type MpscSender<T: Send + 'static> = CatalogMpscSender<T>;
        type MpscReceiver<T: Send + 'static> = CatalogMpscReceiver<T>;
        type OneshotSender<T: Send + 'static> = CatalogOneshotSender<T>;
        type OneshotReceiver<T: Send + 'static> =
            Pin<Box<dyn Future<Output = Result<T, OneshotRecvError>> + Send + 'static>>;
        type BroadcastSender<T: Send + Clone + 'static> = CatalogBroadcastSender<T>;
        type BroadcastReceiver<T: Send + Clone + 'static> = CatalogBroadcastReceiver<T>;
        type WatchSender<T: Send + Sync + 'static> = CatalogWatchSender<T>;
        type WatchReceiver<T: Send + Sync + Clone + 'static> = CatalogWatchReceiver<T>;
        type File = CatalogFile;
        type TcpListener = CatalogTcpListener;
        type TcpStream = CatalogTcpStream;
        type UdpSocket = CatalogUdpSocket;

        fn spawn<F>(&self, _future: F) -> Self::JoinHandle<F::Output>
        where
            F: Future + Send + 'static,
            F::Output: Send + 'static,
        {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn block_on<F: Future>(&self, _future: F) -> F::Output {
            panic!("catalog runtime should not execute test bodies")
        }

        fn sleep(&self, _duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn timeout<'a, F: Future + Send + 'a>(
            &'a self,
            _duration: Duration,
            _future: F,
        ) -> Pin<Box<dyn Future<Output = Result<F::Output, TimeoutError>> + Send + 'a>>
        where
            F::Output: Send,
        {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn mpsc_channel<T: Send + 'static>(
            &self,
            _capacity: usize,
        ) -> (Self::MpscSender<T>, Self::MpscReceiver<T>) {
            (
                CatalogMpscSender(PhantomData),
                CatalogMpscReceiver(PhantomData),
            )
        }

        fn oneshot_channel<T: Send + 'static>(
            &self,
        ) -> (Self::OneshotSender<T>, Self::OneshotReceiver<T>) {
            (
                CatalogOneshotSender(PhantomData),
                Box::pin(async { panic!("catalog runtime should not execute test bodies") }),
            )
        }

        fn broadcast_channel<T: Send + Clone + 'static>(
            &self,
            _capacity: usize,
        ) -> (Self::BroadcastSender<T>, Self::BroadcastReceiver<T>) {
            (
                CatalogBroadcastSender(PhantomData),
                CatalogBroadcastReceiver(PhantomData),
            )
        }

        fn watch_channel<T: Send + Sync + Clone + 'static>(
            &self,
            _initial: T,
        ) -> (Self::WatchSender<T>, Self::WatchReceiver<T>) {
            (
                CatalogWatchSender(PhantomData),
                CatalogWatchReceiver(PhantomData),
            )
        }

        fn file_create<'a>(
            &'a self,
            _path: &'a Path,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::File>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn file_open<'a>(
            &'a self,
            _path: &'a Path,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::File>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn tcp_listen<'a>(
            &'a self,
            _addr: &'a str,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::TcpListener>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn tcp_connect<'a>(
            &'a self,
            _addr: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::TcpStream>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }

        fn udp_bind<'a>(
            &'a self,
            _addr: &'a str,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::UdpSocket>> + Send + 'a>> {
            Box::pin(async { panic!("catalog runtime should not execute test bodies") })
        }
    }

    #[test]
    fn suite_registers_expected_ids_locally_and_globally() {
        let local_ids: Vec<_> = all_tests::<CatalogRuntime>()
            .into_iter()
            .map(|test| test.meta.id)
            .collect();
        assert_eq!(local_ids, vec!["obnl-001", "obnl-002", "obnl-003"]);

        let global_ids: Vec<_> = crate::tests::all_tests::<CatalogRuntime>()
            .into_iter()
            .map(|test| test.meta.id)
            .collect();

        for id in &local_ids {
            assert!(
                global_ids.iter().any(|candidate| candidate == id),
                "crate-wide conformance catalog is missing {id}",
            );
        }
    }
}
