//! Channel Conformance Tests using asupersync implementation.

use asupersync::channel::{broadcast, mpsc, oneshot, watch};
use asupersync::cx::Cx;
use conformance::{
    AsyncFile, BroadcastReceiver, BroadcastRecvError, BroadcastSender, MpscReceiver, MpscSender,
    OneshotSender, RuntimeInterface, TcpListener, TcpStream, TimeoutError, UdpSocket,
    WatchReceiver, WatchRecvError, WatchSender,
};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

struct AsupersyncRuntime;

impl AsupersyncRuntime {
    fn new() -> Self {
        Self
    }
}

// Helper wrappers to adapt asupersync types to conformance traits

struct MpscSenderWrapper<T>(mpsc::Sender<T>);

impl<T> Clone for MpscSenderWrapper<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Send + 'static> MpscSender<T> for MpscSenderWrapper<T> {
    fn send(&self, value: T) -> Pin<Box<dyn Future<Output = Result<(), T>> + Send + '_>> {
        let sender = self.0.clone();
        Box::pin(async move {
            let cx = Cx::for_testing();
            // Reserve first
            match sender.reserve(&cx) {
                Ok(permit) => {
                    permit.send(value);
                    Ok(())
                }
                Err(_) => Err(value),
            }
        })
    }
}

struct MpscReceiverWrapper<T>(mpsc::Receiver<T>);

impl<T: Send + 'static> MpscReceiver<T> for MpscReceiverWrapper<T> {
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = Option<T>> + Send + '_>> {
        let receiver = &self.0;
        Box::pin(async move {
            let cx = Cx::for_testing();
            receiver.recv(&cx).ok()
        })
    }
}

struct OneshotSenderWrapper<T>(Option<oneshot::Sender<T>>);

impl<T: Send + 'static> OneshotSender<T> for OneshotSenderWrapper<T> {
    fn send(mut self, value: T) -> Result<(), T> {
        if let Some(tx) = self.0.take() {
            let cx = Cx::for_testing();
            tx.send(&cx, value).map_err(|e| match e {
                asupersync::channel::oneshot::SendError::Disconnected(v) => v,
            })
        } else {
            Err(value)
        }
    }
}

struct BroadcastSenderWrapper<T>(broadcast::Sender<T>);

impl<T> Clone for BroadcastSenderWrapper<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Send + Clone + 'static> BroadcastSender<T> for BroadcastSenderWrapper<T> {
    fn send(&self, value: T) -> Result<usize, T> {
        let cx = Cx::for_testing();
        self.0.send(&cx, value).map_err(|e| match e {
            broadcast::SendError::Closed(v) => v,
        })
    }

    fn subscribe(&self) -> Box<dyn BroadcastReceiver<T>> {
        Box::new(BroadcastReceiverWrapper(self.0.subscribe()))
    }
}

struct BroadcastReceiverWrapper<T>(broadcast::Receiver<T>);

impl<T: Send + Clone + 'static> BroadcastReceiver<T> for BroadcastReceiverWrapper<T> {
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = Result<T, BroadcastRecvError>> + Send + '_>> {
        let receiver = &mut self.0;
        Box::pin(async move {
            let cx = Cx::for_testing();
            match receiver.recv(&cx) {
                Ok(v) => Ok(v),
                Err(broadcast::RecvError::Lagged(n)) => Err(BroadcastRecvError::Lagged(n)),
                Err(broadcast::RecvError::Closed) => Err(BroadcastRecvError::Closed),
            }
        })
    }
}

// WatchSender does NOT need Clone
struct WatchSenderWrapper<T>(watch::Sender<T>);

impl<T: Send + Sync + 'static> WatchSender<T> for WatchSenderWrapper<T> {
    fn send(&self, value: T) -> Result<(), T> {
        self.0.send(value).map_err(|e| match e {
            watch::SendError::Closed(v) => v,
        })
    }
}

struct WatchReceiverWrapper<T>(watch::Receiver<T>);

impl<T> Clone for WatchReceiverWrapper<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

// Require T: Clone for WatchReceiver implementation
impl<T: Send + Sync + Clone + 'static> WatchReceiver<T> for WatchReceiverWrapper<T> {
    fn changed(&mut self) -> Pin<Box<dyn Future<Output = Result<(), WatchRecvError>> + Send + '_>> {
        let receiver = &mut self.0;
        Box::pin(async move {
            let cx = Cx::for_testing();
            receiver.changed(&cx).map_err(|_| WatchRecvError)
        })
    }

    fn borrow_and_clone(&self) -> T {
        self.0.borrow_and_clone()
    }
}

// Dummy File implementation for now
struct DummyFile;
impl AsyncFile for DummyFile {
    fn write_all<'a>(
        &'a mut self,
        _buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
    fn read_exact<'a>(
        &'a mut self,
        _buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
    fn read_to_end<'a>(
        &'a mut self,
        _buf: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async { Ok(0) })
    }
    fn seek<'a>(
        &'a mut self,
        _pos: io::SeekFrom,
    ) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + 'a>> {
        Box::pin(async { Ok(0) })
    }
    fn sync_all(&self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
    fn shutdown(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

// Dummy Net implementation
struct DummyTcpListener;
impl TcpListener for DummyTcpListener {
    type Stream = DummyTcpStream;
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    fn accept(
        &self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send + '_>> {
        Box::pin(async {
            loop {
                std::future::pending::<()>().await;
            }
        })
    }
}

struct DummyTcpStream;
impl TcpStream for DummyTcpStream {
    fn read<'a>(
        &'a mut self,
        _buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async { Ok(0) })
    }
    fn read_exact<'a>(
        &'a mut self,
        _buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
    fn write_all<'a>(
        &'a mut self,
        _buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
    fn shutdown(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

struct DummyUdpSocket;
impl UdpSocket for DummyUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    fn send_to<'a>(
        &'a self,
        _buf: &'a [u8],
        _addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async { Ok(0) })
    }
    fn recv_from<'a>(
        &'a self,
        _buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(async {
            loop {
                std::future::pending::<()>().await;
            }
        })
    }
}

impl RuntimeInterface for AsupersyncRuntime {
    type JoinHandle<T: Send + 'static> = Pin<Box<dyn Future<Output = T> + Send>>;
    type MpscSender<T: Send + 'static> = MpscSenderWrapper<T>;
    type MpscReceiver<T: Send + 'static> = MpscReceiverWrapper<T>;
    type OneshotSender<T: Send + 'static> = OneshotSenderWrapper<T>;
    type OneshotReceiver<T: Send + 'static> =
        Pin<Box<dyn Future<Output = Result<T, conformance::OneshotRecvError>> + Send>>;
    type BroadcastSender<T: Send + Clone + 'static> = BroadcastSenderWrapper<T>;
    type BroadcastReceiver<T: Send + Clone + 'static> = BroadcastReceiverWrapper<T>;
    type WatchSender<T: Send + Sync + 'static> = WatchSenderWrapper<T>;
    type WatchReceiver<T: Send + Sync + Clone + 'static> = WatchReceiverWrapper<T>;
    type File = DummyFile;
    type TcpListener = DummyTcpListener;
    type TcpStream = DummyTcpStream;
    type UdpSocket = DummyUdpSocket;

    fn spawn<F>(&self, future: F) -> Self::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let handle = std::thread::spawn(move || futures_lite::future::block_on(future));

        Box::pin(async move { handle.join().unwrap() })
    }

    fn block_on<F: Future>(&self, future: F) -> F::Output {
        futures_lite::future::block_on(future)
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            std::thread::sleep(duration);
        })
    }

    fn timeout<'a, F: Future + Send + 'a>(
        &'a self,
        duration: Duration,
        future: F,
    ) -> Pin<Box<dyn Future<Output = Result<F::Output, TimeoutError>> + Send + 'a>> {
        Box::pin(async move {
            let timeout = async {
                std::thread::sleep(duration);
                Err(TimeoutError)
            };

            let ok_future = async { Ok(future.await) };

            futures_lite::future::or(timeout, ok_future).await
        })
    }

    fn mpsc_channel<T: Send + 'static>(
        &self,
        capacity: usize,
    ) -> (Self::MpscSender<T>, Self::MpscReceiver<T>) {
        let (tx, rx) = mpsc::channel(capacity);
        (MpscSenderWrapper(tx), MpscReceiverWrapper(rx))
    }

    fn oneshot_channel<T: Send + 'static>(
        &self,
    ) -> (Self::OneshotSender<T>, Self::OneshotReceiver<T>) {
        let (tx, rx) = oneshot::channel();
        let rx_wrapped = Box::pin(async move {
            let cx = Cx::for_testing();
            rx.recv(&cx)
                .await
                .map_err(|_| conformance::OneshotRecvError)
        });
        (OneshotSenderWrapper(Some(tx)), rx_wrapped)
    }

    fn broadcast_channel<T: Send + Clone + 'static>(
        &self,
        capacity: usize,
    ) -> (Self::BroadcastSender<T>, Self::BroadcastReceiver<T>) {
        let (tx, rx) = broadcast::channel(capacity);
        (BroadcastSenderWrapper(tx), BroadcastReceiverWrapper(rx))
    }

    fn watch_channel<T: Send + Sync + Clone + 'static>(
        &self,
        initial: T,
    ) -> (Self::WatchSender<T>, Self::WatchReceiver<T>) {
        let (tx, rx) = watch::channel(initial);
        (WatchSenderWrapper(tx), WatchReceiverWrapper(rx))
    }

    // Dummy implementations for File/Net
    fn file_create<'a>(
        &'a self,
        _path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::File>> + Send + 'a>> {
        Box::pin(async { Ok(DummyFile) })
    }
    fn file_open<'a>(
        &'a self,
        _path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::File>> + Send + 'a>> {
        Box::pin(async { Ok(DummyFile) })
    }
    fn tcp_listen<'a>(
        &'a self,
        _addr: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::TcpListener>> + Send + 'a>> {
        Box::pin(async { Ok(DummyTcpListener) })
    }
    fn tcp_connect<'a>(
        &'a self,
        _addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::TcpStream>> + Send + 'a>> {
        Box::pin(async { Ok(DummyTcpStream) })
    }
    fn udp_bind<'a>(
        &'a self,
        _addr: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::UdpSocket>> + Send + 'a>> {
        Box::pin(async { Ok(DummyUdpSocket) })
    }
}

#[test]
fn run_channel_conformance_tests() {
    let runtime = AsupersyncRuntime::new();
    let tests = conformance::tests::channels::collect_tests::<AsupersyncRuntime>();

    for test in tests {
        println!("Running test: {}", test.meta.name);
        let result = test.run(&runtime);
        assert!(
            result.passed,
            "Test {} failed: {}",
            test.meta.name,
            result.message.unwrap_or_default()
        );
    }
}
