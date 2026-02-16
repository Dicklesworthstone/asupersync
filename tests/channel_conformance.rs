//! Conformance Tests using asupersync implementation.

#[macro_use]
mod common;

use asupersync::channel::{broadcast, mpsc, oneshot, watch};
use asupersync::cx::Cx;
use asupersync::fs;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use asupersync::net;
use asupersync::runtime::RuntimeBuilder;
use common::*;
use conformance::{
    AsyncFile, BroadcastReceiver, BroadcastRecvError, BroadcastSender, MpscReceiver, MpscSender,
    OneshotSender, RunConfig, RuntimeInterface, TcpListener, TcpStream, TimeoutError, UdpSocket,
    WatchReceiver, WatchRecvError, WatchSender, render_console_summary, run_conformance_suite,
};
use futures_lite::future;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

struct AsupersyncRuntime {
    runtime: asupersync::runtime::Runtime,
    handle: asupersync::runtime::RuntimeHandle,
}

impl AsupersyncRuntime {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new()
            .worker_threads(2)
            .build()
            .expect("failed to build runtime");
        let handle = runtime.handle();
        Self { runtime, handle }
    }
}

fn sleep_future(duration: Duration) -> impl Future<Output = ()> + Send {
    #[derive(Debug)]
    struct SleepState {
        spawned: bool,
        done: bool,
        waker: Option<Waker>,
        join: Option<std::thread::JoinHandle<()>>,
    }

    let state = Arc::new(Mutex::new(SleepState {
        spawned: false,
        done: false,
        waker: None,
        join: None,
    }));

    let state_clone = Arc::clone(&state);
    future::poll_fn(move |cx: &mut Context<'_>| {
        let mut join = None;
        let mut ready = false;
        let should_spawn = {
            let mut guard = state_clone.lock().expect("sleep state lock poisoned");
            if guard.done {
                join = guard.join.take();
                ready = true;
                false
            } else {
                guard.waker = Some(cx.waker().clone());
                if guard.spawned {
                    false
                } else {
                    guard.spawned = true;
                    true
                }
            }
        };

        if let Some(join) = join {
            // The sleeper thread sets done=true just before returning. Join should be fast, and
            // prevents accumulating detached threads across the conformance suite.
            let _ = join.join();
        }
        if ready {
            return Poll::Ready(());
        }

        if should_spawn {
            let thread_state = Arc::clone(&state_clone);
            let handle = std::thread::spawn(move || {
                std::thread::sleep(duration);

                let waker = {
                    let mut guard = thread_state.lock().expect("sleep state lock poisoned");
                    guard.done = true;
                    guard.waker.take()
                };
                if let Some(waker) = waker {
                    waker.wake();
                }
            });
            let mut guard = state_clone.lock().expect("sleep state lock poisoned");
            guard.join = Some(handle);
        }

        Poll::Pending
    })
}

fn current_cx() -> Cx {
    Cx::current().unwrap_or_else(Cx::for_testing)
}

async fn read_some<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut read_buf = ReadBuf::new(buf);
    future::poll_fn(|cx| Pin::new(&mut *reader).poll_read(cx, &mut read_buf)).await?;
    Ok(read_buf.filled().len())
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
            let cx = current_cx();
            // Use the async send method directly
            sender.send(&cx, value).await.map_err(|e| match e {
                mpsc::SendError::Disconnected(v)
                | mpsc::SendError::Cancelled(v)
                | mpsc::SendError::Full(v) => v,
            })
        })
    }
}

struct MpscReceiverWrapper<T>(mpsc::Receiver<T>);

impl<T: Send + 'static> MpscReceiver<T> for MpscReceiverWrapper<T> {
    fn recv(&mut self) -> Pin<Box<dyn Future<Output = Option<T>> + Send + '_>> {
        let receiver = &self.0;
        Box::pin(async move {
            let cx = current_cx();
            receiver.recv(&cx).await.ok()
        })
    }
}

struct OneshotSenderWrapper<T> {
    sender: Option<oneshot::Sender<T>>,
    closed: Arc<AtomicBool>,
}

impl<T: Send + 'static> OneshotSender<T> for OneshotSenderWrapper<T> {
    fn send(mut self, value: T) -> Result<(), T> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(value);
        }
        if let Some(tx) = self.sender.take() {
            let cx = current_cx();
            tx.send(&cx, value).map_err(|e| match e {
                asupersync::channel::oneshot::SendError::Disconnected(v) => v,
            })
        } else {
            Err(value)
        }
    }
}

struct OneshotReceiverWrapper<T> {
    receiver: oneshot::Receiver<T>,
    closed: Arc<AtomicBool>,
}

impl<T> Drop for OneshotReceiverWrapper<T> {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

impl<T: Send + 'static> Future for OneshotReceiverWrapper<T> {
    type Output = Result<T, conformance::OneshotRecvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let current = current_cx();
        let mut recv = this.receiver.recv(&current);
        match Pin::new(&mut recv).poll(cx) {
            Poll::Ready(Ok(value)) => Poll::Ready(Ok(value)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(conformance::OneshotRecvError)),
            Poll::Pending => Poll::Pending,
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
        let cx = current_cx();
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
            let cx = current_cx();
            match receiver.recv(&cx).await {
                Ok(v) => Ok(v),
                Err(broadcast::RecvError::Lagged(n)) => Err(BroadcastRecvError::Lagged(n)),
                Err(broadcast::RecvError::Closed | broadcast::RecvError::Cancelled) => {
                    Err(BroadcastRecvError::Closed)
                }
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
            let cx = current_cx();
            receiver.changed(&cx).await.map_err(|_| WatchRecvError)
        })
    }

    fn borrow_and_clone(&self) -> T {
        self.0.borrow_and_clone()
    }
}

struct AsupersyncFile(fs::File);

impl AsyncFile for AsupersyncFile {
    fn write_all<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { self.0.write_all(buf).await })
    }
    fn read_exact<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { self.0.read_exact(buf).await })
    }
    fn read_to_end<'a>(
        &'a mut self,
        buf: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move { self.0.read_to_end(buf).await })
    }
    fn seek<'a>(
        &'a mut self,
        pos: io::SeekFrom,
    ) -> Pin<Box<dyn Future<Output = io::Result<u64>> + Send + 'a>> {
        Box::pin(async move { self.0.seek(pos).await })
    }
    fn sync_all(&self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async move { self.0.sync_all().await })
    }
    fn shutdown(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async move { self.0.sync_all().await })
    }
}

struct AsupersyncTcpListener(net::TcpListener);

impl TcpListener for AsupersyncTcpListener {
    type Stream = AsupersyncTcpStream;
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
    fn accept(
        &self,
    ) -> Pin<Box<dyn Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send + '_>> {
        let listener = &self.0;
        Box::pin(async move {
            let (stream, addr) = listener.accept().await?;
            Ok((AsupersyncTcpStream(stream), addr))
        })
    }
}

struct AsupersyncTcpStream(net::TcpStream);

impl TcpStream for AsupersyncTcpStream {
    fn read<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move { read_some(&mut self.0, buf).await })
    }
    fn read_exact<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { self.0.read_exact(buf).await })
    }
    fn write_all<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { self.0.write_all(buf).await })
    }
    fn shutdown(&mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async move { AsyncWriteExt::shutdown(&mut self.0).await })
    }
}

struct AsupersyncUdpSocket(net::UdpSocket);

impl UdpSocket for AsupersyncUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let mut socket = self.0.try_clone()?;
            socket.send_to(buf, addr).await
        })
    }
    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move {
            let mut socket = self.0.try_clone()?;
            socket.recv_from(buf).await
        })
    }
}

impl RuntimeInterface for AsupersyncRuntime {
    type JoinHandle<T: Send + 'static> = asupersync::runtime::JoinHandle<T>;
    type MpscSender<T: Send + 'static> = MpscSenderWrapper<T>;
    type MpscReceiver<T: Send + 'static> = MpscReceiverWrapper<T>;
    type OneshotSender<T: Send + 'static> = OneshotSenderWrapper<T>;
    type OneshotReceiver<T: Send + 'static> = OneshotReceiverWrapper<T>;
    type BroadcastSender<T: Send + Clone + 'static> = BroadcastSenderWrapper<T>;
    type BroadcastReceiver<T: Send + Clone + 'static> = BroadcastReceiverWrapper<T>;
    type WatchSender<T: Send + Sync + 'static> = WatchSenderWrapper<T>;
    type WatchReceiver<T: Send + Sync + Clone + 'static> = WatchReceiverWrapper<T>;
    type File = AsupersyncFile;
    type TcpListener = AsupersyncTcpListener;
    type TcpStream = AsupersyncTcpStream;
    type UdpSocket = AsupersyncUdpSocket;

    fn spawn<F>(&self, future: F) -> Self::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.handle.spawn(future)
    }

    fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move { sleep_future(duration).await })
    }

    fn timeout<'a, F: Future + Send + 'a>(
        &'a self,
        duration: Duration,
        future: F,
    ) -> Pin<Box<dyn Future<Output = Result<F::Output, TimeoutError>> + Send + 'a>> {
        Box::pin(async move {
            let timeout = async {
                sleep_future(duration).await;
                Err(TimeoutError)
            };

            let ok_future = async { Ok(future.await) };

            future::or(timeout, ok_future).await
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
        let closed = Arc::new(AtomicBool::new(false));
        let sender = OneshotSenderWrapper {
            sender: Some(tx),
            closed: Arc::clone(&closed),
        };
        let receiver = OneshotReceiverWrapper {
            receiver: rx,
            closed,
        };
        (sender, receiver)
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

    fn file_create<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::File>> + Send + 'a>> {
        Box::pin(async move { fs::File::create(path).await.map(AsupersyncFile) })
    }
    fn file_open<'a>(
        &'a self,
        path: &'a Path,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::File>> + Send + 'a>> {
        Box::pin(async move { fs::File::open(path).await.map(AsupersyncFile) })
    }
    fn tcp_listen<'a>(
        &'a self,
        addr: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::TcpListener>> + Send + 'a>> {
        let addr = addr.to_string();
        Box::pin(async move {
            net::TcpListener::bind(addr)
                .await
                .map(AsupersyncTcpListener)
        })
    }
    fn tcp_connect<'a>(
        &'a self,
        addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::TcpStream>> + Send + 'a>> {
        Box::pin(async move { net::TcpStream::connect(addr).await.map(AsupersyncTcpStream) })
    }
    fn udp_bind<'a>(
        &'a self,
        addr: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::UdpSocket>> + Send + 'a>> {
        let addr = addr.to_string();
        Box::pin(async move { net::UdpSocket::bind(addr).await.map(AsupersyncUdpSocket) })
    }
}

#[test]
fn run_conformance_tests() {
    init_test_logging();
    test_phase!("run_conformance_tests");
    let runtime = AsupersyncRuntime::new();
    let summary = run_conformance_suite(&runtime, "asupersync", RunConfig::new());
    write_conformance_artifacts("channel_conformance", &summary);

    let report = render_console_summary(&summary);
    tracing::info!(summary = %report, "conformance summary");
    assert!(
        summary.failed == 0,
        "Conformance failures detected:\n{report}"
    );
    test_complete!("run_channel_conformance_tests");
}
