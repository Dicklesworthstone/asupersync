//! Exercise scripted source failures through native I/O, not only model state.

#![cfg(unix)]

use super::{LabReactorModel, ReadinessMode};
use crate::cx::Cx;
use crate::io::unix::AsyncFd;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::lab::{LabConfig, LabRuntime};
use crate::net::unix::UnixStream;
use crate::net::{TcpStream, UdpSocket};
use crate::runtime::IoDriverHandle;
use crate::runtime::reactor::{Interest, Reactor, Token};
use crate::sync::atomic::{AtomicUsize, Ordering};
use crate::types::{Budget, RegionId, TaskId};
use crate::sync::pl::Mutex;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::net;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn model_driver() -> (Arc<LabReactorModel>, IoDriverHandle) {
    let model = Arc::new(LabReactorModel::new());
    let driver = IoDriverHandle::new(model.clone());
    (model, driver)
}

fn with_driver<T>(driver: &IoDriverHandle, poll: impl FnOnce() -> T) -> T {
    let ambient = Cx::new_with_observability(
        RegionId::new_for_test(0, 1),
        TaskId::new_for_test(0, 0),
        Budget::INFINITE,
        None,
        Some(driver.clone()),
        None,
    );
    let _current = Cx::set_current(Some(ambient));
    poll()
}

fn sole_token(model: &LabReactorModel) -> Token {
    let state = model.state.lock();
    assert_eq!(state.registrations.len(), 1);
    *state.registrations.keys().next().unwrap()
}

fn dispatch(driver: &IoDriverHandle) -> usize {
    driver
        .turn_with(Some(Duration::ZERO), |_, _| {})
        .expect("source failure does not fail the reactor poll")
}

fn assert_error<T>(result: Poll<io::Result<T>>, kind: io::ErrorKind) {
    match result {
        Poll::Ready(Err(error)) => assert_eq!(error.kind(), kind),
        Poll::Ready(Ok(_)) => panic!("scripted source error was hidden by successful I/O"),
        Poll::Pending => panic!("scripted source error was hidden by parking or fallback"),
    }
}

fn read<R: AsyncRead + Unpin>(
    stream: &mut R,
    cx: &mut Context<'_>,
    bytes: &mut [u8],
) -> Poll<io::Result<usize>> {
    let mut buf = ReadBuf::new(bytes);
    Pin::new(stream)
        .poll_read(cx, &mut buf)
        .map(|result| result.map(|()| buf.filled().len()))
}

fn tcp_pair() -> (TcpStream, net::TcpStream) {
    let listener = net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local = net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (peer, _) = listener.accept().unwrap();
    (TcpStream::from_std(local).unwrap(), peer)
}

fn unix_pair() -> (UnixStream, StdUnixStream) {
    let (local, peer) = StdUnixStream::pair().unwrap();
    (UnixStream::from_std(local).unwrap(), peer)
}

fn async_fd_pair() -> (AsyncFd<StdUnixStream>, StdUnixStream) {
    let (local, peer) = StdUnixStream::pair().unwrap();
    local.set_nonblocking(true).unwrap();
    (AsyncFd::new(local).unwrap(), peer)
}

#[test]
fn pending_tcp_read_observes_exact_source_error_once() {
    for kind in [io::ErrorKind::ConnectionReset, io::ErrorKind::NotConnected] {
        let (model, driver) = model_driver();
        let (mut stream, _peer) = tcp_pair();
        let count = Arc::new(WakeCount::default());
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        let mut bytes = [0; 8];
        assert!(with_driver(&driver, || read(&mut stream, &mut cx, &mut bytes)).is_pending());
        let token = sole_token(&model);

        model.inject_source_error(token, kind).unwrap();
        assert_eq!(dispatch(&driver), 1);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_error(
            with_driver(&driver, || read(&mut stream, &mut cx, &mut bytes)),
            kind,
        );
        assert!(model.take_error(token).is_none());
        assert!(with_driver(&driver, || read(&mut stream, &mut cx, &mut bytes)).is_pending());
        assert_eq!(sole_token(&model), token);
        assert_eq!(driver.poll_error_count(), 0);
        drop(stream);
        assert!(driver.is_empty());
        assert_eq!(model.registration_count(), 0);
    }
}

#[test]
fn tcp_split_halves_and_reunite_do_not_discard_source_errors() {
    let (model, driver) = model_driver();
    let (mut stream, _peer) = tcp_pair();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut bytes = [0; 8];
    assert!(with_driver(&driver, || read(&mut stream, &mut cx, &mut bytes)).is_pending());
    let token = sole_token(&model);
    {
        let (mut reader, mut writer) = stream.split();
        model
            .inject_source_error(token, io::ErrorKind::NotConnected)
            .unwrap();
        assert_error(
            with_driver(&driver, || read(&mut reader, &mut cx, &mut bytes)),
            io::ErrorKind::NotConnected,
        );
        model
            .inject_source_error(token, io::ErrorKind::BrokenPipe)
            .unwrap();
        assert_error(
            with_driver(&driver, || Pin::new(&mut writer).poll_write(&mut cx, b"x")),
            io::ErrorKind::BrokenPipe,
        );
    }
    model
        .inject_source_error(token, io::ErrorKind::ConnectionReset)
        .unwrap();

    let (mut reader, writer) = stream.into_split();
    assert_error(
        with_driver(&driver, || read(&mut reader, &mut cx, &mut bytes)),
        io::ErrorKind::ConnectionReset,
    );
    assert!(with_driver(&driver, || read(&mut reader, &mut cx, &mut bytes)).is_pending());
    model
        .inject_source_error(token, io::ErrorKind::NotConnected)
        .unwrap();
    let mut stream = reader.reunite(writer).unwrap();
    assert_error(
        with_driver(&driver, || read(&mut stream, &mut cx, &mut bytes)),
        io::ErrorKind::NotConnected,
    );
    drop(stream);
    assert_eq!(model.registration_count(), 0);
}

#[test]
fn udp_migration_reports_old_source_error_before_replacing_registration() {
    let (model_a, driver_a) = model_driver();
    let (model_b, driver_b) = model_driver();
    let mut socket = UdpSocket::from_std(net::UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap();
    let waker = Waker::noop();
    let cx = Context::from_waker(waker);
    let mut bytes = [0; 8];
    assert!(with_driver(&driver_a, || socket.poll_recv_from(&cx, &mut bytes)).is_pending());
    let token = sole_token(&model_a);
    model_a
        .inject_source_error(token, io::ErrorKind::NotConnected)
        .unwrap();

    assert_error(
        with_driver(&driver_b, || socket.poll_recv_from(&cx, &mut bytes)),
        io::ErrorKind::NotConnected,
    );
    assert_eq!(sole_token(&model_a), token);
    assert_eq!(model_b.registration_count(), 0);
    assert!(with_driver(&driver_b, || socket.poll_recv_from(&cx, &mut bytes)).is_pending());
    assert!(driver_a.is_empty());
    assert_eq!(model_a.registration_count(), 0);
    let migrated = sole_token(&model_b);
    model_b
        .inject_source_error(migrated, io::ErrorKind::ConnectionRefused)
        .unwrap();
    assert_eq!(dispatch(&driver_b), 1);
    assert_error(
        with_driver(&driver_b, || socket.poll_recv_from(&cx, &mut bytes)),
        io::ErrorKind::ConnectionRefused,
    );
    assert!(with_driver(&driver_b, || socket.poll_recv_from(&cx, &mut bytes)).is_pending());
    drop(socket);
    assert_eq!(model_b.registration_count(), 0);
}

#[test]
fn unix_source_error_precedes_buffered_bytes_and_survives_split() {
    let (model, driver) = model_driver();
    let (mut stream, mut peer) = unix_pair();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut bytes = [0; 8];
    assert!(with_driver(&driver, || read(&mut stream, &mut cx, &mut bytes)).is_pending());
    let token = sole_token(&model);
    model
        .inject_source_error(token, io::ErrorKind::ConnectionReset)
        .unwrap();
    peer.write_all(b"a").unwrap();
    assert_error(
        with_driver(&driver, || read(&mut stream, &mut cx, &mut bytes)),
        io::ErrorKind::ConnectionReset,
    );
    assert!(matches!(
        with_driver(&driver, || read(&mut stream, &mut cx, &mut bytes)),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(bytes[0], b'a');

    {
        let (mut reader, mut writer) = stream.split();
        model
            .inject_source_error(token, io::ErrorKind::NotConnected)
            .unwrap();
        assert_error(
            with_driver(&driver, || read(&mut reader, &mut cx, &mut bytes)),
            io::ErrorKind::NotConnected,
        );
        model
            .inject_source_error(token, io::ErrorKind::BrokenPipe)
            .unwrap();
        assert_error(
            with_driver(&driver, || Pin::new(&mut writer).poll_write(&mut cx, b"x")),
            io::ErrorKind::BrokenPipe,
        );
    }

    let (mut reader, writer) = stream.into_split();
    model
        .inject_source_error(token, io::ErrorKind::NotConnected)
        .unwrap();
    peer.write_all(b"b").unwrap();
    assert_error(
        with_driver(&driver, || read(&mut reader, &mut cx, &mut bytes)),
        io::ErrorKind::NotConnected,
    );
    assert!(matches!(
        with_driver(&driver, || read(&mut reader, &mut cx, &mut bytes)),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(bytes[0], b'b');
    drop((reader, writer));
    assert_eq!(model.registration_count(), 0);
}

#[test]
fn async_fd_source_error_precedes_cached_readiness_without_clearing_it() {
    let (model, driver) = model_driver();
    let (fd, _peer) = async_fd_pair();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(with_driver(&driver, || fd.poll_read_ready(&mut cx)).is_pending());
    let token = sole_token(&model);
    model.set_ready(token, Interest::READABLE).unwrap();
    assert_eq!(dispatch(&driver), 1);
    assert!(matches!(
        with_driver(&driver, || fd.poll_read_ready(&mut cx)),
        Poll::Ready(Ok(_))
    ));

    // The one-shot is disarmed and the readiness bit is already cached.
    // An operation must still observe the source fault without another event.
    assert!(!model.is_armed(token).unwrap());
    model
        .inject_source_error(token, io::ErrorKind::ConnectionReset)
        .unwrap();
    assert_error(
        with_driver(&driver, || fd.poll_read_ready(&mut cx)),
        io::ErrorKind::ConnectionReset,
    );
    assert_eq!(model.readiness(token).unwrap(), Interest::READABLE);
    assert!(matches!(
        with_driver(&driver, || fd.poll_read_ready(&mut cx)),
        Poll::Ready(Ok(_))
    ));
    drop(fd);
    assert_eq!(model.registration_count(), 0);
}

#[test]
fn async_fd_migration_cannot_discard_pending_source_error() {
    let (model_a, driver_a) = model_driver();
    let (model_b, driver_b) = model_driver();
    let (fd, _peer) = async_fd_pair();
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(with_driver(&driver_a, || fd.poll_read_ready(&mut cx)).is_pending());
    let token = sole_token(&model_a);
    model_a
        .inject_source_error(token, io::ErrorKind::NotConnected)
        .unwrap();
    assert_error(
        with_driver(&driver_b, || fd.poll_read_ready(&mut cx)),
        io::ErrorKind::NotConnected,
    );
    assert_eq!(sole_token(&model_a), token);
    assert_eq!(model_b.registration_count(), 0);
    assert!(with_driver(&driver_b, || fd.poll_read_ready(&mut cx)).is_pending());
    assert_eq!(model_a.registration_count(), 0);
    assert_eq!(model_b.registration_count(), 1);
    drop(fd);
    assert!(driver_a.is_empty());
    assert!(driver_b.is_empty());
}

#[test]
fn held_async_fd_guards_observe_errors_injected_after_readiness() {
    for mutable in [false, true] {
        let (model, driver) = model_driver();
        let (mut fd, _peer) = async_fd_pair();
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(with_driver(&driver, || fd.poll_read_ready(&mut cx)).is_pending());
        let token = sole_token(&model);
        model.set_ready(token, Interest::READABLE).unwrap();
        assert_eq!(dispatch(&driver), 1);

        if mutable {
            let mut waiting = Box::pin(fd.readable_mut());
            let mut guard = match with_driver(&driver, || waiting.as_mut().poll(&mut cx)) {
                Poll::Ready(Ok(guard)) => guard,
                _ => panic!("readiness was dispatched"),
            };
            drop(waiting);
            model
                .inject_source_error(token, io::ErrorKind::ConnectionReset)
                .unwrap();
            let error = guard
                .try_io::<()>(|_| panic!("I/O closure ran before pending source error"))
                .unwrap()
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            assert_eq!(guard.try_io(|_| Ok(7)).unwrap().unwrap(), 7);
        } else {
            let mut guard = match with_driver(&driver, || fd.poll_read_ready(&mut cx)) {
                Poll::Ready(Ok(guard)) => guard,
                _ => panic!("readiness was dispatched"),
            };
            model
                .inject_source_error(token, io::ErrorKind::ConnectionReset)
                .unwrap();
            let error = guard
                .try_io::<()>(|_| panic!("I/O closure ran before pending source error"))
                .unwrap()
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
            assert_eq!(guard.try_io(|_| Ok(7)).unwrap().unwrap(), 7);
        }
        assert_eq!(model.readiness(token).unwrap(), Interest::READABLE);
        drop(fd);
        assert_eq!(model.registration_count(), 0);
    }
}

#[test]
fn attached_lab_delivers_source_error_to_parked_native_read_at_current_time() {
    let (mut lab, model) =
        LabRuntime::with_reactor_model(LabConfig::new(61), ReadinessMode::OneShot);
    let driver = lab.state.io_driver_handle().unwrap();
    let (mut stream, _peer) = unix_pair();
    let polls = Arc::new(AtomicUsize::new(0));
    let task_polls = polls.clone();
    let observed = Arc::new(Mutex::new(None));
    let task_observed = observed.clone();
    let mut bytes = [0; 8];
    let future = poll_fn(move |cx| {
        task_polls.fetch_add(1, Ordering::SeqCst);
        match read(&mut stream, cx, &mut bytes) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                *task_observed.lock() = Some(error.kind());
                Poll::Ready(())
            }
            Poll::Ready(Ok(_)) => panic!("peer never sent bytes or closed"),
        }
    });
    let region = lab.state.create_root_region(Budget::INFINITE);
    let (task, _handle) = lab
        .state
        .create_task(region, Budget::INFINITE, future)
        .unwrap();
    lab.scheduler.lock().schedule(task, 0);
    lab.run_until_idle();
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert!(lab.scheduler.lock().is_empty());
    let now = lab.now();
    model
        .inject_source_error(sole_token(&model), io::ErrorKind::ConnectionReset)
        .unwrap();

    let _report = lab.run_with_auto_advance();
    assert_eq!(*observed.lock(), Some(io::ErrorKind::ConnectionReset));
    assert_eq!(polls.load(Ordering::SeqCst), 2);
    assert_eq!(lab.now(), now);
    assert_eq!(model.now(), now);
    assert_eq!(driver.poll_error_count(), 0);
    assert!(driver.is_empty());
    assert_eq!(model.registration_count(), 0);
}
