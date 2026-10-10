use super::*;
use crate::cx::Cx;
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::Time;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};

#[derive(Default)]
struct ControlledIo {
    writable: bool,
    flushable: bool,
    zero_write: bool,
    reads: usize,
    writes: usize,
}

impl AsyncRead for ControlledIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads += 1;
        if buf.remaining() != 0 {
            buf.unfilled()[0] = 7;
            buf.advance(1);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ControlledIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes += 1;
        if self.zero_write {
            Poll::Ready(Ok(0))
        } else if self.writable {
            Poll::Ready(Ok(buf.len()))
        } else {
            Poll::Pending
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.poll_write(cx, bufs.first().map_or(&[], |buf| buf.as_ref()))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flushable { Poll::Ready(Ok(())) } else { Poll::Pending }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

fn fixture(
    timeout: Option<Duration>,
) -> (RemoteWriteProgress<ControlledIo>, Arc<VirtualClock>, TimerDriverHandle) {
    let clock = Arc::new(VirtualClock::new());
    let driver = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let io = RemoteWriteProgress::new(ControlledIo::default(), timeout, Some(driver.clone()));
    (io, clock, driver)
}

fn timed_out<T: std::fmt::Debug>(result: Poll<io::Result<T>>) {
    assert!(matches!(result, Poll::Ready(Err(ref error))
        if error.kind() == io::ErrorKind::TimedOut), "{result:?}");
}

#[test]
fn stalled_write_wakes_at_its_deadline_and_incoming_bytes_do_not_renew_it() {
    let (mut io, clock, driver) = fixture(Some(Duration::from_secs(1)));
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut task = Context::from_waker(&waker);
    assert!(Pin::new(&mut io).poll_write(&mut task, b"reply").is_pending());
    assert_eq!(driver.pending_count(), 1);
    clock.advance_to(Time::from_millis(900));
    let mut byte = [0; 1];
    assert!(matches!(Pin::new(&mut io).poll_read(&mut task, &mut ReadBuf::new(&mut byte)),
        Poll::Ready(Ok(()))));
    assert_eq!(byte, [7]);
    assert!(Pin::new(&mut io).poll_write(&mut task, b"reply").is_pending());
    assert_eq!(driver.pending_count(), 1);
    clock.advance_to(Time::from_secs(1));
    assert_eq!(driver.process_timers(), 1);
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    timed_out(Pin::new(&mut io).poll_write(&mut task, b"reply"));
    let polls = io.inner.writes;
    io.inner.writable = true;
    timed_out(Pin::new(&mut io).poll_write(&mut task, b"late"));
    timed_out(Pin::new(&mut io).poll_read(&mut task, &mut ReadBuf::new(&mut byte)));
    assert_eq!(io.inner.writes, polls, "timed-out transport cannot be reused");
    assert_eq!(driver.pending_count(), 0);
}

#[test]
fn nonempty_vectored_progress_renews_the_budget_but_zero_writes_do_not() {
    let (mut io, clock, driver) = fixture(Some(Duration::from_secs(1)));
    let mut task = Context::from_waker(Waker::noop());
    let bufs = [IoSlice::new(b"bytes")];
    assert!(io.is_write_vectored());
    assert!(Pin::new(&mut io).poll_write_vectored(&mut task, &bufs).is_pending());
    clock.advance_to(Time::from_millis(900));
    io.inner.writable = true;
    assert!(matches!(Pin::new(&mut io).poll_write_vectored(&mut task, &bufs),
        Poll::Ready(Ok(5))));
    assert_eq!(driver.pending_count(), 0);
    io.inner.writable = false;
    assert!(Pin::new(&mut io).poll_write_vectored(&mut task, &bufs).is_pending());
    clock.advance_to(Time::from_millis(1500));
    io.inner.zero_write = true;
    assert!(matches!(Pin::new(&mut io).poll_write(&mut task, b"x"), Poll::Ready(Ok(0))));
    clock.advance_to(Time::from_millis(1900));
    timed_out(Pin::new(&mut io).poll_write_vectored(&mut task, &bufs));
}

#[test]
fn flush_shutdown_and_drop_share_and_retire_the_pending_write_budget() {
    let (mut io, clock, driver) = fixture(Some(Duration::from_secs(1)));
    let mut task = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut io).poll_flush(&mut task).is_pending());
    clock.advance_to(Time::from_millis(900));
    io.inner.flushable = true;
    assert!(matches!(Pin::new(&mut io).poll_flush(&mut task), Poll::Ready(Ok(()))));
    assert_eq!(driver.pending_count(), 0);
    io.inner.flushable = false;
    assert!(Pin::new(&mut io).poll_shutdown(&mut task).is_pending());
    clock.advance_to(Time::from_millis(1900));
    timed_out(Pin::new(&mut io).poll_shutdown(&mut task));
    assert_eq!(driver.pending_count(), 0);

    let (mut parked, _, driver) = fixture(Some(Duration::from_secs(1)));
    assert!(Pin::new(&mut parked).poll_write(&mut task, b"x").is_pending());
    assert_eq!(driver.pending_count(), 1);
    drop(parked);
    assert_eq!(driver.pending_count(), 0, "dropping connection retires its timer");
}

#[test]
fn disabled_and_zero_write_budgets_preserve_their_explicit_policies() {
    use crate::remote::RemoteComputationServiceConfig;
    let defaults = RemoteComputationServiceConfig::new();
    assert_eq!(defaults.write_progress_timeout(), None);
    assert_eq!(
        defaults.with_write_progress_timeout(Some(Duration::ZERO)).write_progress_timeout(),
        Some(Duration::ZERO),
    );
    let (mut io, clock, driver) = fixture(None);
    let mut task = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut io).poll_write(&mut task, b"x").is_pending());
    clock.advance_to(Time::from_secs(100));
    assert!(Pin::new(&mut io).poll_write(&mut task, b"x").is_pending());
    assert_eq!(driver.pending_count(), 0);

    let (mut zero, _, driver) = fixture(Some(Duration::ZERO));
    zero.inner.writable = true;
    assert!(matches!(Pin::new(&mut zero).poll_write(&mut task, b"x"), Poll::Ready(Ok(1))));
    zero.inner.writable = false;
    timed_out(Pin::new(&mut zero).poll_write(&mut task, b"x"));
    assert_eq!(driver.pending_count(), 0);
}

#[test]
fn ambient_cancellation_is_not_misreported_as_write_timeout() {
    let (mut io, clock, _) = fixture(Some(Duration::from_secs(1)));
    let ambient: Cx = Cx::for_testing();
    ambient.set_cancel_requested(true);
    let _current = Cx::set_current(Some(ambient));
    let mut task = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut io).poll_write(&mut task, b"x").is_pending());
    clock.advance_to(Time::from_millis(999));
    assert!(Pin::new(&mut io).poll_write(&mut task, b"x").is_pending());
    clock.advance_to(Time::from_secs(1));
    timed_out(Pin::new(&mut io).poll_write(&mut task, b"x"));
}

#[cfg(unix)]
mod native {
    use super::*;
    use crate::distributed::{HasSchema, SchemaDescriptor};
    use crate::net::TcpStream;
    use crate::remote::{
        ComputationName, IdempotencyKey, NodeId, RemoteComputationClient,
        RemoteComputationClientConfig, RemoteComputationRegistry, RemoteComputationService,
        RemoteComputationServiceConfig, RemoteComputationServiceHandle, RemoteInput,
        RemoteOutcome, RemotePeerAdmissionPolicy, RemoteProtocolVersion, RemoteServiceWireLimits,
        RemoteServiceWireOutcome, RemoteServiceWireRequest, RemoteServiceWireResponse,
        RemoteTaskId, SpawnRequest, remote_service_framed, write_remote_service_frame,
    };
    use crate::runtime::RuntimeBuilder;
    use crate::tls::{
        Certificate, CertificateChain, CertificatePin, CertificatePinSet, ClientAuth,
        PrivateKey, RootCertStore, TlsAcceptorBuilder, TlsConnectorBuilder,
    };

    const OUTPUT_BYTES: usize = 8 * 1024 * 1024;
    const FRAME_BYTES: usize = 24 * 1024 * 1024;

    struct Bytes;
    impl HasSchema for Bytes {
        fn schema() -> SchemaDescriptor {
            SchemaDescriptor::primitive("remote-write-progress.bytes.v1")
        }
    }

    struct ForceClose(RemoteComputationServiceHandle);
    impl Drop for ForceClose {
        fn drop(&mut self) { self.0.force_close(); }
    }

    #[allow(clippy::too_many_lines)]
    fn exercise(workers: usize, version: RemoteProtocolVersion) {
        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread().build().unwrap()
        } else {
            RuntimeBuilder::multi_thread().worker_threads(workers).build().unwrap()
        };
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let factories = Arc::new(AtomicUsize::new(0));
            let seen = Arc::clone(&factories);
            let mut registry = RemoteComputationRegistry::new();
            registry.register::<Bytes, Bytes, _, _>("large", move |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                async { Ok(RemoteOutcome::Success(vec![7; OUTPUT_BYTES])) }
            }).unwrap();

            let cert = Certificate::from_pem(
                include_bytes!("../../../tests/fixtures/tls/server.crt"),
            ).unwrap().remove(0);
            let chain = CertificateChain::from_pem(
                include_bytes!("../../../tests/fixtures/tls/server.crt"),
            ).unwrap();
            let key = PrivateKey::from_pem(
                include_bytes!("../../../tests/fixtures/tls/server.key"),
            ).unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(&cert).unwrap();
            let acceptor = TlsAcceptorBuilder::new(chain.clone(), key.clone())
                .client_auth(ClientAuth::Required(roots)).build().unwrap();
            let mut pins = CertificatePinSet::new();
            pins.add(CertificatePin::compute_spki_sha256(&cert).unwrap());
            let connector = TlsConnectorBuilder::new().add_root_certificate(&cert)
                .identity(chain, key).with_certificate_pins(pins.clone()).build().unwrap();
            let mut policy = RemotePeerAdmissionPolicy::new(version, registry.schema_registry().clone());
            policy.grant_tls_peer(NodeId::new("origin"), pins, ["large"]).unwrap();
            let hello = policy.hello_for(NodeId::new("origin"));
            let limits = RemoteServiceWireLimits::new(FRAME_BYTES);
            let config = RemoteComputationServiceConfig::new()
                .with_wire_limits(limits)
                .with_max_connections(Some(2))
                .with_write_progress_timeout(Some(Duration::from_secs(1)))
                .with_drain_timeout(Duration::from_secs(3));
            let service = RemoteComputationService::bind(
                "127.0.0.1:0", acceptor, policy, registry, config,
            ).await.unwrap();
            let address = service.local_addr().unwrap();
            let operator = service.handle();
            let _stop = ForceClose(operator.clone());
            let mut serving = cx.spawn(move |server| async move { service.run(&server).await }).unwrap();

            // The listener is already bound. Limit the real peer receive buffer
            // so an 8 MiB result cannot fit in TCP while this peer never reads it.
            let socket = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
            socket2::SockRef::from(&socket).set_recv_buffer_size(4096).unwrap();
            let socket = TcpStream::from_std(socket).unwrap();
            let stream = crate::time::timeout(
                cx.now(), Duration::from_secs(3), connector.connect("localhost", socket),
            ).await.expect("mTLS handshake deadline").unwrap();
            let mut stalled = remote_service_framed(stream, limits).unwrap();
            let request = RemoteServiceWireRequest::from_spawn_request(hello, &SpawnRequest {
                remote_task_id: RemoteTaskId::next(),
                computation: ComputationName::new("large"),
                input: RemoteInput::new(b"exact retry".to_vec()),
                lease: Duration::from_secs(30),
                idempotency_key: IdempotencyKey::from_raw(901),
                budget: None,
                origin_node: NodeId::new("origin"),
                origin_region: cx.region_id(),
                origin_task: cx.task_id(),
            }).unwrap();
            write_remote_service_frame(&cx, &mut stalled, &request, FRAME_BYTES).await.unwrap();

            crate::time::timeout(cx.now(), Duration::from_secs(10), async {
                while factories.load(Ordering::SeqCst) == 0 || operator.active_connections() != 0 {
                    crate::time::sleep(cx.now(), Duration::from_millis(1)).await;
                }
            }).await.expect("non-reading peer must lose its slot to the write deadline");
            assert_eq!(factories.load(Ordering::SeqCst), 1);

            // Keep the original non-reading TLS peer alive. A new connection
            // must replay the already committed result, not execute it again.
            let client = RemoteComputationClient::new(
                address, "localhost", connector,
                RemoteComputationClientConfig::new().with_wire_limits(limits)
                    .with_max_attempts(1).with_attempt_timeout(Duration::from_secs(20)),
            ).unwrap();
            let response = client.call(&cx, &request).await.unwrap();
            assert!(matches!(response, RemoteServiceWireResponse::Outcome {
                outcome: RemoteServiceWireOutcome::Success(ref bytes), ..
            } if bytes.len() == OUTPUT_BYTES && bytes.iter().all(|byte| *byte == 7)));
            assert_eq!(factories.load(Ordering::SeqCst), 1, "terminal write failure cannot rerun a commit");
            drop(stalled);
            let _ = operator.begin_drain();
            let report = crate::time::timeout(
                cx.now(), Duration::from_secs(3), serving.join(&cx),
            ).await.expect("listener drain deadline").expect("listener task").expect("listener result");
            assert_eq!(report.failed_connections, 1);
            assert_eq!(report.completed_connections, 1);
            assert_eq!(report.interrupted_connections, 0);
            assert_eq!(report.panicked_connections, 0);
            assert!(report.first_connection_failure.as_deref().unwrap().contains("no write progress"));
            assert_eq!(operator.active_connections(), 0);
            assert!(!cx.is_cancel_requested());
        });
        assert!(runtime.diagnostics().find_leaked_obligations().is_empty());
        assert!(runtime.shutdown_timeout(Duration::from_secs(3)));
    }

    #[test]
    fn stalled_mtls_terminal_releases_its_slot_and_replays_without_reexecution() {
        for workers in [1, 2] {
            for version in [RemoteProtocolVersion::V2, RemoteProtocolVersion::V3] {
                exercise(workers, version);
            }
        }
    }
}
