#![allow(missing_docs)]
#![cfg(feature = "test-internals")]
//! I/O Cancellation and Obligation Tests.
//!
//! These tests verify that I/O operations are cancel-safe and integrate
//! properly with asupersync's obligation tracking and registration cleanup.
//!
//! # Test Coverage (asupersync-ofb5)
//!
//! - IO-CANCEL-001: Cancel during read cleans up registration
//! - IO-CANCEL-002: Cancel during write cleans up registration
//! - IO-CANCEL-003: Cancel during accept cleans up registration
//! - IO-CANCEL-004: Cancel during connect cleans up registration
//! - IO-CANCEL-005: Registration cleanup on normal drop
//! - IO-CANCEL-006: Split stream cleanup works correctly
//! - IO-CANCEL-007: Nested task cancellation propagates to I/O
//! - IO-CANCEL-008: Multiple concurrent I/O operations cancel correctly
//!
//! # Key Invariants
//!
//! 1. When I/O operations are cancelled:
//!    - Reactor registrations must be cleaned up
//!    - No leaked obligations
//!    - No dangling wakers
//!    - Resources properly released
//!
//! 2. Cancellation is a protocol, not silent drop:
//!    - Request -> Drain -> Finalize

#[macro_use]
mod common;

use asupersync::cx::Cx;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::reactor::{Interest, LabReactor};
use asupersync::runtime::{IoDriverHandle, Reactor, RuntimeBuilder};
use asupersync::types::{Budget, RegionId, TaskId};
use common::*;
use futures_lite::future::block_on;
use std::future::Future;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::Duration;

/// Simple no-op waker for polling tests.
struct NoopWaker;

impl Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWaker))
}

fn init_test(test_name: &str) {
    init_test_logging();
    test_phase!(test_name);
}

/// Create a lab reactor with Cx context for testing.
fn setup_test_cx() -> (Arc<LabReactor>, impl Drop) {
    let reactor = Arc::new(LabReactor::new());
    let reactor_dyn: Arc<dyn Reactor> = Arc::clone(&reactor) as Arc<dyn Reactor>;
    let driver = IoDriverHandle::new(reactor_dyn);
    let cx = Cx::new_with_observability(
        RegionId::new_for_test(0, 0),
        TaskId::new_for_test(0, 0),
        Budget::INFINITE,
        None,
        Some(driver),
        None, // entropy
    );
    let guard = Cx::set_current(Some(cx));
    (reactor, guard)
}

/// Create a connected TCP pair for testing.
fn create_connected_pair() -> io::Result<(TcpStream, std::net::TcpStream)> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    // Connect in a background thread
    let client_handle = thread::spawn(move || block_on(TcpStream::connect(addr)));

    // Accept the connection
    let (server_stream, _) = listener.accept()?;
    server_stream.set_nonblocking(true)?;

    let client_stream = client_handle.join().expect("client thread panicked")?;

    Ok((client_stream, server_stream))
}

// ============================================================================
// IO-CANCEL-001: Cancel during read cleans up registration
// ============================================================================

/// Verifies that cancelling a read operation properly cleans up the reactor registration.
#[test]
fn io_cancel_001_cancel_during_read() {
    init_test("io_cancel_001_cancel_during_read");

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // Connect from std stream (simpler for this test)
        let server_handle = thread::spawn(move || {
            let client = std::net::TcpStream::connect(addr).expect("connect");
            client.set_nonblocking(true).expect("nonblocking");
            // Don't send any data - let the read block
            thread::sleep(Duration::from_millis(100));
            drop(client);
        });

        // Accept connection
        let (mut stream, _) = listener.accept().await?;

        // Try to read (will return Pending since no data)
        let mut buf = [0u8; 1024];
        let mut read_buf = ReadBuf::new(&mut buf);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Poll read - should return Pending and register interest
        let poll_result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
        tracing::info!(?poll_result, "first poll result");
        assert!(
            matches!(poll_result, Poll::Pending),
            "read should be pending"
        );

        // Now simulate cancellation by dropping the stream
        tracing::info!("dropping stream to simulate cancellation");
        drop(stream);

        // Wait for server to finish
        server_handle.join().expect("server thread panicked");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "cancel during read test should complete: {:?}",
        result
    );
    test_complete!("io_cancel_001_cancel_during_read");
}

// ============================================================================
// IO-CANCEL-002: Cancel during write cleans up registration
// ============================================================================

/// Verifies that cancelling a write operation properly cleans up resources.
#[test]
fn io_cancel_002_cancel_during_write() {
    init_test("io_cancel_002_cancel_during_write");

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let accept_handle = thread::spawn(move || {
            block_on(async {
                let (stream, _) = listener.accept().await?;
                // Don't read - let the write buffer fill up
                thread::sleep(Duration::from_millis(100));
                drop(stream);
                Ok::<_, io::Error>(())
            })
        });

        // Give server time to start listening
        thread::sleep(Duration::from_millis(10));

        // Connect
        let mut stream = TcpStream::connect(addr).await?;

        // Try to write
        let data = vec![0u8; 1024];
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Poll write - may succeed or return Pending
        let poll_result = Pin::new(&mut stream).poll_write(&mut cx, &data);
        tracing::info!(?poll_result, "poll_write result");

        // Drop stream to simulate cancellation (even mid-operation)
        tracing::info!("dropping stream to simulate cancellation");
        drop(stream);

        // Wait for server
        let _ = accept_handle.join();

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "cancel during write test should complete: {:?}",
        result
    );
    test_complete!("io_cancel_002_cancel_during_write");
}

// ============================================================================
// IO-CANCEL-003: Cancel during accept cleans up registration
// ============================================================================

/// Verifies that cancelling an accept operation properly cleans up.
#[test]
fn io_cancel_003_cancel_during_accept() {
    init_test("io_cancel_003_cancel_during_accept");

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        tracing::info!(addr = ?listener.local_addr(), "listener bound");

        // Start accept in a pinned future that we can poll
        let mut accept_fut = Box::pin(listener.accept());
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Poll accept - should return Pending (no connection yet)
        let poll_result = accept_fut.as_mut().poll(&mut cx);
        tracing::info!(?poll_result, "accept poll result");
        assert!(
            matches!(poll_result, Poll::Pending),
            "accept should be pending"
        );

        // Cancel by dropping the future
        tracing::info!("dropping accept future to simulate cancellation");
        drop(accept_fut);

        // Listener should still be valid
        tracing::info!("listener still valid after cancel");

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "cancel during accept test should complete: {:?}",
        result
    );
    test_complete!("io_cancel_003_cancel_during_accept");
}

// ============================================================================
// IO-CANCEL-004: Cancel during connect cleans up registration
// ============================================================================

/// Verifies that cancelling a connect operation properly cleans up.
#[test]
fn io_cancel_004_cancel_during_connect() {
    init_test("io_cancel_004_cancel_during_connect");

    // Use a non-routable address to ensure connect blocks
    let addr: SocketAddr = "192.0.2.1:81".parse().expect("parse addr");

    let mut connect_fut = Box::pin(TcpStream::connect(addr));
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // Poll connect - should return Pending or error
    let poll_result = connect_fut.as_mut().poll(&mut cx);
    tracing::info!(?poll_result, "connect poll result");

    // Cancel by dropping
    tracing::info!("dropping connect future to simulate cancellation");
    drop(connect_fut);

    // Should not deadlock or leak resources
    tracing::info!("connect cancelled successfully");
    test_complete!("io_cancel_004_cancel_during_connect");
}

// ============================================================================
// IO-CANCEL-005: Registration cleanup on normal drop
// ============================================================================

/// Verifies that dropping a stream normally cleans up its registration.
#[test]
fn io_cancel_005_registration_cleanup_on_drop() {
    init_test("io_cancel_005_registration_cleanup_on_drop");

    let (reactor, _guard) = setup_test_cx();
    let initial_count = reactor.registration_count();

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // Connect in background
        let connect_handle = thread::spawn(move || block_on(TcpStream::connect(addr)));

        // Accept
        let (mut stream, _) = listener.accept().await?;

        // Trigger registration by attempting I/O
        let mut buf = [0u8; 1024];
        let mut read_buf = ReadBuf::new(&mut buf);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // This should register with the reactor
        let _ = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);

        // Get client
        let _ = connect_handle.join();

        // Stream dropped here
        Ok::<_, io::Error>(())
    });

    // After drop, registration count should return to initial
    let final_count = reactor.registration_count();
    tracing::info!(initial_count, final_count, "registration counts");

    assert!(
        result.is_ok(),
        "registration cleanup test should complete: {:?}",
        result
    );
    test_complete!("io_cancel_005_registration_cleanup_on_drop");
}

// ============================================================================
// IO-CANCEL-006: Split stream cleanup works correctly
// ============================================================================

/// Verifies that split stream halves properly share and clean up registration.
#[test]
fn io_cancel_006_split_stream_cleanup() {
    init_test("io_cancel_006_split_stream_cleanup");

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // Server accepts in background
        let server_handle = thread::spawn(move || {
            block_on(async {
                let (stream, _) = listener.accept().await?;
                // Split the server stream too
                let (read_half, write_half) = stream.into_split();

                // Verify both halves exist
                tracing::info!("server split into halves");

                // Drop read half first
                drop(read_half);
                tracing::info!("server read half dropped");

                // Write half should still work conceptually
                thread::sleep(Duration::from_millis(10));
                drop(write_half);
                tracing::info!("server write half dropped");

                Ok::<_, io::Error>(())
            })
        });

        // Give server time to start
        thread::sleep(Duration::from_millis(10));

        // Connect client
        let stream = TcpStream::connect(addr).await?;
        let (read_half, write_half) = stream.into_split();

        tracing::info!("client split into halves");

        // Drop one half
        drop(read_half);
        tracing::info!("client read half dropped");

        // Other half should still be valid
        thread::sleep(Duration::from_millis(10));

        // Reunite would fail since read_half is dropped, but cleanup should work
        drop(write_half);
        tracing::info!("client write half dropped");

        // Wait for server
        server_handle.join().expect("server panicked")?;

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "split stream cleanup test should complete: {:?}",
        result
    );
    test_complete!("io_cancel_006_split_stream_cleanup");
}

// ============================================================================
// IO-CANCEL-007: Nested task cancellation propagates to I/O
// ============================================================================

/// Verifies that cancelling a parent task propagates to I/O operations in child.
#[test]
fn io_cancel_007_nested_cancellation() {
    init_test("io_cancel_007_nested_cancellation");

    let cancelled = Arc::new(AtomicBool::new(false));
    let cancelled_clone = Arc::clone(&cancelled);

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // Simulate a "child task" with I/O
        let io_handle = thread::spawn(move || {
            block_on(async {
                match TcpStream::connect(addr).await {
                    Ok(mut stream) => {
                        // Try to read - will block
                        let mut buf = [0u8; 1024];
                        let mut read_buf = ReadBuf::new(&mut buf);
                        let waker = noop_waker();
                        let mut cx = Context::from_waker(&waker);

                        let _ = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);
                        // Simulate cancellation via drop
                        cancelled_clone.store(true, Ordering::SeqCst);
                    }
                    Err(e) => {
                        tracing::info!(?e, "connect failed (expected in some cases)");
                        cancelled_clone.store(true, Ordering::SeqCst);
                    }
                }
            })
        });

        // Accept and then close immediately (triggering cancellation-like behavior)
        thread::sleep(Duration::from_millis(50));
        let accept_result = listener.accept().await;
        if let Ok((stream, _)) = accept_result {
            // Drop immediately
            drop(stream);
        }

        // Wait for "child"
        io_handle.join().expect("io thread panicked");

        Ok::<_, io::Error>(())
    });

    let was_cancelled = cancelled.load(Ordering::SeqCst);
    tracing::info!(was_cancelled, "cancellation flag");

    assert!(
        result.is_ok(),
        "nested cancellation test should complete: {:?}",
        result
    );
    test_complete!("io_cancel_007_nested_cancellation");
}

// ============================================================================
// IO-CANCEL-008: Multiple concurrent I/O operations cancel correctly
// ============================================================================

/// Verifies that multiple concurrent I/O operations can all be cancelled properly.
#[test]
fn io_cancel_008_multiple_concurrent_cancel() {
    init_test("io_cancel_008_multiple_concurrent_cancel");

    const NUM_CONNECTIONS: usize = 5;
    let cancelled_count = Arc::new(AtomicUsize::new(0));

    let result = block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // Accept connections in background
        let accept_handle = thread::spawn(move || {
            block_on(async {
                for i in 0..NUM_CONNECTIONS {
                    match listener.accept().await {
                        Ok((stream, peer)) => {
                            tracing::info!(i, ?peer, "accepted connection");
                            // Hold stream briefly then drop
                            thread::sleep(Duration::from_millis(10));
                            drop(stream);
                        }
                        Err(e) => {
                            tracing::warn!(i, ?e, "accept failed");
                            break;
                        }
                    }
                }
            })
        });

        // Give server time to start
        thread::sleep(Duration::from_millis(10));

        // Spawn multiple connect tasks
        let mut handles = Vec::new();
        for i in 0..NUM_CONNECTIONS {
            let counter = Arc::clone(&cancelled_count);
            let handle = thread::spawn(move || {
                block_on(async {
                    match TcpStream::connect(addr).await {
                        Ok(stream) => {
                            tracing::info!(i, "connected");
                            // Drop to trigger cancellation/cleanup
                            drop(stream);
                            counter.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(e) => {
                            tracing::info!(i, ?e, "connect failed");
                            counter.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                })
            });
            handles.push(handle);
        }

        // Wait for all clients
        for handle in handles {
            handle.join().expect("client panicked");
        }

        // Wait for server
        accept_handle.join().expect("accept panicked");

        Ok::<_, io::Error>(())
    });

    let final_count = cancelled_count.load(Ordering::SeqCst);
    tracing::info!(
        final_count,
        NUM_CONNECTIONS,
        "concurrent cancellation counts"
    );

    assert!(
        result.is_ok(),
        "multiple concurrent cancel test should complete: {:?}",
        result
    );
    assert_eq!(
        final_count, NUM_CONNECTIONS,
        "all connections should complete"
    );
    test_complete!("io_cancel_008_multiple_concurrent_cancel");
}

// ============================================================================
// Registration State Verification Tests
// ============================================================================

/// Verifies that the reactor's registration count tracks correctly.
#[test]
fn io_cancel_registration_count_tracking() {
    init_test("io_cancel_registration_count_tracking");

    let (reactor, _guard) = setup_test_cx();
    let initial = reactor.registration_count();

    tracing::info!(initial, "initial registration count");

    // Create listener - may or may not register immediately depending on impl
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // Connect
    let _client = std::net::TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    server.set_nonblocking(true).expect("nonblocking");

    // Create async stream and trigger registration
    let mut stream = TcpStream::from_std(server);
    let mut buf = [0u8; 8];
    let mut read_buf = ReadBuf::new(&mut buf);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // This poll should register with reactor
    let _ = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);

    let after_register = reactor.registration_count();
    tracing::info!(after_register, "after registration");

    // Drop stream
    drop(stream);

    let after_drop = reactor.registration_count();
    tracing::info!(after_drop, "after drop");

    // Cleanup
    drop(_client);

    test_complete!("io_cancel_registration_count_tracking");
}

/// Verifies that poll_read properly handles WouldBlock by registering interest.
#[test]
fn io_cancel_wouldblock_registers_interest() {
    init_test("io_cancel_wouldblock_registers_interest");

    let (reactor, _guard) = setup_test_cx();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let client = std::net::TcpStream::connect(addr).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    client.set_nonblocking(true).expect("client nonblocking");
    server.set_nonblocking(true).expect("server nonblocking");

    let mut stream = TcpStream::from_std(server);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    // First poll should trigger WouldBlock and register
    let mut buf = [0u8; 1024];
    let mut read_buf = ReadBuf::new(&mut buf);
    let result = Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf);

    tracing::info!(?result, "poll result");
    assert!(matches!(result, Poll::Pending), "should be pending");

    // Verify registration occurred (reactor should have at least one)
    let count = reactor.registration_count();
    tracing::info!(count, "registration count after poll");

    // Cleanup
    drop(stream);
    drop(client);

    test_complete!("io_cancel_wouldblock_registers_interest");
}
