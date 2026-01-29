//! Integration tests for the io_uring reactor backend.
//!
//! These tests exercise real I/O using the `IoUringReactor` on Linux.
//! They verify: socket readiness, file I/O semantics, wake mechanism,
//! registration lifecycle, and cancellation during in-flight operations.
//!
//! Requires: Linux kernel 5.1+, feature `io-uring`.

#![cfg(all(target_os = "linux", feature = "io-uring"))]
#![allow(unsafe_code)]

use asupersync::runtime::reactor::{Events, Interest, IoUringReactor, Reactor, Token};
use std::io;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// =========================================================================
// Helpers
// =========================================================================

/// Wrapper to implement Source for std types.
struct FdSource {
    fd: std::os::fd::RawFd,
}

impl FdSource {
    fn from_raw(fd: std::os::fd::RawFd) -> Self {
        Self { fd }
    }
}

impl AsRawFd for FdSource {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd
    }
}

fn bind_ephemeral() -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

// =========================================================================
// Construction
// =========================================================================

#[test]
fn reactor_creates_successfully() {
    let reactor = IoUringReactor::new();
    assert!(reactor.is_ok(), "io_uring reactor should create on Linux 5.1+");
    let r = reactor.unwrap();
    assert!(r.is_empty());
    assert_eq!(r.registration_count(), 0);
}

// =========================================================================
// Registration lifecycle
// =========================================================================

#[test]
fn register_and_deregister_socket() {
    let reactor = IoUringReactor::new().unwrap();
    let listener = bind_ephemeral().unwrap();
    let source = FdSource::from_raw(listener.as_raw_fd());
    let token = Token::new(1);

    reactor
        .register(&source, token, Interest::READABLE)
        .expect("register should succeed");
    assert_eq!(reactor.registration_count(), 1);

    reactor.deregister(token).expect("deregister should succeed");
    assert_eq!(reactor.registration_count(), 0);
}

#[test]
fn duplicate_register_fails() {
    let reactor = IoUringReactor::new().unwrap();
    let listener = bind_ephemeral().unwrap();
    let source = FdSource::from_raw(listener.as_raw_fd());
    let token = Token::new(10);

    reactor
        .register(&source, token, Interest::READABLE)
        .expect("first register should succeed");

    let result = reactor.register(&source, token, Interest::READABLE);
    assert!(result.is_err(), "duplicate register should fail");
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::AlreadyExists);

    reactor.deregister(token).unwrap();
}

#[test]
fn deregister_unknown_token_fails() {
    let reactor = IoUringReactor::new().unwrap();
    let result = reactor.deregister(Token::new(999));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
}

#[test]
fn modify_interest() {
    let reactor = IoUringReactor::new().unwrap();
    let listener = bind_ephemeral().unwrap();
    let source = FdSource::from_raw(listener.as_raw_fd());
    let token = Token::new(20);

    reactor
        .register(&source, token, Interest::READABLE)
        .expect("register");
    reactor
        .modify(token, Interest::WRITABLE)
        .expect("modify should succeed");

    reactor.deregister(token).unwrap();
}

#[test]
fn modify_unknown_token_fails() {
    let reactor = IoUringReactor::new().unwrap();
    let result = reactor.modify(Token::new(999), Interest::READABLE);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
}

// =========================================================================
// Poll and readiness
// =========================================================================

#[test]
fn poll_returns_zero_with_no_registrations() {
    let reactor = IoUringReactor::new().unwrap();
    let mut events = Events::with_capacity(64);

    let count = reactor.poll(&mut events, Some(Duration::ZERO)).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn poll_detects_listener_readable_on_connect() {
    let reactor = IoUringReactor::new().unwrap();
    let listener = bind_ephemeral().unwrap();
    let addr = listener.local_addr().unwrap();
    let source = FdSource::from_raw(listener.as_raw_fd());
    let token = Token::new(100);

    reactor
        .register(&source, token, Interest::READABLE)
        .expect("register listener");

    // Connect from another thread to make the listener readable.
    let handle = thread::spawn(move || {
        let _client = TcpStream::connect(addr).expect("client connect");
    });

    // Poll — should detect readability.
    let mut events = Events::with_capacity(64);
    let mut found = false;
    for _ in 0..10 {
        let n = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .unwrap();
        if n > 0 {
            for event in &events {
                if event.token == token && event.is_readable() {
                    found = true;
                }
            }
            break;
        }
    }

    assert!(found, "should detect listener readable after client connect");

    handle.join().unwrap();
    reactor.deregister(token).unwrap();
}

#[test]
fn poll_detects_stream_writable() {
    let reactor = IoUringReactor::new().unwrap();
    let listener = bind_ephemeral().unwrap();
    let addr = listener.local_addr().unwrap();

    // Connect a client.
    let client = TcpStream::connect(addr).unwrap();
    client.set_nonblocking(true).unwrap();
    let _server = listener.accept().unwrap();

    let source = FdSource::from_raw(client.as_raw_fd());
    let token = Token::new(200);
    reactor
        .register(&source, token, Interest::WRITABLE)
        .expect("register client");

    let mut events = Events::with_capacity(64);
    let mut found = false;
    for _ in 0..10 {
        let n = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .unwrap();
        if n > 0 {
            for event in &events {
                if event.token == token && event.is_writable() {
                    found = true;
                }
            }
            break;
        }
    }

    assert!(
        found,
        "connected TCP socket should be writable immediately"
    );
    reactor.deregister(token).unwrap();
}

#[test]
fn poll_detects_stream_readable_after_write() {
    let reactor = IoUringReactor::new().unwrap();
    let listener = bind_ephemeral().unwrap();
    let addr = listener.local_addr().unwrap();

    let client = TcpStream::connect(addr).unwrap();
    client.set_nonblocking(true).unwrap();
    let (mut server, _) = listener.accept().unwrap();

    // Register client for readable.
    let source = FdSource::from_raw(client.as_raw_fd());
    let token = Token::new(300);
    reactor
        .register(&source, token, Interest::READABLE)
        .expect("register");

    // Write data from server side.
    server.write_all(b"hello io_uring").unwrap();
    server.flush().unwrap();

    // Poll should detect readable.
    let mut events = Events::with_capacity(64);
    let mut found = false;
    for _ in 0..10 {
        let n = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .unwrap();
        if n > 0 {
            for event in &events {
                if event.token == token && event.is_readable() {
                    found = true;
                }
            }
            break;
        }
    }

    assert!(found, "should detect readable after server writes data");
    reactor.deregister(token).unwrap();
}

// =========================================================================
// Socket send/recv roundtrip
// =========================================================================

#[test]
fn socket_send_recv_roundtrip_via_reactor() {
    let reactor = IoUringReactor::new().unwrap();
    let listener = bind_ephemeral().unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client = TcpStream::connect(addr).unwrap();
    client.set_nonblocking(true).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server.set_nonblocking(true).unwrap();

    // Register client for writable, server for readable.
    let client_src = FdSource::from_raw(client.as_raw_fd());
    let server_src = FdSource::from_raw(server.as_raw_fd());
    let client_token = Token::new(400);
    let server_token = Token::new(401);

    reactor
        .register(&client_src, client_token, Interest::WRITABLE)
        .unwrap();
    reactor
        .register(&server_src, server_token, Interest::READABLE)
        .unwrap();

    // Wait for client writable.
    let mut events = Events::with_capacity(64);
    let mut client_writable = false;
    for _ in 0..10 {
        reactor
            .poll(&mut events, Some(Duration::from_millis(50)))
            .unwrap();
        for event in &events {
            if event.token == client_token && event.is_writable() {
                client_writable = true;
            }
        }
        if client_writable {
            break;
        }
    }
    assert!(client_writable, "client should become writable");

    // Write data.
    let msg = b"io_uring roundtrip test";
    client.write_all(msg).unwrap();
    client.flush().unwrap();

    // Wait for server readable.
    let mut server_readable = false;
    for _ in 0..10 {
        reactor
            .poll(&mut events, Some(Duration::from_millis(50)))
            .unwrap();
        for event in &events {
            if event.token == server_token && event.is_readable() {
                server_readable = true;
            }
        }
        if server_readable {
            break;
        }
    }
    assert!(server_readable, "server should become readable after write");

    // Read data.
    let mut buf = [0u8; 128];
    let n = server.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], msg);

    reactor.deregister(client_token).unwrap();
    reactor.deregister(server_token).unwrap();
}

// =========================================================================
// Wake mechanism
// =========================================================================

#[test]
fn wake_interrupts_blocking_poll() {
    // Use Arc so the reactor can be shared across threads.
    let reactor = Arc::new(IoUringReactor::new().unwrap());
    let listener = bind_ephemeral().unwrap();
    let source = FdSource::from_raw(listener.as_raw_fd());
    let token = Token::new(500);

    reactor
        .register(&source, token, Interest::READABLE)
        .unwrap();

    // Spawn a thread that calls wake() after a short delay.
    let reactor_wake = Arc::clone(&reactor);
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        reactor_wake.wake().expect("wake should succeed");
    });

    // Poll with a long timeout — wake() should interrupt it early.
    let start = std::time::Instant::now();
    let mut events = Events::with_capacity(64);
    let _ = reactor.poll(&mut events, Some(Duration::from_secs(5)));
    let elapsed = start.elapsed();

    // Should return well before the 5-second timeout.
    assert!(
        elapsed < Duration::from_secs(2),
        "wake() should interrupt poll early, took {elapsed:?}"
    );

    handle.join().unwrap();
    reactor.deregister(token).unwrap();
}

#[test]
fn wake_without_registrations() {
    let reactor = IoUringReactor::new().unwrap();
    // wake() should succeed even with no registrations.
    reactor.wake().expect("wake should succeed with no registrations");
}

// =========================================================================
// Multiple registrations
// =========================================================================

#[test]
fn multiple_concurrent_registrations() {
    let reactor = IoUringReactor::new().unwrap();
    let mut listeners = Vec::new();
    let mut tokens = Vec::new();

    for i in 0..8 {
        let listener = bind_ephemeral().unwrap();
        let source = FdSource::from_raw(listener.as_raw_fd());
        let token = Token::new(600 + i);
        reactor
            .register(&source, token, Interest::READABLE)
            .unwrap();
        tokens.push(token);
        listeners.push(listener);
    }

    assert_eq!(reactor.registration_count(), 8);

    // Connect to all listeners to make them readable.
    let mut clients = Vec::new();
    for listener in &listeners {
        let addr = listener.local_addr().unwrap();
        clients.push(TcpStream::connect(addr).unwrap());
    }

    // Poll should find at least some events.
    let mut events = Events::with_capacity(64);
    let mut total_events = 0;
    for _ in 0..20 {
        let n = reactor
            .poll(&mut events, Some(Duration::from_millis(50)))
            .unwrap();
        total_events += n;
        if total_events >= 8 {
            break;
        }
    }

    assert!(
        total_events >= 8,
        "should get readability for all 8 listeners, got {total_events}"
    );

    // Deregister all.
    for token in &tokens {
        reactor.deregister(*token).unwrap();
    }
    assert!(reactor.is_empty());
}

// =========================================================================
// Cancellation / deregister during poll
// =========================================================================

#[test]
fn deregister_cancels_in_flight_poll() {
    let reactor = IoUringReactor::new().unwrap();
    let listener = bind_ephemeral().unwrap();
    let source = FdSource::from_raw(listener.as_raw_fd());
    let token = Token::new(700);

    reactor
        .register(&source, token, Interest::READABLE)
        .unwrap();

    // Deregister before any event fires (simulates cancellation).
    reactor.deregister(token).unwrap();
    assert!(reactor.is_empty());

    // Poll should not return events for the deregistered token.
    let mut events = Events::with_capacity(64);
    let n = reactor
        .poll(&mut events, Some(Duration::from_millis(50)))
        .unwrap();
    for event in &events {
        assert_ne!(
            event.token, token,
            "should not get events for deregistered token"
        );
    }

    // n could be 0 or could include REMOVE completions — either is fine.
    let _ = n;
}

#[test]
fn deregister_during_active_io() {
    let reactor = IoUringReactor::new().unwrap();
    let listener = bind_ephemeral().unwrap();
    let addr = listener.local_addr().unwrap();
    let source = FdSource::from_raw(listener.as_raw_fd());
    let token = Token::new(800);

    reactor
        .register(&source, token, Interest::READABLE)
        .unwrap();

    // Connect from another thread — this will make the listener readable.
    let handle = thread::spawn(move || {
        let _client = TcpStream::connect(addr).expect("client connect");
        // Keep client alive briefly.
        thread::sleep(Duration::from_millis(100));
    });

    // Brief delay to let the connection start.
    thread::sleep(Duration::from_millis(20));

    // Deregister while I/O may be in-flight.
    reactor.deregister(token).unwrap();
    assert!(reactor.is_empty());

    // Poll should be safe — no panics, no events for deregistered token.
    let mut events = Events::with_capacity(64);
    let _ = reactor.poll(&mut events, Some(Duration::from_millis(100)));
    for event in &events {
        assert_ne!(
            event.token, token,
            "deregistered token should not appear in events"
        );
    }

    handle.join().unwrap();
}

// =========================================================================
// File I/O (pipe-based, since regular files aren't pollable)
// =========================================================================

#[test]
fn pipe_read_write_via_reactor() {
    let reactor = IoUringReactor::new().unwrap();

    // Create a pipe.
    let (read_fd, write_fd) = {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        assert_eq!(ret, 0, "pipe2 should succeed");
        (fds[0], fds[1])
    };

    // Register read end for readable.
    let read_source = FdSource::from_raw(read_fd);
    let read_token = Token::new(900);
    reactor
        .register(&read_source, read_token, Interest::READABLE)
        .unwrap();

    // Write data to the pipe.
    let msg = b"pipe via io_uring";
    let written = unsafe {
        libc::write(
            write_fd,
            msg.as_ptr().cast::<libc::c_void>(),
            msg.len(),
        )
    };
    assert_eq!(written as usize, msg.len());

    // Poll should detect readable.
    let mut events = Events::with_capacity(64);
    let mut found = false;
    for _ in 0..10 {
        let n = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .unwrap();
        if n > 0 {
            for event in &events {
                if event.token == read_token && event.is_readable() {
                    found = true;
                }
            }
            if found {
                break;
            }
        }
    }
    assert!(found, "pipe read end should become readable");

    // Read the data.
    let mut buf = [0u8; 128];
    let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    assert!(n > 0);
    assert_eq!(&buf[..n as usize], msg);

    reactor.deregister(read_token).unwrap();
    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
}

#[test]
fn pipe_hangup_detected() {
    let reactor = IoUringReactor::new().unwrap();

    let (read_fd, write_fd) = {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        assert_eq!(ret, 0);
        (fds[0], fds[1])
    };

    let read_source = FdSource::from_raw(read_fd);
    let token = Token::new(950);
    reactor
        .register(&read_source, token, Interest::READABLE)
        .unwrap();

    // Close write end — should cause HUP on read end.
    unsafe {
        libc::close(write_fd);
    }

    let mut events = Events::with_capacity(64);
    let mut found_readable_or_hup = false;
    for _ in 0..10 {
        let n = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .unwrap();
        if n > 0 {
            for event in &events {
                if event.token == token && (event.is_readable() || event.is_hangup()) {
                    found_readable_or_hup = true;
                }
            }
            if found_readable_or_hup {
                break;
            }
        }
    }

    assert!(
        found_readable_or_hup,
        "closing write end should trigger readable or HUP on read end"
    );

    reactor.deregister(token).unwrap();
    unsafe {
        libc::close(read_fd);
    }
}

// =========================================================================
// Timeout behavior
// =========================================================================

#[test]
fn poll_with_zero_timeout_returns_immediately() {
    let reactor = IoUringReactor::new().unwrap();
    let listener = bind_ephemeral().unwrap();
    let source = FdSource::from_raw(listener.as_raw_fd());
    let token = Token::new(1000);

    reactor
        .register(&source, token, Interest::READABLE)
        .unwrap();

    let start = std::time::Instant::now();
    let mut events = Events::with_capacity(64);
    let _ = reactor.poll(&mut events, Some(Duration::ZERO));
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(100),
        "zero timeout should return immediately, took {elapsed:?}"
    );

    reactor.deregister(token).unwrap();
}

#[test]
fn poll_respects_timeout_duration() {
    let reactor = IoUringReactor::new().unwrap();
    let listener = bind_ephemeral().unwrap();
    let source = FdSource::from_raw(listener.as_raw_fd());
    let token = Token::new(1100);

    reactor
        .register(&source, token, Interest::READABLE)
        .unwrap();

    let start = std::time::Instant::now();
    let mut events = Events::with_capacity(64);
    let _ = reactor.poll(&mut events, Some(Duration::from_millis(100)));
    let elapsed = start.elapsed();

    // Should block for at least ~80ms (allowing some scheduling jitter).
    assert!(
        elapsed >= Duration::from_millis(50),
        "should block near the timeout duration, elapsed {elapsed:?}"
    );
    // Should not block much longer than the timeout.
    assert!(
        elapsed < Duration::from_secs(2),
        "should not block much longer than timeout, elapsed {elapsed:?}"
    );

    reactor.deregister(token).unwrap();
}

// =========================================================================
// Edge: re-arming after event delivery
// =========================================================================

#[test]
fn events_are_rearmed_automatically() {
    let reactor = IoUringReactor::new().unwrap();
    let listener = bind_ephemeral().unwrap();
    let addr = listener.local_addr().unwrap();
    let source = FdSource::from_raw(listener.as_raw_fd());
    let token = Token::new(1200);

    reactor
        .register(&source, token, Interest::READABLE)
        .unwrap();

    // First connection.
    let _client1 = TcpStream::connect(addr).unwrap();

    let mut events = Events::with_capacity(64);
    let mut found = false;
    for _ in 0..10 {
        let n = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .unwrap();
        if n > 0 {
            for event in &events {
                if event.token == token {
                    found = true;
                }
            }
            break;
        }
    }
    assert!(found, "first connection should be detected");

    // Accept the first connection.
    let _accepted1 = listener.accept();

    // Second connection — re-arming should allow us to see this.
    let _client2 = TcpStream::connect(addr).unwrap();

    let mut found2 = false;
    for _ in 0..10 {
        let n = reactor
            .poll(&mut events, Some(Duration::from_millis(100)))
            .unwrap();
        if n > 0 {
            for event in &events {
                if event.token == token {
                    found2 = true;
                }
            }
            break;
        }
    }
    assert!(
        found2,
        "second connection should be detected (re-arming works)"
    );

    reactor.deregister(token).unwrap();
}
