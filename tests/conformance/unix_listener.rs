#![cfg(unix)]
//! Conformance tests for Unix domain socket listener implementation.
//!
//! This suite repairs the dormant Unix listener conformance module against the
//! current public `asupersync::net::unix` API. It covers filesystem-bound
//! listener lifecycle, accept cancellation, stale-path safety, stream ordering,
//! datagram atomicity, path-length errors, permission bits, and Linux abstract
//! namespace sockets.

use asupersync::Cx;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::unix::{UnixDatagram, UnixListener, UnixStream};
use futures_lite::future::block_on;
use std::fs;
use std::io::{self, ErrorKind};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;
use tempfile::tempdir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixListenerScenarioResult {
    scenario_id: &'static str,
    operation: &'static str,
    input_shape: &'static str,
    expected_result: &'static str,
    actual_result: String,
    cleanup_status: String,
    unsupported_reason: &'static str,
    verdict: &'static str,
    first_failure: String,
}

impl UnixListenerScenarioResult {
    fn pass(
        scenario_id: &'static str,
        operation: &'static str,
        input_shape: &'static str,
        cleanup_status: impl Into<String>,
    ) -> Self {
        Self {
            scenario_id,
            operation,
            input_shape,
            expected_result: "pass",
            actual_result: "pass".to_string(),
            cleanup_status: cleanup_status.into(),
            unsupported_reason: "",
            verdict: "pass",
            first_failure: String::new(),
        }
    }

    fn unsupported(
        scenario_id: &'static str,
        operation: &'static str,
        input_shape: &'static str,
        reason: &'static str,
    ) -> Self {
        Self {
            scenario_id,
            operation,
            input_shape,
            expected_result: "unsupported",
            actual_result: "unsupported".to_string(),
            cleanup_status: "not_applicable".to_string(),
            unsupported_reason: reason,
            verdict: "pass",
            first_failure: String::new(),
        }
    }

    fn fail(
        scenario_id: &'static str,
        operation: &'static str,
        input_shape: &'static str,
        failure: impl Into<String>,
    ) -> Self {
        let failure = failure.into();
        Self {
            scenario_id,
            operation,
            input_shape,
            expected_result: "pass",
            actual_result: "fail".to_string(),
            cleanup_status: "unknown".to_string(),
            unsupported_reason: "",
            verdict: "fail",
            first_failure: failure,
        }
    }
}

fn sanitize_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':' | '/') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn emit_conformance_log(result: &UnixListenerScenarioResult) {
    println!(
        "bead_id=asupersync-2qssae suite_id=unix_listener scenario_id={} adapter_kind=unix_domain_socket platform={} feature_flags=test-internals operation={} input_shape={} expected_result={} actual_result={} cleanup_status={} unsupported_reason={} verdict={} first_failure={}",
        result.scenario_id,
        std::env::consts::OS,
        sanitize_field(result.operation),
        sanitize_field(result.input_shape),
        sanitize_field(result.expected_result),
        sanitize_field(&result.actual_result),
        sanitize_field(&result.cleanup_status),
        sanitize_field(result.unsupported_reason),
        result.verdict,
        sanitize_field(&result.first_failure)
    );
}

fn connect_after_delay(path: impl AsRef<Path>) -> std::thread::JoinHandle<io::Result<UnixStream>> {
    let path = path.as_ref().to_path_buf();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(25));
        block_on(UnixStream::connect(path))
    })
}

fn assert_pass(result: UnixListenerScenarioResult) {
    emit_conformance_log(&result);
    assert_eq!(
        result.verdict, "pass",
        "{} failed: {}",
        result.scenario_id, result.first_failure
    );
}

fn listener_bind_accept_close_cleanup() -> UnixListenerScenarioResult {
    block_on(async {
        let dir = match tempdir() {
            Ok(dir) => dir,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_LISTENER_BIND_ACCEPT_CLOSE",
                    "bind_accept_close",
                    "tempdir_path",
                    format!("tempdir failed: {err}"),
                );
            }
        };
        let socket_path = dir.path().join("listener.sock");

        let listener = match UnixListener::bind(&socket_path).await {
            Ok(listener) => listener,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_LISTENER_BIND_ACCEPT_CLOSE",
                    "bind_accept_close",
                    "filesystem_socket",
                    format!("bind failed: {err}"),
                );
            }
        };

        match fs::symlink_metadata(&socket_path) {
            Ok(metadata) if metadata.file_type().is_socket() => {}
            Ok(metadata) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_LISTENER_BIND_ACCEPT_CLOSE",
                    "bind_accept_close",
                    "filesystem_socket",
                    format!("bound path was not a socket: {:?}", metadata.file_type()),
                );
            }
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_LISTENER_BIND_ACCEPT_CLOSE",
                    "bind_accept_close",
                    "filesystem_socket",
                    format!("metadata failed: {err}"),
                );
            }
        }

        let client = connect_after_delay(&socket_path);
        let accepted = listener.accept().await;
        let client = client
            .join()
            .map_err(|_| io::Error::other("client thread panicked"));

        if let Err(err) = accepted {
            return UnixListenerScenarioResult::fail(
                "UNIX_LISTENER_BIND_ACCEPT_CLOSE",
                "bind_accept_close",
                "filesystem_socket",
                format!("accept failed: {err}"),
            );
        }
        match client {
            Ok(Ok(_client_stream)) => {}
            Ok(Err(err)) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_LISTENER_BIND_ACCEPT_CLOSE",
                    "bind_accept_close",
                    "filesystem_socket",
                    format!("connect failed: {err}"),
                );
            }
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_LISTENER_BIND_ACCEPT_CLOSE",
                    "bind_accept_close",
                    "filesystem_socket",
                    format!("connect join failed: {err}"),
                );
            }
        }

        drop(listener);
        let removed_by_listener = !socket_path.exists();

        if removed_by_listener {
            UnixListenerScenarioResult::pass(
                "UNIX_LISTENER_BIND_ACCEPT_CLOSE",
                "bind_accept_close",
                "filesystem_socket",
                "listener_drop_removed_socket_file",
            )
        } else {
            UnixListenerScenarioResult::fail(
                "UNIX_LISTENER_BIND_ACCEPT_CLOSE",
                "bind_accept_close",
                "filesystem_socket",
                "listener drop did not remove its own socket file",
            )
        }
    })
}

fn stream_ordering_preservation() -> UnixListenerScenarioResult {
    block_on(async {
        let dir = match tempdir() {
            Ok(dir) => dir,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_STREAM_ORDERING",
                    "stream_ordering",
                    "filesystem_socket",
                    format!("tempdir failed: {err}"),
                );
            }
        };
        let socket_path = dir.path().join("ordering.sock");
        let listener = match UnixListener::bind(&socket_path).await {
            Ok(listener) => listener,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_STREAM_ORDERING",
                    "stream_ordering",
                    "filesystem_socket",
                    format!("bind failed: {err}"),
                );
            }
        };

        let client_path = socket_path.clone();
        let client = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            block_on(async move {
                let mut stream = UnixStream::connect(&client_path).await?;
                stream.write_all(b"FIRST").await?;
                stream.write_all(b"SECOND").await?;
                stream.write_all(b"THIRD").await?;
                stream.shutdown(std::net::Shutdown::Write)
            })
        });

        let (mut stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_STREAM_ORDERING",
                    "stream_ordering",
                    "filesystem_socket",
                    format!("accept failed: {err}"),
                );
            }
        };

        let mut buffer = Vec::new();
        if let Err(err) = stream.read_to_end(&mut buffer).await {
            return UnixListenerScenarioResult::fail(
                "UNIX_STREAM_ORDERING",
                "stream_ordering",
                "filesystem_socket",
                format!("read_to_end failed: {err}"),
            );
        }

        match client.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_STREAM_ORDERING",
                    "stream_ordering",
                    "filesystem_socket",
                    format!("client failed: {err}"),
                );
            }
            Err(_) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_STREAM_ORDERING",
                    "stream_ordering",
                    "filesystem_socket",
                    "client thread panicked",
                );
            }
        }

        if buffer == b"FIRSTSECONDTHIRD" {
            UnixListenerScenarioResult::pass(
                "UNIX_STREAM_ORDERING",
                "stream_ordering",
                "filesystem_socket",
                "tempdir_owned_cleanup",
            )
        } else {
            UnixListenerScenarioResult::fail(
                "UNIX_STREAM_ORDERING",
                "stream_ordering",
                "filesystem_socket",
                format!("unexpected stream payload: {:?}", buffer),
            )
        }
    })
}

fn datagram_atomicity() -> UnixListenerScenarioResult {
    block_on(async {
        let (mut sender, mut receiver) = match UnixDatagram::pair() {
            Ok(pair) => pair,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_DATAGRAM_ATOMICITY",
                    "datagram_atomicity",
                    "socket_pair",
                    format!("pair failed: {err}"),
                );
            }
        };
        let message = vec![0xCC; 4096];

        match sender.send(&message).await {
            Ok(sent) if sent == message.len() => {}
            Ok(sent) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_DATAGRAM_ATOMICITY",
                    "datagram_atomicity",
                    "socket_pair",
                    format!("partial send: {sent}"),
                );
            }
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_DATAGRAM_ATOMICITY",
                    "datagram_atomicity",
                    "socket_pair",
                    format!("send failed: {err}"),
                );
            }
        }

        let mut buffer = vec![0; message.len() + 16];
        match receiver.recv(&mut buffer).await {
            Ok(received) if received == message.len() && buffer[..received] == message => {
                UnixListenerScenarioResult::pass(
                    "UNIX_DATAGRAM_ATOMICITY",
                    "datagram_atomicity",
                    "socket_pair",
                    "no_filesystem_cleanup_needed",
                )
            }
            Ok(received) => UnixListenerScenarioResult::fail(
                "UNIX_DATAGRAM_ATOMICITY",
                "datagram_atomicity",
                "socket_pair",
                format!("unexpected receive length/content: {received}"),
            ),
            Err(err) => UnixListenerScenarioResult::fail(
                "UNIX_DATAGRAM_ATOMICITY",
                "datagram_atomicity",
                "socket_pair",
                format!("recv failed: {err}"),
            ),
        }
    })
}

fn stale_path_refused_without_unlinking() -> UnixListenerScenarioResult {
    block_on(async {
        let dir = match tempdir() {
            Ok(dir) => dir,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_STALE_PATH_REFUSED",
                    "stale_path_refused",
                    "regular_file_path",
                    format!("tempdir failed: {err}"),
                );
            }
        };
        let socket_path = dir.path().join("occupied.sock");
        if let Err(err) = fs::write(&socket_path, b"not a socket") {
            return UnixListenerScenarioResult::fail(
                "UNIX_STALE_PATH_REFUSED",
                "stale_path_refused",
                "regular_file_path",
                format!("seed write failed: {err}"),
            );
        }

        match UnixListener::bind(&socket_path).await {
            Ok(_listener) => UnixListenerScenarioResult::fail(
                "UNIX_STALE_PATH_REFUSED",
                "stale_path_refused",
                "regular_file_path",
                "bind unexpectedly succeeded over regular file",
            ),
            Err(err)
                if socket_path.exists()
                    && matches!(fs::read(&socket_path), Ok(contents) if contents == b"not a socket") =>
            {
                UnixListenerScenarioResult::pass(
                    "UNIX_STALE_PATH_REFUSED",
                    "stale_path_refused",
                    "regular_file_path",
                    format!(
                        "existing_file_preserved_error={}",
                        sanitize_field(&err.to_string())
                    ),
                )
            }
            Err(err) => UnixListenerScenarioResult::fail(
                "UNIX_STALE_PATH_REFUSED",
                "stale_path_refused",
                "regular_file_path",
                format!("bind failed but regular file changed or vanished: {err}"),
            ),
        }
    })
}

fn cancelled_accept_returns_interrupted() -> UnixListenerScenarioResult {
    block_on(async {
        let dir = match tempdir() {
            Ok(dir) => dir,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_ACCEPT_CANCELLED",
                    "accept_cancelled",
                    "filesystem_socket",
                    format!("tempdir failed: {err}"),
                );
            }
        };
        let socket_path = dir.path().join("cancel.sock");
        let listener = match UnixListener::bind(&socket_path).await {
            Ok(listener) => listener,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_ACCEPT_CANCELLED",
                    "accept_cancelled",
                    "filesystem_socket",
                    format!("bind failed: {err}"),
                );
            }
        };

        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let _guard = cx.set_current_restricted();

        match listener.accept().await {
            Err(err) if err.kind() == ErrorKind::Interrupted => UnixListenerScenarioResult::pass(
                "UNIX_ACCEPT_CANCELLED",
                "accept_cancelled",
                "filesystem_socket",
                "cancelled_before_accept_registration",
            ),
            Err(err) => UnixListenerScenarioResult::fail(
                "UNIX_ACCEPT_CANCELLED",
                "accept_cancelled",
                "filesystem_socket",
                format!("unexpected accept error: {err}"),
            ),
            Ok((_stream, _addr)) => UnixListenerScenarioResult::fail(
                "UNIX_ACCEPT_CANCELLED",
                "accept_cancelled",
                "filesystem_socket",
                "cancelled accept unexpectedly succeeded",
            ),
        }
    })
}

fn path_length_limit() -> UnixListenerScenarioResult {
    block_on(async {
        let dir = match tempdir() {
            Ok(dir) => dir,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_PATH_LENGTH_LIMIT",
                    "path_length_limit",
                    "long_filesystem_path",
                    format!("tempdir failed: {err}"),
                );
            }
        };
        let invalid_path = dir.path().join("a".repeat(200));

        match UnixListener::bind(&invalid_path).await {
            Ok(_listener) => UnixListenerScenarioResult::fail(
                "UNIX_PATH_LENGTH_LIMIT",
                "path_length_limit",
                "long_filesystem_path",
                format!(
                    "bind unexpectedly succeeded for path length {}",
                    invalid_path.to_string_lossy().len()
                ),
            ),
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::InvalidInput | ErrorKind::InvalidData | ErrorKind::Other
                ) || err.raw_os_error() == Some(libc::ENAMETOOLONG) =>
            {
                UnixListenerScenarioResult::pass(
                    "UNIX_PATH_LENGTH_LIMIT",
                    "path_length_limit",
                    "long_filesystem_path",
                    format!("rejected_error_kind={:?}", err.kind()),
                )
            }
            Err(err) => UnixListenerScenarioResult::fail(
                "UNIX_PATH_LENGTH_LIMIT",
                "path_length_limit",
                "long_filesystem_path",
                format!("unexpected error for long path: {err}"),
            ),
        }
    })
}

fn filesystem_permissions_honored() -> UnixListenerScenarioResult {
    block_on(async {
        let dir = match tempdir() {
            Ok(dir) => dir,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_SOCKET_PERMISSIONS",
                    "filesystem_permissions",
                    "filesystem_socket",
                    format!("tempdir failed: {err}"),
                );
            }
        };
        let socket_path = dir.path().join("permission.sock");
        let listener = match UnixListener::bind(&socket_path).await {
            Ok(listener) => listener,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_SOCKET_PERMISSIONS",
                    "filesystem_permissions",
                    "filesystem_socket",
                    format!("bind failed: {err}"),
                );
            }
        };

        let restrictive_mode = 0o600;
        if let Err(err) =
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(restrictive_mode))
        {
            return UnixListenerScenarioResult::fail(
                "UNIX_SOCKET_PERMISSIONS",
                "filesystem_permissions",
                "filesystem_socket",
                format!("chmod failed: {err}"),
            );
        }

        let actual_mode = match fs::metadata(&socket_path) {
            Ok(metadata) => metadata.permissions().mode() & 0o777,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_SOCKET_PERMISSIONS",
                    "filesystem_permissions",
                    "filesystem_socket",
                    format!("metadata failed: {err}"),
                );
            }
        };

        drop(listener);

        if actual_mode == restrictive_mode {
            UnixListenerScenarioResult::pass(
                "UNIX_SOCKET_PERMISSIONS",
                "filesystem_permissions",
                "filesystem_socket",
                format!("mode={actual_mode:o}"),
            )
        } else {
            UnixListenerScenarioResult::fail(
                "UNIX_SOCKET_PERMISSIONS",
                "filesystem_permissions",
                "filesystem_socket",
                format!("expected mode {restrictive_mode:o}, got {actual_mode:o}"),
            )
        }
    })
}

#[cfg(target_os = "linux")]
fn abstract_namespace_bind() -> UnixListenerScenarioResult {
    block_on(async {
        let name = format!(
            "asupersync_conformance_{}_{}",
            std::process::id(),
            "abstract"
        );
        let listener = match UnixListener::bind_abstract(name.as_bytes()).await {
            Ok(listener) => listener,
            Err(err) => {
                return UnixListenerScenarioResult::fail(
                    "UNIX_ABSTRACT_NAMESPACE",
                    "abstract_namespace_bind",
                    "linux_abstract_socket",
                    format!("bind_abstract failed: {err}"),
                );
            }
        };

        let client_name = name.clone();
        let client = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            block_on(UnixStream::connect_abstract(client_name.as_bytes()))
        });

        let accepted = listener.accept().await;
        let client = client
            .join()
            .map_err(|_| io::Error::other("client thread panicked"));

        match (accepted, client) {
            (Ok((_stream, peer_addr)), Ok(Ok(_client_stream)))
                if listener
                    .local_addr()
                    .is_ok_and(|addr| addr.as_pathname().is_none())
                    && peer_addr.as_pathname().is_none() =>
            {
                UnixListenerScenarioResult::pass(
                    "UNIX_ABSTRACT_NAMESPACE",
                    "abstract_namespace_bind",
                    "linux_abstract_socket",
                    "kernel_owned_no_filesystem_cleanup",
                )
            }
            (Ok((_stream, peer_addr)), Ok(Ok(_client_stream))) => UnixListenerScenarioResult::fail(
                "UNIX_ABSTRACT_NAMESPACE",
                "abstract_namespace_bind",
                "linux_abstract_socket",
                format!("unexpected pathname for abstract socket: {peer_addr:?}"),
            ),
            (Err(err), _) => UnixListenerScenarioResult::fail(
                "UNIX_ABSTRACT_NAMESPACE",
                "abstract_namespace_bind",
                "linux_abstract_socket",
                format!("accept failed: {err}"),
            ),
            (_, Ok(Err(err))) => UnixListenerScenarioResult::fail(
                "UNIX_ABSTRACT_NAMESPACE",
                "abstract_namespace_bind",
                "linux_abstract_socket",
                format!("connect_abstract failed: {err}"),
            ),
            (_, Err(err)) => UnixListenerScenarioResult::fail(
                "UNIX_ABSTRACT_NAMESPACE",
                "abstract_namespace_bind",
                "linux_abstract_socket",
                format!("connect thread failed: {err}"),
            ),
        }
    })
}

#[cfg(not(target_os = "linux"))]
fn abstract_namespace_bind() -> UnixListenerScenarioResult {
    UnixListenerScenarioResult::unsupported(
        "UNIX_ABSTRACT_NAMESPACE",
        "abstract_namespace_bind",
        "linux_abstract_socket",
        "abstract_namespace_requires_linux",
    )
}

pub fn run_unix_listener_conformance_tests() -> Vec<UnixListenerScenarioResult> {
    vec![
        listener_bind_accept_close_cleanup(),
        stream_ordering_preservation(),
        datagram_atomicity(),
        stale_path_refused_without_unlinking(),
        cancelled_accept_returns_interrupted(),
        path_length_limit(),
        filesystem_permissions_honored(),
        abstract_namespace_bind(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_listener_conformance_suite() {
        let results = run_unix_listener_conformance_tests();
        for result in results {
            assert_pass(result);
        }
    }

    #[test]
    fn unix_listener_bind_accept_close_cleanup() {
        assert_pass(listener_bind_accept_close_cleanup());
    }

    #[test]
    fn unix_stream_ordering_preservation() {
        assert_pass(stream_ordering_preservation());
    }

    #[test]
    fn unix_datagram_atomicity() {
        assert_pass(datagram_atomicity());
    }

    #[test]
    fn unix_stale_path_refused_without_unlinking() {
        assert_pass(stale_path_refused_without_unlinking());
    }

    #[test]
    fn unix_cancelled_accept_returns_interrupted() {
        assert_pass(cancelled_accept_returns_interrupted());
    }

    #[test]
    fn unix_path_length_limit() {
        assert_pass(path_length_limit());
    }

    #[test]
    fn unix_filesystem_permissions_honored() {
        assert_pass(filesystem_permissions_honored());
    }

    #[test]
    fn unix_abstract_namespace_bind() {
        assert_pass(abstract_namespace_bind());
    }
}
