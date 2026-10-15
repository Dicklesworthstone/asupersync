#![allow(missing_docs)]
#![cfg(unix)]
//! `UnixStream` integration tests for the ancillary-data and peer-credential
//! surface, which has no existing `tests/*.rs` coverage:
//!   - `fd_passing_round_trip_via_scm_rights`: an open file descriptor is sent
//!     over a connected pair with `send_with_ancillary` (SCM_RIGHTS) and the
//!     received descriptor is an independent, readable dup of the original.
//!   - `peer_cred_on_pair_reports_this_process`: `peer_cred` reports consistent
//!     credentials on both ends of a `socketpair` (and, on Linux, this very
//!     process's pid).
//!
//! Real Unix domain stream sockets (`UnixStream::pair`) and a real on-disk file,
//! no mocks. The receive follows the send on the connected pair, so the first
//! poll is `Ready` (no reactor parking).

use asupersync::net::unix::{AncillaryMessage, SocketAncillary, UnixStream};
use futures_lite::future::block_on;
use std::io::{self, Read};
use std::os::unix::io::{AsRawFd, FromRawFd};
use tempfile::TempDir;

/// Pass an open file descriptor over a connected `UnixStream` pair via
/// `SCM_RIGHTS` and prove the received descriptor reads the same file.
#[test]
#[allow(unsafe_code)] // from_raw_fd: take ownership of the descriptor passed over the socket
fn fd_passing_round_trip_via_scm_rights() {
    let result = block_on(async {
        let (tx, rx) = UnixStream::pair()?;

        let dir = TempDir::new()?;
        let path = dir.path().join("passed.txt");
        let body = b"passed-through-scm-rights";
        std::fs::write(&path, body)?;
        let file = std::fs::File::open(&path)?;

        // Send the file's fd alongside a small payload.
        let mut send_anc = SocketAncillary::new(128);
        assert!(
            send_anc.add_fds(&[file.as_raw_fd()]),
            "one fd must fit in a 128-byte ancillary buffer"
        );
        let payload = b"fd";
        let n = tx.send_with_ancillary(payload, &mut send_anc).await?;
        assert_eq!(n, payload.len(), "the whole payload is sent");

        // Receive the payload and the control message.
        let mut buf = [0u8; 16];
        let mut recv_anc = SocketAncillary::new(128);
        let m = rx.recv_with_ancillary(&mut buf, &mut recv_anc).await?;
        assert_eq!(&buf[..m], payload, "payload bytes round-trip");
        assert!(
            !recv_anc.is_truncated(),
            "a 128-byte ancillary buffer holds one fd without MSG_CTRUNC"
        );

        // Exactly one descriptor should arrive via SCM_RIGHTS. `AncillaryMessage`
        // has a single variant, so the bind is irrefutable.
        let mut received = Vec::new();
        for msg in recv_anc.messages() {
            let AncillaryMessage::ScmRights(fds) = msg;
            received.extend(fds);
        }
        assert_eq!(received.len(), 1, "exactly one fd was passed");

        // The received fd is an independent, usable dup of the original open
        // file: take ownership (closed on drop) and read it back.
        let mut received_file = unsafe { std::fs::File::from_raw_fd(received[0]) };
        let mut contents = String::new();
        received_file.read_to_string(&mut contents)?;
        assert_eq!(
            contents.as_bytes(),
            body,
            "the received fd reads the original file's bytes"
        );

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "fd-passing round trip should succeed: {result:?}"
    );
}

/// `peer_cred` returns consistent credentials on both ends of a `socketpair`
/// (both were created by this process), and on Linux reports this process's pid.
#[test]
fn peer_cred_on_pair_reports_this_process() {
    let result = block_on(async {
        let (a, b) = UnixStream::pair()?;

        let ca = a.peer_cred()?;
        let cb = b.peer_cred()?;

        assert_eq!(ca.uid, cb.uid, "both ends observe the same peer uid");
        assert_eq!(ca.gid, cb.gid, "both ends observe the same peer gid");

        // On Linux, SO_PEERCRED yields the peer's pid; for a socketpair created
        // by this process, that is our own pid.
        #[cfg(target_os = "linux")]
        {
            let me = i32::try_from(std::process::id()).expect("process id fits pid_t");
            assert_eq!(ca.pid, Some(me), "peer pid is this process");
            assert_eq!(cb.pid, ca.pid, "both ends agree on the peer pid");
        }

        Ok::<_, io::Error>(())
    });

    assert!(
        result.is_ok(),
        "peer_cred on a pair should succeed: {result:?}"
    );
}
