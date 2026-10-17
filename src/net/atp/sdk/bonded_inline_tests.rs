    use super::*;
    use crate::runtime::{Runtime, RuntimeBuilder};
    use std::sync::mpsc as std_mpsc;
    use std::thread;

    fn build_test_runtime() -> Runtime {
        RuntimeBuilder::multi_thread()
            .worker_threads(2)
            .enable_platform_reactor(true)
            .build()
            .expect("bonded sdk test runtime")
    }

    fn bonded_sdk_tmp(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!(
            "atp_sdk_bonded_{label}_{}_{nanos}",
            std::process::id()
        ))
    }

    fn bonded_sdk_payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect()
    }

    fn loopback_listen() -> SocketAddr {
        "127.0.0.1:0".parse().expect("loopback listen addr")
    }

    /// (a)-(c): drive the receiver through the SDK handle (spawn + live
    /// progress) and two donor legs through the SDK `run()` builder, asserting a
    /// byte-identical commit, both donors enrolled + contributing, and live
    /// progress with per-donor ingress + aggregate symbols + blocks_remaining
    /// reaching 0 + a Completed terminal snapshot.
    #[test]
    fn bonded_sdk_two_donor_loopback_reports_progress_and_commits() {
        let root = bonded_sdk_tmp("two_donor_progress");
        let donor_a_dir = root.join("donor-a");
        let donor_b_dir = root.join("donor-b");
        let recv_copy_dir = root.join("recv-copy");
        let dst_dir = root.join("dst");
        for dir in [&donor_a_dir, &donor_b_dir, &recv_copy_dir, &dst_dir] {
            std::fs::create_dir_all(dir).expect("create e2e dir");
        }
        let payload = bonded_sdk_payload(200_003);
        for dir in [&donor_a_dir, &donor_b_dir, &recv_copy_dir] {
            std::fs::write(dir.join("payload.bin"), &payload).expect("write e2e payload");
        }

        type ReceiverOutput = Result<(BondedReceiveReport, Vec<BondedTransferProgress>), String>;
        let (ready_tx, ready_rx) = std_mpsc::channel::<SocketAddr>();
        let receiver = {
            let recv_source = recv_copy_dir.join("payload.bin");
            let dest = dst_dir.clone();
            thread::spawn(move || -> ReceiverOutput {
                let runtime = build_test_runtime();
                runtime.block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().expect("bonded sdk receiver cx");
                    let mut handle = match BondedTransfer::receive(dest, recv_source)
                        .expect_donors(2)
                        .listen(loopback_listen())
                        .udp_bind("127.0.0.1")
                        .allow_unauthenticated_lab(true)
                        .max_block_size(64 * 1024)
                        .accept_timeout(Duration::from_secs(30))
                        .spawn(&cx)
                    {
                        AtpOutcome::Ok(handle) => handle,
                        AtpOutcome::Err(err) => return Err(format!("spawn error: {err:?}")),
                        AtpOutcome::Cancelled(reason) => {
                            return Err(format!("spawn cancelled: {reason:?}"));
                        }
                        AtpOutcome::Panicked(payload) => {
                            return Err(format!("spawn panicked: {payload:?}"));
                        }
                    };
                    let control = handle
                        .control_addr()
                        .await
                        .ok_or_else(|| "receiver never bound its control listener".to_string())?;
                    ready_tx
                        .send(control)
                        .map_err(|_| "send bonded control addr".to_string())?;
                    let mut snapshots = Vec::new();
                    while let Some(snapshot) = handle.next_progress().await {
                        snapshots.push(snapshot);
                    }
                    match handle.wait_for_completion().await {
                        AtpOutcome::Ok(report) => Ok((report, snapshots)),
                        other => Err(format!("receiver did not commit: {other:?}")),
                    }
                }))
            })
        };
        let control = ready_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("bonded receiver bound its control listener");

        let spawn_donor = |source: PathBuf| {
            thread::spawn(move || -> Result<BondedDonateReport, String> {
                let runtime = build_test_runtime();
                runtime.block_on(runtime.handle().spawn(async move {
                    let cx = Cx::current().expect("bonded sdk donor cx");
                    match BondedTransfer::donate(source, control)
                        .allow_unauthenticated_lab(true)
                        .max_block_size(64 * 1024)
                        .accept_timeout(Duration::from_secs(30))
                        .run(&cx)
                        .await
                    {
                        AtpOutcome::Ok(BondedReport::Donate(report)) => Ok(report),
                        other => Err(format!("donor failed: {other:?}")),
                    }
                }))
            })
        };
        let donor_a = spawn_donor(donor_a_dir.join("payload.bin"));
        let donor_b = spawn_donor(donor_b_dir.join("payload.bin"));

        let report_a = donor_a
            .join()
            .expect("donor A thread")
            .expect("donor A succeeds");
        let report_b = donor_b
            .join()
            .expect("donor B thread")
            .expect("donor B succeeds");
        let (report, snapshots) = receiver
            .join()
            .expect("receiver thread")
            .expect("bonded sdk receive commits");

        // (a) byte-identical commit through the SDK.
        assert!(report.committed, "bonded receive must commit: {report:?}");
        assert_eq!(report.bytes_received, payload.len() as u64);
        assert_eq!(report.files, 1);
        assert_eq!(report.enrolled_donors, 2);
        let received = std::fs::read(dst_dir.join("payload.bin")).expect("read committed file");
        assert_eq!(received, payload, "commit must be byte-identical");

        // (b) both donors enrolled with distinct identities and contributed.
        assert_ne!(report_a.donor_index, report_b.donor_index);
        assert_eq!(report_a.donor_count, 2);
        assert_eq!(report_b.donor_count, 2);
        assert!(report_a.receipt.committed && report_b.receipt.committed);
        assert_eq!(
            report.donor_ingress.len(),
            2,
            "both donors must appear in terminal ingress: {:?}",
            report.donor_ingress
        );
        for (donor_index, stats) in &report.donor_ingress {
            assert!(
                stats.symbols_accepted > 0,
                "donor {donor_index} must contribute accepted symbols: {stats:?}"
            );
        }

        // (c) live progress: per-donor ingress + aggregate symbols + blocks
        // remaining reaching 0 + a Completed terminal snapshot.
        assert!(
            !snapshots.is_empty(),
            "receiver must emit at least one live progress snapshot"
        );
        let completed = snapshots
            .iter()
            .rev()
            .find(|snapshot| snapshot.is_complete())
            .expect("a Completed terminal snapshot must be observed");
        assert_eq!(completed.phase, TransferPhase::Completed);
        assert_eq!(
            completed.blocks_remaining, 0,
            "blocks_remaining must reach 0: {completed:?}"
        );
        assert!(completed.blocks_total >= 1);
        assert!(
            completed.symbols_accepted > 0,
            "aggregate symbols_accepted must be positive: {completed:?}"
        );
        assert!((completed.progress_percent() - 100.0).abs() < f64::EPSILON);
        assert_eq!(completed.transfer_id, report.transfer_id);

        let with_donors = snapshots
            .iter()
            .find(|snapshot| !snapshot.donor_ingress.is_empty())
            .expect("a snapshot carrying per-donor ingress must be observed");
        assert!(
            with_donors
                .donor_ingress
                .iter()
                .any(|(_, stats)| stats.symbols_accepted > 0),
            "a live snapshot must carry a contributing donor: {:?}",
            with_donors.donor_ingress
        );
    }

    /// (d) cancel-correctness: spawn a receiver waiting for donors, cancel it
    /// through the handle, and assert it unwinds cleanly (no hang, no commit).
    #[test]
    fn bonded_sdk_receiver_cancel_unwinds_clean() {
        let root = bonded_sdk_tmp("cancel");
        let recv_copy_dir = root.join("recv-copy");
        let dst_dir = root.join("dst");
        for dir in [&recv_copy_dir, &dst_dir] {
            std::fs::create_dir_all(dir).expect("create cancel dir");
        }
        std::fs::write(
            recv_copy_dir.join("payload.bin"),
            bonded_sdk_payload(96_007),
        )
        .expect("write cancel payload");

        let committed_path = dst_dir.join("payload.bin");
        let runtime = build_test_runtime();
        let outcome = runtime.block_on(runtime.handle().spawn(async move {
            let cx = Cx::current().expect("bonded sdk cancel cx");
            let mut handle =
                match BondedTransfer::receive(dst_dir, recv_copy_dir.join("payload.bin"))
                    .expect_donors(2)
                    .listen(loopback_listen())
                    .udp_bind("127.0.0.1")
                    .allow_unauthenticated_lab(true)
                    .max_block_size(64 * 1024)
                    .accept_timeout(Duration::from_secs(30))
                    .spawn(&cx)
                {
                    AtpOutcome::Ok(handle) => handle,
                    other => panic!(
                        "bonded receiver spawn must succeed: {}",
                        outcome_label(&other)
                    ),
                };
            // Wait until the receiver has bound + entered its donor-accept wait,
            // then cancel: no donors will ever connect.
            let bound = handle.control_addr().await;
            assert!(bound.is_some(), "receiver must bind before cancel");
            let cancel = handle.cancel().await;
            let report = handle.wait_for_completion().await;
            (cancel, report)
        }));

        let (cancel, report) = outcome;
        assert!(
            matches!(cancel, AtpOutcome::Ok(())),
            "cancel request must succeed"
        );
        // A cancelled receiver unwinds clean: the cancellation surfaces as
        // Cancelled (explicit checkpoint or the poll_accept interrupt mapped to
        // Cancelled) — never a committed Ok.
        match report {
            AtpOutcome::Cancelled(_) => {}
            AtpOutcome::Err(_) => {}
            other => panic!("cancelled receiver must unwind clean, got {other:?}"),
        }
        assert!(
            !committed_path.exists(),
            "a cancelled bonded transfer must commit nothing"
        );
    }

    /// Small helper so a spawn-failure panic can name the outcome without
    /// requiring `Debug` on the handle inside the `Ok` arm.
    fn outcome_label(outcome: &AtpOutcome<BondedReceiveHandle>) -> String {
        match outcome {
            AtpOutcome::Ok(_) => "ok".to_string(),
            AtpOutcome::Err(err) => format!("err: {err:?}"),
            AtpOutcome::Cancelled(reason) => format!("cancelled: {reason:?}"),
            AtpOutcome::Panicked(payload) => format!("panicked: {payload:?}"),
        }
    }

    #[test]
    fn bonded_transfer_defaults_match_cli() {
        let receive = BondedTransfer::receive("/dst", "/src");
        assert_eq!(receive.listen.port(), DEFAULT_BONDED_CONTROL_PORT);
        assert!(receive.listen.ip().is_unspecified());
        assert_eq!(receive.expect_donors, 1);
        assert_eq!(receive.peer_id, "atp-bond-receiver");
        assert_eq!(receive.max_block_size, DEFAULT_BONDED_MAX_BLOCK_SIZE);
        assert!(receive.symbol_size.is_none());
        assert_eq!(receive.effective_symbol_size(), DEFAULT_SYMBOL_SIZE);

        // Unauthenticated lab config resolves with no descriptor key id.
        let lab = BondedTransfer::receive("/dst", "/src").allow_unauthenticated_lab(true);
        assert!(lab.build_config().is_ok());
        assert_eq!(lab.resolved_auth_key_id().expect("auth id"), None);

        // A valid high-entropy key + the lab flag conflict; the same key alone
        // yields a stable fingerprint.
        const VALID_KEY_HEX: &str =
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let conflict = BondedTransfer::receive("/dst", "/src")
            .auth_key_hex(VALID_KEY_HEX)
            .allow_unauthenticated_lab(true);
        assert!(conflict.build_config().is_err());

        let keyed = BondedTransfer::receive("/dst", "/src").auth_key_hex(VALID_KEY_HEX);
        let key_id = keyed.resolved_auth_key_id().expect("auth id");
        assert!(
            key_id
                .as_deref()
                .is_some_and(|id| id.starts_with("rq-auth-sha256:")),
            "auth key id must be a stable fingerprint: {key_id:?}"
        );

        // Missing auth with no lab opt-out fails closed.
        assert!(
            BondedTransfer::receive("/dst", "/src")
                .build_config()
                .is_err()
        );
    }

    #[test]
    fn bonded_progress_percent_is_block_ratio() {
        let mut progress = BondedTransferProgress {
            transfer_id: "t".to_string(),
            symbols_accepted: 0,
            bytes_total: 0,
            blocks_total: 4,
            blocks_remaining: 4,
            feedback_rounds: 0,
            reallocated_repair_windows: 0,
            enrolled_donors: 0,
            donor_ingress: Vec::new(),
            phase: TransferPhase::DataTransfer,
        };
        assert!((progress.progress_percent() - 0.0).abs() < f64::EPSILON);
        assert!(!progress.is_complete());
        progress.blocks_remaining = 1;
        assert!((progress.progress_percent() - 75.0).abs() < f64::EPSILON);
        progress.blocks_remaining = 0;
        progress.phase = TransferPhase::Completed;
        assert!((progress.progress_percent() - 100.0).abs() < f64::EPSILON);
        assert!(progress.is_complete());
    }
