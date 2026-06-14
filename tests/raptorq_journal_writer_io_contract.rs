//! Durable striped file-I/O contract for the RaptorQ trace journal
//! (br-asupersync-raptorq-leverage-3bb2pl.2): encode a checkpoint, write each
//! stripe to its own file via the crash-durable atomic writer, destroy one
//! stripe file (a lost failure domain), and confirm the epoch still recovers.

#![allow(missing_docs)]

use asupersync::config::EncodingConfig;
use asupersync::runtime::RuntimeBuilder;
use asupersync::trace::raptorq_journal::{latest_complete_epoch, scan_frames};
use asupersync::trace::raptorq_journal_writer::{
    DurableTraceJournal, DurableTraceJournalConfig, encode_and_serialize_epoch,
    read_epoch_manifest, read_epoch_stripes, stripe_file_name, write_epoch_manifest,
    write_epoch_stripes,
};
use tempfile::tempdir;

#[test]
fn striped_files_persist_and_recover_after_losing_a_stripe() {
    let dir = tempdir().expect("tempdir");
    let dir_path = dir.path().to_path_buf();
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");

    let recovered = runtime.block_on(runtime.handle().spawn(async move {
        let data = vec![0xCDu8; 600];
        let (stripes, manifest) =
            encode_and_serialize_epoch(77, &data, EncodingConfig::default(), 4, 3, 0)
                .expect("encode ok")
                .expect("nonzero stripes");

        let paths = write_epoch_stripes(&dir_path, 77, &stripes)
            .await
            .expect("write stripes");
        assert_eq!(paths.len(), 3);
        for path in &paths {
            assert!(
                path.exists(),
                "stripe file must exist after a durable write"
            );
        }

        // Read all stripes back -> the epoch is fully recoverable.
        let all = read_epoch_stripes(&dir_path, 77, 3)
            .await
            .expect("read all stripes");
        let (all_frames, _) = scan_frames(&all);
        assert_eq!(latest_complete_epoch(&all_frames, &[manifest]), Some(77));

        // Destroy one whole stripe file (a failure domain is lost).
        std::fs::remove_file(&paths[0]).expect("remove stripe 0");

        let survivors = read_epoch_stripes(&dir_path, 77, 3)
            .await
            .expect("read surviving stripes");
        let (frames, _) = scan_frames(&survivors);
        latest_complete_epoch(&frames, &[manifest]) == Some(77)
    }));

    assert!(
        recovered,
        "epoch must still recover after losing one of three stripe files"
    );
}

#[test]
fn manifest_persists_and_drives_recovery_purely_from_disk() {
    let dir = tempdir().expect("tempdir");
    let dir_path = dir.path().to_path_buf();
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");

    let ok = runtime.block_on(runtime.handle().spawn(async move {
        let data = vec![0x5Au8; 600];
        let (stripes, manifest) =
            encode_and_serialize_epoch(88, &data, EncodingConfig::default(), 4, 3, 0)
                .expect("encode ok")
                .expect("nonzero stripes");
        write_epoch_stripes(&dir_path, 88, &stripes)
            .await
            .expect("write stripes");
        write_epoch_manifest(&dir_path, manifest)
            .await
            .expect("write manifest");

        // Recover with nothing but what is on disk: the manifest record + stripes.
        let loaded = read_epoch_manifest(&dir_path, 88)
            .await
            .expect("read manifest")
            .expect("manifest present");
        assert_eq!(loaded, manifest);

        // A missing epoch's manifest is reported as absent, not an error.
        assert!(
            read_epoch_manifest(&dir_path, 999)
                .await
                .expect("read missing manifest")
                .is_none()
        );

        let survivors = read_epoch_stripes(&dir_path, 88, 3)
            .await
            .expect("read stripes");
        let (frames, _) = scan_frames(&survivors);
        latest_complete_epoch(&frames, &[loaded]) == Some(88)
    }));

    assert!(ok, "epoch must recover using the disk-persisted manifest");
}

#[test]
fn durable_trace_journal_handle_records_and_recovers() {
    let dir = tempdir().expect("tempdir");
    let dir_path = dir.path().to_path_buf();
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");

    let ok = runtime.block_on(runtime.handle().spawn(async move {
        let journal = DurableTraceJournal::new(DurableTraceJournalConfig {
            directory: dir_path.clone(),
            encoding: EncodingConfig::default(),
            repair_count: 4,
            stripe_count: 3,
        });

        let data = vec![0x11u8; 600];
        journal.record_epoch(55, &data).await.expect("record epoch");

        let recoverable_full = journal.epoch_recoverable(55).await.expect("recoverable");

        // Lose one stripe file (a failure domain) — still recoverable.
        std::fs::remove_file(dir_path.join(stripe_file_name(55, 0))).expect("remove stripe 0");
        let recoverable_after_loss = journal
            .epoch_recoverable(55)
            .await
            .expect("recoverable after loss");

        // An epoch never recorded (no manifest) is reported not-recoverable.
        let unknown = journal.epoch_recoverable(999).await.expect("unknown epoch");

        recoverable_full && recoverable_after_loss && !unknown
    }));

    assert!(
        ok,
        "DurableTraceJournal must record an epoch and report it recoverable through one stripe loss"
    );
}
