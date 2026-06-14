//! Durable striped file-I/O contract for the RaptorQ trace journal
//! (br-asupersync-raptorq-leverage-3bb2pl.2): encode a checkpoint, write each
//! stripe to its own file via the crash-durable atomic writer, destroy one
//! stripe file (a lost failure domain), and confirm the epoch still recovers.

#![allow(missing_docs)]

use asupersync::config::EncodingConfig;
use asupersync::runtime::RuntimeBuilder;
use asupersync::trace::raptorq_journal::{ObjectParamsRecord, latest_complete_epoch, scan_frames};
use asupersync::trace::raptorq_journal_writer::{
    DurableJournalError, DurableTraceJournal, DurableTraceJournalConfig,
    encode_and_serialize_epoch, read_epoch_manifest, read_epoch_stripes, stripe_file_name,
    write_epoch_manifest, write_epoch_stripes,
};
use tempfile::tempdir;

/// Varied (non-constant) test payload so byte-exact recovery is meaningful — a
/// constant fill would "recover" trivially.
fn varied_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect()
}

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

#[test]
fn journal_discovers_epochs_and_finds_latest_recoverable() {
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

        for epoch in [10u64, 20, 30] {
            journal
                .record_epoch(epoch, &vec![0x22u8; 600])
                .await
                .expect("record epoch");
        }

        let discovered = journal.recorded_epochs().await.expect("discover epochs");
        assert_eq!(discovered, vec![10, 20, 30]);
        let latest = journal
            .latest_recoverable_epoch()
            .await
            .expect("latest recoverable");
        assert_eq!(latest, Some(30));

        // Damage the newest epoch: remove two of its three stripe files so fewer
        // than K' symbols survive -> it drops out of the recoverable set.
        std::fs::remove_file(dir_path.join(stripe_file_name(30, 0))).expect("remove 30/0");
        std::fs::remove_file(dir_path.join(stripe_file_name(30, 1))).expect("remove 30/1");

        let latest_after = journal
            .latest_recoverable_epoch()
            .await
            .expect("latest recoverable after damage");
        latest_after == Some(20)
    }));

    assert!(
        ok,
        "journal must discover epochs and fall back to the latest still-recoverable one"
    );
}

#[test]
fn recover_epoch_reconstructs_original_bytes_through_stripe_loss() {
    // AC1/AC5: the journal must reconstruct the EXACT original checkpoint bytes
    // from the surviving stripes (real RaptorQ decode), not merely confirm that
    // enough symbols survived — including after losing a whole failure domain.
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

        let data = varied_payload(600);
        journal.record_epoch(42, &data).await.expect("record epoch");

        // Full recovery decodes the exact original bytes.
        let full = journal.recover_epoch(42).await.expect("recover full");
        assert_eq!(
            full, data,
            "full recovery must reproduce the original bytes"
        );

        // Lose one whole stripe file (a failure domain) — still byte-exact.
        std::fs::remove_file(dir_path.join(stripe_file_name(42, 0))).expect("remove stripe 0");
        let after_loss = journal
            .recover_epoch(42)
            .await
            .expect("recover after losing a stripe");
        after_loss == data
    }));

    assert!(
        ok,
        "recover_epoch must reconstruct the exact original bytes after losing one of three stripes"
    );
}

#[test]
fn recover_epoch_without_params_record_reports_missing_params() {
    // An epoch with no persisted params record cannot be byte-decoded; recovery
    // surfaces a typed MissingParams error rather than guessing.
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
        matches!(
            journal.recover_epoch(999).await,
            Err(DurableJournalError::MissingParams)
        )
    }));

    assert!(
        ok,
        "recovering an unrecorded epoch must report MissingParams"
    );
}

#[test]
fn object_params_record_roundtrips_and_detects_corruption() {
    // Pure on-disk record contract: encode→decode is identity; a flipped byte is
    // caught by the CRC; the block layout matches the decoder's planner.
    let record = ObjectParamsRecord {
        epoch: 7,
        object_size: 600,
        symbol_size: 256,
        max_block_size: 1024 * 1024,
    };
    let mut bytes = record.encode().to_vec();
    assert_eq!(ObjectParamsRecord::decode(&bytes).expect("decode"), record);

    // 600 bytes / 256 = ceil 3 symbols, single block under a 1 MiB block size.
    assert_eq!(record.block_layout(), (1, 3));

    // Corrupt a payload byte -> CRC mismatch.
    bytes[14] ^= 0xFF;
    assert!(ObjectParamsRecord::decode(&bytes).is_err());
}

#[test]
fn recover_latest_returns_newest_recoverable_bytes_after_damage() {
    // The one-call recovery entry point: given only a directory, restore the
    // newest checkpoint that still decodes. Damaging the newest epoch falls back
    // to the previous one, decoded byte-exact.
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

        let data30 = varied_payload(700);
        journal
            .record_epoch(20, &varied_payload(500))
            .await
            .expect("record 20");
        journal.record_epoch(30, &data30).await.expect("record 30");

        // Newest (30) recovers, decoded exactly.
        let (epoch, bytes) = journal
            .recover_latest()
            .await
            .expect("recover")
            .expect("some");
        assert_eq!(epoch, 30);
        assert_eq!(bytes, data30);

        // Wipe 2 of epoch 30's 3 stripes -> it drops below K' -> fall back to 20.
        std::fs::remove_file(dir_path.join(stripe_file_name(30, 0))).expect("rm 30/0");
        std::fs::remove_file(dir_path.join(stripe_file_name(30, 1))).expect("rm 30/1");

        let (epoch_after, bytes_after) = journal
            .recover_latest()
            .await
            .expect("recover after")
            .expect("some");
        epoch_after == 20 && bytes_after == varied_payload(500)
    }));

    assert!(
        ok,
        "recover_latest must restore the newest recoverable checkpoint and fall back on damage"
    );
}
