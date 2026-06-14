//! Durable striped file-I/O contract for the RaptorQ trace journal
//! (br-asupersync-raptorq-leverage-3bb2pl.2): encode a checkpoint, write each
//! stripe to its own file via the crash-durable atomic writer, destroy one
//! stripe file (a lost failure domain), and confirm the epoch still recovers.

#![allow(missing_docs)]

use asupersync::config::EncodingConfig;
use asupersync::runtime::RuntimeBuilder;
use asupersync::trace::raptorq_journal::{latest_complete_epoch, scan_frames};
use asupersync::trace::raptorq_journal_writer::{
    encode_and_serialize_epoch, read_epoch_stripes, write_epoch_stripes,
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
