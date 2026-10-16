    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // -- UnixVfs: file create, write, read roundtrip --

    #[test]
    fn unix_vfs_write_read_roundtrip() {
        init_test("unix_vfs_write_read_roundtrip");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let path = dir.path().join("hello.txt");

            // Write via convenience method
            vfs.write(&path, b"hello vfs").await.unwrap();

            // Read back via convenience method
            let contents = vfs.read_to_string(&path).await.unwrap();
            crate::assert_with_log!(contents == "hello vfs", "contents", "hello vfs", contents);
        });
        crate::test_complete!("unix_vfs_write_read_roundtrip");
    }

    // -- UnixVfs: open + VfsFile read/write --

    #[test]
    fn unix_vfs_open_file_rw() {
        init_test("unix_vfs_open_file_rw");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let path = dir.path().join("rw.txt");

            // Create and write via VfsFile
            let mut file = vfs.open_create(&path).await.unwrap();
            file.write_all(b"vfs file write").await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Read back via VfsFile
            let mut file = vfs.open_read(&path).await.unwrap();
            let mut buf = String::new();
            file.read_to_string(&mut buf).await.unwrap();
            crate::assert_with_log!(buf == "vfs file write", "read back", "vfs file write", buf);
        });
        crate::test_complete!("unix_vfs_open_file_rw");
    }

    // -- UnixVfs: metadata --

    #[test]
    fn unix_vfs_metadata() {
        init_test("unix_vfs_metadata");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let path = dir.path().join("meta.txt");

            vfs.write(&path, b"12345").await.unwrap();
            let meta = vfs.metadata(&path).await.unwrap();
            crate::assert_with_log!(meta.is_file(), "is_file", true, meta.is_file());
            crate::assert_with_log!(meta.len() == 5, "len", 5, meta.len());
        });
        crate::test_complete!("unix_vfs_metadata");
    }

    // -- UnixVfs: directory operations --

    #[test]
    fn unix_vfs_dir_ops() {
        init_test("unix_vfs_dir_ops");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let sub = dir.path().join("a/b/c");

            vfs.create_dir_all(&sub).await.unwrap();
            let meta = vfs.metadata(&sub).await.unwrap();
            crate::assert_with_log!(meta.is_dir(), "is_dir", true, meta.is_dir());

            // Write a file inside
            let file_path = sub.join("test.txt");
            vfs.write(&file_path, b"nested").await.unwrap();

            // read_dir
            let mut rd = vfs.read_dir(&sub).await.unwrap();
            let entry = rd.next_entry().await.unwrap().expect("one entry");
            let name = entry.file_name().to_string_lossy().to_string();
            crate::assert_with_log!(name == "test.txt", "entry name", "test.txt", name);

            // remove_dir_all
            let top = dir.path().join("a");
            vfs.remove_dir_all(&top).await.unwrap();
            let exists = top.exists();
            crate::assert_with_log!(!exists, "removed", false, exists);
        });
        crate::test_complete!("unix_vfs_dir_ops");
    }

    // -- UnixVfs: rename + copy + remove_file --

    #[test]
    fn unix_vfs_rename_copy_remove() {
        init_test("unix_vfs_rename_copy_remove");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let src = dir.path().join("src.txt");
            let dst = dir.path().join("dst.txt");
            let renamed = dir.path().join("renamed.txt");

            vfs.write(&src, b"copy me").await.unwrap();

            // copy
            let n = vfs.copy(&src, &dst).await.unwrap();
            crate::assert_with_log!(n == 7, "bytes copied", 7, n);

            // rename
            vfs.rename(&dst, &renamed).await.unwrap();
            let exists = dst.exists();
            crate::assert_with_log!(!exists, "dst gone", false, exists);

            let contents = vfs.read(&renamed).await.unwrap();
            crate::assert_with_log!(
                contents == b"copy me",
                "renamed contents",
                b"copy me",
                contents
            );

            // remove_file
            vfs.remove_file(&renamed).await.unwrap();
            let exists = renamed.exists();
            crate::assert_with_log!(!exists, "removed", false, exists);
        });
        crate::test_complete!("unix_vfs_rename_copy_remove");
    }

    #[test]
    fn unix_vfs_hard_link_shares_file_contents() {
        init_test("unix_vfs_hard_link_shares_file_contents");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let original = dir.path().join("original.txt");
            let linked = dir.path().join("linked.txt");

            vfs.write(&original, b"before").await.unwrap();
            vfs.hard_link(&original, &linked).await.unwrap();
            let linked_contents = vfs.read(&linked).await.unwrap();
            crate::assert_with_log!(
                linked_contents == b"before",
                "linked initial contents",
                b"before",
                linked_contents
            );

            vfs.write(&original, b"after").await.unwrap();
            let linked_contents = vfs.read(&linked).await.unwrap();
            crate::assert_with_log!(
                linked_contents == b"after",
                "linked updated contents",
                b"after",
                linked_contents
            );
        });
        crate::test_complete!("unix_vfs_hard_link_shares_file_contents");
    }

    // -- VfsFile: seek --

    #[test]
    fn unix_vfs_file_seek() {
        init_test("unix_vfs_file_seek");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let path = dir.path().join("seek.txt");

            // Write data
            let opts = OpenOptions::new().read(true).write(true).create(true);
            let mut file = vfs.open(&path, &opts).await.unwrap();
            file.write_all(b"0123456789").await.unwrap();
            drop(file);

            // Re-open, seek into the file, and verify the cursor moves correctly.
            let mut file = vfs.open_read(&path).await.unwrap();
            let pos = file.seek(SeekFrom::Start(3)).await.unwrap();
            crate::assert_with_log!(pos == 3, "seek position", 3u64, pos);

            let mut tail = String::new();
            file.read_to_string(&mut tail).await.unwrap();
            crate::assert_with_log!(tail == "3456789", "tail read", "3456789", tail);
        });
        crate::test_complete!("unix_vfs_file_seek");
    }

    // -- VfsFile: metadata + set_len --

    #[test]
    fn unix_vfs_file_metadata_set_len() {
        init_test("unix_vfs_file_metadata_set_len");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let path = dir.path().join("truncate.txt");

            let mut file = vfs.open_create(&path).await.unwrap();
            file.write_all(b"hello world").await.unwrap();
            file.sync_all().await.unwrap();

            // Check metadata via VfsFile
            let meta = VfsFile::metadata(&file).await.unwrap();
            crate::assert_with_log!(meta.len() == 11, "initial len", 11, meta.len());

            // Truncate
            file.set_len(5).await.unwrap();
            file.sync_all().await.unwrap();
            drop(file);

            // Verify via Vfs
            let contents = vfs.read(&path).await.unwrap();
            crate::assert_with_log!(contents == b"hello", "truncated", b"hello", contents);
        });
        crate::test_complete!("unix_vfs_file_metadata_set_len");
    }

    // -- Generic function that works with any Vfs --

    async fn write_and_read_back<V: Vfs>(vfs: &V, dir: &Path) -> String {
        let path = dir.join("generic.txt");
        vfs.write(&path, b"generic vfs").await.unwrap();
        vfs.read_to_string(&path).await.unwrap()
    }

    #[test]
    fn unix_vfs_generic_usage() {
        init_test("unix_vfs_generic_usage");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let result = write_and_read_back(&vfs, dir.path()).await;
            crate::assert_with_log!(result == "generic vfs", "generic", "generic vfs", result);
        });
        crate::test_complete!("unix_vfs_generic_usage");
    }

    // -- Symlink metadata (Unix-only) --

    #[cfg(unix)]
    #[test]
    fn unix_vfs_symlink_metadata() {
        init_test("unix_vfs_symlink_metadata");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let target = dir.path().join("target.txt");
            let link = dir.path().join("link");

            vfs.write(&target, b"content").await.unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();

            // metadata follows symlinks
            let meta = vfs.metadata(&link).await.unwrap();
            crate::assert_with_log!(meta.is_file(), "follows symlink", true, meta.is_file());

            // symlink_metadata does not
            let meta = vfs.symlink_metadata(&link).await.unwrap();
            crate::assert_with_log!(meta.is_symlink(), "is_symlink", true, meta.is_symlink());
        });
        crate::test_complete!("unix_vfs_symlink_metadata");
    }

    #[cfg(unix)]
    #[test]
    fn unix_vfs_canonicalize_and_read_link() {
        init_test("unix_vfs_canonicalize_and_read_link");
        futures_lite::future::block_on(async {
            let vfs = UnixVfs::new();
            let dir = tempdir().unwrap();
            let target = dir.path().join("target.txt");
            let link = dir.path().join("link");

            vfs.write(&target, b"content").await.unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();

            let read_target = vfs.read_link(&link).await.unwrap();
            let expected_target = target.display().to_string();
            let actual_target = read_target.display().to_string();
            crate::assert_with_log!(
                read_target == target,
                "read_link target",
                expected_target,
                actual_target
            );

            let canonical_target = vfs.canonicalize(&target).await.unwrap();
            let canonical_link = vfs.canonicalize(&link).await.unwrap();
            crate::assert_with_log!(
                canonical_link == canonical_target,
                "canonical link target",
                canonical_target,
                canonical_link
            );
        });
        crate::test_complete!("unix_vfs_canonicalize_and_read_link");
    }

    // --- wave 80 trait coverage ---

    #[test]
    fn unix_vfs_debug_clone_copy_default() {
        let v = UnixVfs;
        let v2 = v; // Copy
        let v3 = v;
        let _ = v2;
        let _ = v3;
        let dbg = format!("{v:?}");
        assert!(dbg.contains("UnixVfs"));
    }
