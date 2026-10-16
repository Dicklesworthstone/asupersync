    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::stream::StreamExt;
    use tempfile::tempdir;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_read_dir() {
        init_test("test_read_dir");
        let dir = tempdir().unwrap();
        let path = dir.path();
        std::fs::write(path.join("a.txt"), b"a").unwrap();
        std::fs::write(path.join("b.txt"), b"b").unwrap();
        std::fs::create_dir_all(path.join("subdir")).unwrap();

        let result = futures_lite::future::block_on(async {
            let mut entries = read_dir(&path).await?;
            let mut names = Vec::new();
            while let Some(entry) = entries.next_entry().await? {
                names.push(entry.file_name().to_string_lossy().to_string());
            }
            names.sort();
            Ok::<_, io::Error>(names)
        })
        .unwrap();

        crate::assert_with_log!(
            result == vec!["a.txt", "b.txt", "subdir"],
            "entries",
            vec!["a.txt", "b.txt", "subdir"],
            result
        );
        crate::test_complete!("test_read_dir");
    }

    #[test]
    fn test_read_dir_as_stream() {
        init_test("test_read_dir_as_stream");
        let dir = tempdir().unwrap();
        let path = dir.path();
        std::fs::write(path.join("file1.txt"), b"1").unwrap();
        std::fs::write(path.join("file2.txt"), b"2").unwrap();

        let names = futures_lite::future::block_on(async {
            let entries = read_dir(&path).await.unwrap();
            let names: Vec<String> = entries
                .map(|r| r.unwrap().file_name().to_string_lossy().to_string())
                .collect()
                .await;
            let mut names = names;
            names.sort();
            names
        });

        crate::assert_with_log!(
            names == vec!["file1.txt", "file2.txt"],
            "entries",
            vec!["file1.txt", "file2.txt"],
            names
        );
        crate::test_complete!("test_read_dir_as_stream");
    }

    #[test]
    fn test_dir_entry_metadata() {
        init_test("test_dir_entry_metadata");
        let dir = tempdir().unwrap();
        let path = dir.path();
        let file_path = path.join("test.txt");
        std::fs::write(&file_path, b"content").unwrap();

        let (is_file, len) = futures_lite::future::block_on(async {
            let mut entries = read_dir(&path).await?;
            let entry = entries.next_entry().await?.expect("missing entry");
            let metadata = entry.metadata().await?;
            Ok::<_, io::Error>((metadata.is_file(), metadata.len()))
        })
        .unwrap();

        crate::assert_with_log!(is_file, "is_file", true, is_file);
        crate::assert_with_log!(len == 7, "len", 7, len);
        crate::test_complete!("test_dir_entry_metadata");
    }

    #[cfg(unix)]
    #[test]
    fn test_dir_entry_symlink_semantics() {
        init_test("test_dir_entry_symlink_semantics");
        let dir = tempdir().unwrap();
        let path = dir.path();
        let target = path.join("target.txt");
        let link = path.join("link.txt");
        std::fs::write(&target, b"target").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let (is_symlink, metadata_is_file, metadata_is_symlink, len) =
            futures_lite::future::block_on(async {
                let mut entries = read_dir(&path).await?;
                while let Some(entry) = entries.next_entry().await? {
                    if entry.file_name().to_string_lossy() == "link.txt" {
                        let file_type = entry.file_type().await?;
                        let metadata = entry.metadata().await?;
                        return Ok::<_, io::Error>((
                            file_type.is_symlink(),
                            metadata.is_file(),
                            metadata.file_type().is_symlink(),
                            metadata.len(),
                        ));
                    }
                }
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "missing symlink entry",
                ))
            })
            .unwrap();

        crate::assert_with_log!(is_symlink, "file_type reports symlink", true, is_symlink);
        crate::assert_with_log!(
            !metadata_is_file,
            "metadata is not target file metadata",
            false,
            metadata_is_file
        );
        crate::assert_with_log!(
            metadata_is_symlink,
            "metadata preserves symlink semantics",
            true,
            metadata_is_symlink
        );
        crate::assert_with_log!(len > 0, "symlink metadata len", true, len > 0);
        crate::test_complete!("test_dir_entry_symlink_semantics");
    }
