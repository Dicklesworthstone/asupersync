    use super::*;

    fn config(bytes: u64, entries: u64) -> InboxConfig {
        let directory = tempfile::tempdir().unwrap().keep();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        InboxConfig {
            certificate_sha256: "11".repeat(32),
            directory,
            max_retained_bytes: bytes,
            max_retained_entries: entries,
        }
    }

    #[test]
    fn fresh_private_file_charges_one_entry_and_keeps_legacy_two_alias_accounting() {
        let config = config(10, 2); // lock plus one data file
        let inbox = Inbox::open(&config).unwrap();
        inbox.reserve_private_file(10, None).unwrap();
        assert_eq!((inbox.usage.lock().bytes, inbox.maximum_entries), (10, 2));
        assert_eq!(inbox.usage.lock().entries, 2);
        assert_eq!(
            inbox.reserve_private_file(0, None).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        drop(inbox);
        let legacy = Inbox::open(&config).unwrap();
        assert_eq!(
            legacy.reserve(5).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!((legacy.usage.lock().bytes, legacy.maximum_bytes), (0, 10));
        assert_eq!(legacy.usage.lock().entries, 1);
    }

    #[test]
    fn resumed_private_file_reserves_only_unwritten_bytes_without_another_entry() {
        let config = config(10, 2);
        std::fs::write(config.directory.join("partial"), b"abc").unwrap();
        let inbox = Inbox::open(&config).unwrap();
        assert_eq!(inbox.usage.lock().bytes, 3);
        inbox.reserve_private_file(10, Some(3)).unwrap();
        assert_eq!(inbox.usage.lock().bytes, 10);
        assert_eq!(inbox.usage.lock().entries, 2);
        assert_eq!(
            inbox.reserve_private_file(2, Some(3)).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(inbox.usage.lock().bytes, 10);
    }

    #[test]
    fn restart_cannot_ignore_other_retained_files_when_reserving_growth() {
        let config = config(10, 3);
        std::fs::write(config.directory.join("partial"), b"abc").unwrap();
        std::fs::write(config.directory.join("unrelated"), b"1234567").unwrap();
        let inbox = Inbox::open(&config).unwrap();
        assert_eq!(
            inbox.reserve_private_file(10, Some(3)).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(inbox.usage.lock().bytes, 10);
        assert_eq!(inbox.usage.lock().entries, 3);
    }
