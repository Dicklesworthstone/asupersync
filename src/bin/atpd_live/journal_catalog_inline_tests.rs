    use super::*;
    fn fixture() -> (PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap().keep();
        let catalog = root.join("state"); let inbox = root.join("inbox");
        for path in [&catalog, &inbox] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        (catalog.join("catalog.log"), inbox)
    }
    fn key(n: u8) -> ResumeSessionKey {
        ResumeSessionKey { client: NativeClientCertificateId::from_sha256([1; 32]), nonce: [n; 32] }
    }
    fn policy() -> FilePolicy { FilePolicy { data_bytes: 64, journal_bytes: 4096, snapshots: 16 } }

    #[test]
    fn claims_and_retirement_survive_restart_without_reusing_names_or_budgets() {
        let (path, inbox) = fixture(); Catalog::initialize(&path, 3, 8192).unwrap();
        let catalog = Catalog::open(&path).unwrap();
        let (first, fresh) = catalog.admit(key(1), &inbox, policy()).unwrap(); assert!(fresh);
        let before = std::fs::read(&path).unwrap();
        let (again, fresh) = catalog.admit(key(1), &inbox, FilePolicy { data_bytes: 128, ..policy() }).unwrap();
        assert!(!fresh); assert_eq!(again, first); assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(catalog.retire(key(1), Retirement::Idle).unwrap());
        assert!(!catalog.retire(key(1), Retirement::Revoked).unwrap());
        drop(catalog);
        let catalog = Catalog::open(&path).unwrap();
        assert_eq!(catalog.admit(key(1), &inbox, policy()).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let (second, fresh) = catalog.admit(key(2), &inbox, policy()).unwrap(); assert!(fresh);
        assert_ne!(first.data_path(&inbox), second.data_path(&inbox));
        assert_eq!(catalog.admit(key(3), &inbox, policy()).unwrap_err().kind(), io::ErrorKind::StorageFull);
        assert_eq!(catalog.entries()[0].retired, Some(Retirement::Idle));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), HEADER + 3 * RECORD);
        assert!(std::fs::read_dir(inbox).unwrap().next().is_none());
    }

    #[test]
    fn exact_client_and_inbox_identity_are_part_of_the_claim() {
        let (path, inbox) = fixture(); Catalog::initialize(&path, 4, 16384).unwrap();
        let catalog = Catalog::open(&path).unwrap();
        let (first, _) = catalog.admit(key(1), &inbox, policy()).unwrap();
        let other = ResumeSessionKey { client: NativeClientCertificateId::from_sha256([2; 32]), ..key(1) };
        let (second, _) = catalog.admit(other, &inbox, policy()).unwrap(); assert_ne!(first.id, second.id);
        let (_, changed_directory) = fixture();
        assert!(catalog.admit(key(1), &changed_directory, policy()).is_err());
        assert_eq!(catalog.entries().len(), 2);
    }

    #[test]
    fn missing_torn_unknown_and_exclusively_owned_history_never_becomes_empty() {
        let (path, inbox) = fixture(); assert!(Catalog::open(&path).is_err()); assert!(!path.exists());
        Catalog::initialize(&path, 2, 8192).unwrap(); let catalog = Catalog::open(&path).unwrap();
        assert!(Catalog::open(&path).is_err()); assert!(Catalog::initialize(&path, 2, 8192).is_err());
        catalog.admit(key(1), &inbox, policy()).unwrap(); drop(catalog);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap(); file.write_all(&[0]).unwrap(); file.sync_all().unwrap();
        let broken = std::fs::read(&path).unwrap(); assert!(Catalog::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), broken);
        let (other, _) = fixture(); Catalog::initialize(&other, 2, 8192).unwrap();
        std::fs::write(other.parent().unwrap().join("untracked"), b"keep").unwrap();
        assert!(Catalog::open(&other).is_err());
    }

    #[test]
    fn append_uncertainty_poison_is_sticky_but_admission_limits_are_not() {
        let (path, inbox) = fixture(); Catalog::initialize(&path, 2, 8192).unwrap();
        let catalog = Catalog::open(&path).unwrap(); catalog.admit(key(1), &inbox, policy()).unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap(); file.write_all(&[0]).unwrap(); file.sync_all().unwrap();
        assert!(catalog.retire(key(1), Retirement::LocalFailure).is_err()); assert!(catalog.failed());
        assert!(catalog.admit(key(2), &inbox, policy()).is_err());
        assert!(catalog.admit(key(1), &inbox, policy()).is_err());
        assert_eq!(catalog.entries().len(), 1);
        let (path, inbox) = fixture(); Catalog::initialize(&path, 1, 4096).unwrap();
        let catalog = Catalog::open(&path).unwrap(); catalog.admit(key(1), &inbox, policy()).unwrap();
        assert!(catalog.admit(key(2), &inbox, policy()).is_err()); assert!(!catalog.failed());
        assert!(!catalog.admit(key(1), &inbox, policy()).unwrap().1);
    }

    #[test]
    fn directory_census_accepts_only_bounded_claimed_wals() {
        let (path, inbox) = fixture(); Catalog::initialize(&path, 2, 8192).unwrap();
        let catalog = Catalog::open(&path).unwrap(); let (entry, _) = catalog.admit(key(1), &inbox, policy()).unwrap();
        let wal = catalog.wal_path(&entry);
        OpenOptions::new().write(true).create_new(true).mode(0o600).open(&wal).unwrap(); drop(catalog);
        // A header-only/empty claimed WAL is not validated here. Admission must
        // still refuse it through ReceiverJournalFile::open_existing, never recreate it.
        assert!(Catalog::open(&path).is_ok());
        OpenOptions::new().write(true).open(&wal).unwrap().set_len(4097).unwrap();
        assert!(Catalog::open(&path).is_err());
    }

    #[test]
    fn decoding_rejects_changed_checksums_and_nonprivate_catalogs() {
        let (path, inbox) = fixture(); Catalog::initialize(&path, 2, 8192).unwrap();
        let catalog = Catalog::open(&path).unwrap(); catalog.admit(key(1), &inbox, policy()).unwrap(); drop(catalog);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Catalog::open(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(HEADER + 56)).unwrap(); file.write_all(&[99]).unwrap(); file.sync_all().unwrap();
        let corrupted = std::fs::read(&path).unwrap(); assert!(Catalog::open(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupted);
    }

    /// GH #77 item 3 (br-asupersync-7nw4jf): a reboot can renumber the device
    /// a directory lives on. A catalog whose recorded device numbers all
    /// changed (the catalog directory in the header, the inbox in its entry)
    /// still reopens and re-admits its key, because the inodes match.
    #[test]
    fn recorded_device_numbers_changed_by_a_reboot_do_not_refuse_the_catalog() {
        let (path, inbox) = fixture();
        Catalog::initialize(&path, 2, 8192).unwrap();
        let catalog = Catalog::open(&path).unwrap();
        let (first, _) = catalog.admit(key(1), &inbox, policy()).unwrap();
        drop(catalog);
        let renumbered = u64::MAX.to_be_bytes();
        let mut bytes = std::fs::read(&path).unwrap();
        let header = HEADER as usize;
        bytes[24..32].copy_from_slice(&renumbered);
        let mut previous = checksum(&[], &bytes[..48]);
        bytes[48..header].copy_from_slice(&previous);
        for record in bytes[header..].chunks_mut(RECORD as usize) {
            record[88..96].copy_from_slice(&renumbered);
            previous = checksum(&previous, &record[..BODY]);
            record[BODY..].copy_from_slice(&previous);
        }
        std::fs::write(&path, &bytes).unwrap();
        let catalog = Catalog::open(&path).expect("the recorded inodes still match");
        assert_eq!(catalog.entries()[0].directory.0, u64::MAX);
        let (again, fresh) = catalog
            .admit(key(1), &inbox, policy())
            .expect("the same inbox on a renumbered device");
        assert!(!fresh);
        assert_eq!(again.id, first.id);
    }
