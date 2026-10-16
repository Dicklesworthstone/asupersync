    use super::*;

    fn file_storage(compression_enabled: bool) -> FileStorage {
        FileStorage {
            root_dir: PathBuf::new(),
            metrics: Mutex::new(StorageMetrics::default()),
            compression_enabled,
        }
    }

    #[test]
    fn file_storage_leaves_small_content_unframed() {
        let storage = file_storage(true);
        let content = b"small content";

        let encoded = storage.compress_content(content).unwrap();
        assert_eq!(encoded, content);
        assert_eq!(storage.decompress_content(&encoded).unwrap(), content);
    }

    #[test]
    #[cfg(feature = "compression")]
    fn file_storage_gzip_envelope_roundtrips_and_verifies_digest() {
        let storage = file_storage(true);
        let content = b"cache payload ".repeat(512);

        let encoded = storage.compress_content(&content).unwrap();
        assert!(encoded.starts_with(CACHE_COMPRESSION_MAGIC));
        assert!(encoded.len() < content.len());
        assert_eq!(storage.decompress_content(&encoded).unwrap(), content);

        let mut tampered = encoded;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x40;
        assert!(storage.decompress_content(&tampered).is_err());
    }

    #[test]
    #[cfg(not(feature = "compression"))]
    fn file_storage_compression_fails_closed_without_feature() {
        let storage = file_storage(true);
        let content = vec![b'x'; CACHE_COMPRESSION_THRESHOLD + 1];

        assert!(storage.compress_content(&content).is_err());
    }

    #[test]
    fn file_storage_derives_safe_paths_from_untrusted_content_hashes() {
        let root = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(root.path(), false).unwrap();
        let key = CacheKey::new("manifest".to_string(), "../outside/cache".to_string(), None);
        let content = b"cache content";

        let location = storage.store(&key, content).unwrap();
        let StorageLocation::File(path) = &location else {
            panic!("file storage must return file location");
        };

        assert!(path.starts_with(root.path()));
        assert!(
            !path
                .components()
                .any(|component| { matches!(component, std::path::Component::ParentDir) })
        );
        assert_eq!(storage.retrieve(&location).unwrap(), content.to_vec());
    }

    #[test]
    fn file_storage_rejects_locations_outside_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_path = outside.path().join("victim.cache");
        std::fs::write(&outside_path, b"do not touch").unwrap();

        let mut storage = FileStorage::new(root.path(), false).unwrap();
        let location = StorageLocation::File(outside_path.clone());

        assert!(storage.retrieve(&location).is_err());
        assert!(!storage.exists(&location));
        assert!(storage.remove(&location).is_err());
        assert_eq!(std::fs::read(&outside_path).unwrap(), b"do not touch");
    }

    #[test]
    fn memory_storage_distinguishes_scopes_and_tracks_replacement_bytes() {
        let mut storage = MemoryStorage::new(128);
        let key_private = CacheKey::new(
            "manifest".to_string(),
            "content".to_string(),
            Some("private".to_string()),
        );
        let key_public = CacheKey::new(
            "manifest".to_string(),
            "content".to_string(),
            Some("public".to_string()),
        );

        let private_location = storage.store(&key_private, b"private").unwrap();
        let public_location = storage.store(&key_public, b"public").unwrap();
        assert_ne!(private_location, public_location);
        assert_eq!(storage.memory_usage(), 13);

        storage.store(&key_private, b"p").unwrap();
        assert_eq!(storage.memory_usage(), 7);
        assert_eq!(storage.retrieve(&private_location).unwrap(), b"p".to_vec());
        assert_eq!(
            storage.retrieve(&public_location).unwrap(),
            b"public".to_vec()
        );
    }

    #[test]
    fn hybrid_storage_falls_back_to_file_when_memory_backend_is_full() {
        let root = tempfile::tempdir().unwrap();
        let mut storage = HybridStorage::new(4, 1024, root.path(), false).unwrap();
        let key = CacheKey::new("manifest".to_string(), "content".to_string(), None);
        let content = b"larger than memory";

        let location = storage.store(&key, content).unwrap();
        assert!(matches!(location, StorageLocation::File(_)));
        assert_eq!(storage.retrieve(&location).unwrap(), content.to_vec());
        assert_eq!(storage.metrics().files_stored, 1);
        assert_eq!(storage.metrics().errors, 0);
    }
