    use super::*;
    use futures_lite::future::block_on;

    #[test]
    fn object_hash_creation() {
        let data = b"hello world";
        let hash = ObjectHash::from_data(data);

        let hex = hash.hex();
        assert_eq!(hex.len(), 64); // SHA-256 is 32 bytes = 64 hex chars

        let parsed_hash = ObjectHash::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed_hash);
    }

    #[test]
    fn object_metadata_operations() {
        let mut metadata = ObjectMetadata::new();
        assert!(metadata.fields.is_empty());

        metadata.insert("key1".to_string(), "value1".to_string());
        metadata.insert("key2".to_string(), "value2".to_string());

        assert_eq!(metadata.get("key1"), Some("value1"));
        assert_eq!(metadata.get("key2"), Some("value2"));
        assert_eq!(metadata.get("key3"), None);

        assert!(metadata.contains_key("key1"));
        assert!(!metadata.contains_key("key3"));

        let removed = metadata.remove("key1");
        assert_eq!(removed, Some("value1".to_string()));
        assert_eq!(metadata.get("key1"), None);
    }

    #[test]
    fn memory_object_store() {
        crate::test_utils::init_test_logging();

        let cx = crate::cx::Cx::for_testing();

        let store = MemoryObjectStore::new();
        let data = b"test data".to_vec();
        let content_type = "text/plain";
        let metadata = ObjectMetadata::with_filename("test.txt");

        block_on(async {
            // Store object
            let object = store
                .store_object(&cx, data.clone(), content_type, metadata)
                .await
                .unwrap();
            assert_eq!(object.size_bytes, data.len() as u64);
            assert_eq!(object.content_type, content_type);

            // Check existence
            let exists = store.has_object(&cx, &object.hash).await.unwrap();
            assert!(exists);

            // Retrieve object
            let retrieved = store.get_object(&cx, &object.hash).await.unwrap();
            assert_eq!(retrieved, Some(data));

            // Get object info
            let info = store.get_object_info(&cx, &object.hash).await.unwrap();
            assert!(info.is_some());
            assert_eq!(info.unwrap().hash, object.hash);

            // Delete object
            let deleted = store.delete_object(&cx, &object.hash).await.unwrap();
            assert!(deleted);

            let exists_after_delete = store.has_object(&cx, &object.hash).await.unwrap();
            assert!(!exists_after_delete);
        });

        crate::test_complete!("memory_object_store");
    }

    #[test]
    fn manifest_builder() {
        let mut builder = ManifestBuilder::new();

        let hash1 = ObjectHash::from_data(b"data1");
        let hash2 = ObjectHash::from_data(b"data2");

        builder.add_object(
            hash1.clone(),
            "file1.txt".to_string(),
            5,
            "text/plain".to_string(),
            ObjectMetadata::with_filename("file1.txt"),
        );

        builder.add_object(
            hash2.clone(),
            "file2.txt".to_string(),
            5,
            "text/plain".to_string(),
            ObjectMetadata::with_filename("file2.txt"),
        );

        builder.add_metadata("description".to_string(), "test manifest".to_string());

        let manifest = builder.build(hash1.clone());

        assert_eq!(manifest.root_hash, hash1);
        assert_eq!(manifest.objects.len(), 2);
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.metadata.get("description"), Some("test manifest"));
    }

    #[test]
    fn filesystem_object_store() {
        crate::test_utils::init_test_logging();

        use tempfile::tempdir;

        let cx = crate::cx::Cx::for_testing();

        let temp_dir = tempdir().unwrap();
        let store = FileSystemObjectStore::new(temp_dir.path().to_path_buf());
        let data = b"filesystem test data".to_vec();
        let content_type = "application/octet-stream";
        let metadata = ObjectMetadata::with_filename("fstest.bin");

        block_on(async {
            // Store object
            let object = store
                .store_object(&cx, data.clone(), content_type, metadata)
                .await
                .unwrap();

            // Verify file was created
            let object_path = store.object_path(&object.hash);
            assert!(object_path.exists());

            // Retrieve object
            let retrieved = store.get_object(&cx, &object.hash).await.unwrap();
            assert_eq!(retrieved, Some(data));

            // Get object info
            let info = store.get_object_info(&cx, &object.hash).await.unwrap();
            assert!(info.is_some());

            // List objects
            let objects = store.list_objects(&cx).await.unwrap();
            assert!(objects.contains(&object.hash));

            // Delete object
            let deleted = store.delete_object(&cx, &object.hash).await.unwrap();
            assert!(deleted);
            assert!(!object_path.exists());
        });

        crate::test_complete!("filesystem_object_store");
    }
