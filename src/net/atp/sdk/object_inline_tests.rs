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

#[test]
fn filesystem_store_metadata_refusal_preserves_existing_payload() {
    let directory = tempfile::tempdir().unwrap();
    let store = FileSystemObjectStore::new(directory.path().to_path_buf());
    let cx = Cx::for_testing();
    let data = b"replacement object".to_vec();
    let hash = ObjectHash::from_data(&data);
    let payload = store.object_path(&hash);
    let sidecar = store.metadata_path(&hash);
    std::fs::create_dir_all(payload.parent().unwrap()).unwrap();
    std::fs::write(&payload, b"previous bytes must survive refusal").unwrap();
    std::fs::create_dir(&sidecar).unwrap();

    let outcome =
        block_on(store.store_object(&cx, data, "application/octet-stream", ObjectMetadata::new()));
    assert!(matches!(outcome, AtpOutcome::Err(_)), "{outcome:?}");
    assert_eq!(
        std::fs::read(&payload).unwrap(),
        b"previous bytes must survive refusal"
    );
    assert!(
        sidecar.is_dir(),
        "the obstructing path must not be replaced"
    );
    let entries = std::fs::read_dir(payload.parent().unwrap())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 2, "no staging file may remain");
}

#[cfg(unix)]
#[test]
fn filesystem_store_publication_does_not_truncate_existing_readers() {
    use std::io::Read as _;

    let directory = tempfile::tempdir().unwrap();
    let store = FileSystemObjectStore::new(directory.path().to_path_buf());
    let cx = Cx::for_testing();
    let data = vec![0x5a; 128 * 1024];
    let hash = ObjectHash::from_data(&data);
    let payload = store.object_path(&hash);
    let sidecar = store.metadata_path(&hash);
    std::fs::create_dir_all(payload.parent().unwrap()).unwrap();
    std::fs::write(&payload, b"previous payload snapshot").unwrap();
    std::fs::write(&sidecar, b"previous metadata snapshot").unwrap();
    let mut prior_payload = std::fs::File::open(&payload).unwrap();
    let mut prior_sidecar = std::fs::File::open(&sidecar).unwrap();

    block_on(async {
        let object = store
            .store_object(
                &cx,
                data.clone(),
                "application/octet-stream",
                ObjectMetadata::new(),
            )
            .await
            .unwrap();
        assert_eq!(object.hash, hash);
        assert_eq!(store.get_object(&cx, &hash).await.unwrap(), Some(data));
        assert_eq!(
            store.get_object_info(&cx, &hash).await.unwrap(),
            Some(object)
        );
    });
    let mut old_payload = Vec::new();
    let mut old_sidecar = Vec::new();
    prior_payload.read_to_end(&mut old_payload).unwrap();
    prior_sidecar.read_to_end(&mut old_sidecar).unwrap();
    assert_eq!(old_payload, b"previous payload snapshot");
    assert_eq!(old_sidecar, b"previous metadata snapshot");
}

#[test]
fn filesystem_object_info_rejects_wrong_hash_and_size() {
    let directory = tempfile::tempdir().unwrap();
    let store = FileSystemObjectStore::new(directory.path().to_path_buf());
    let cx = Cx::for_testing();
    block_on(async {
        let object = store
            .store_object(
                &cx,
                b"verified bytes".to_vec(),
                "text/plain",
                ObjectMetadata::new(),
            )
            .await
            .unwrap();
        let metadata_path = store.metadata_path(&object.hash);
        let mut wrong_hash = object.clone();
        wrong_hash.hash = ObjectHash::from_data(b"other object");
        std::fs::write(&metadata_path, serde_json::to_vec(&wrong_hash).unwrap()).unwrap();
        assert!(matches!(
            store.get_object_info(&cx, &object.hash).await,
            AtpOutcome::Err(AtpError::Manifest(ManifestError::HashMismatch))
        ));

        let mut wrong_size = object.clone();
        wrong_size.size_bytes += 1;
        std::fs::write(&metadata_path, serde_json::to_vec(&wrong_size).unwrap()).unwrap();
        assert!(matches!(
            store.get_object_info(&cx, &object.hash).await,
            AtpOutcome::Err(AtpError::Manifest(ManifestError::HashMismatch))
        ));
        std::fs::write(&metadata_path, serde_json::to_vec(&object).unwrap()).unwrap();
        assert_eq!(
            store.get_object_info(&cx, &object.hash).await.unwrap(),
            Some(object)
        );
    });
}

#[test]
fn filesystem_orphan_sidecar_is_invisible_and_deletion_retries_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let store = FileSystemObjectStore::new(directory.path().to_path_buf());
    let cx = Cx::for_testing();
    let object = AtpObject {
        hash: ObjectHash::from_data(b"absent payload"),
        size_bytes: 14,
        content_type: "text/plain".into(),
        metadata: ObjectMetadata::new(),
        created_at_nanos: 0,
    };
    let metadata_path = store.metadata_path(&object.hash);
    std::fs::create_dir_all(metadata_path.parent().unwrap()).unwrap();
    std::fs::write(&metadata_path, serde_json::to_vec(&object).unwrap()).unwrap();

    block_on(async {
        assert_eq!(store.get_object(&cx, &object.hash).await.unwrap(), None);
        assert_eq!(
            store.get_object_info(&cx, &object.hash).await.unwrap(),
            None
        );
        assert!(!store.has_object(&cx, &object.hash).await.unwrap());
        assert!(store.list_objects(&cx).await.unwrap().is_empty());
        assert!(!store.delete_object(&cx, &object.hash).await.unwrap());
        assert!(
            !metadata_path.exists(),
            "retry must remove an orphan sidecar"
        );
        assert!(!store.delete_object(&cx, &object.hash).await.unwrap());
    });
}

#[test]
fn filesystem_store_keeps_data_only_legacy_objects_readable() {
    let directory = tempfile::tempdir().unwrap();
    let store = FileSystemObjectStore::new(directory.path().to_path_buf());
    let cx = Cx::for_testing();
    let data = Vec::new();
    let hash = ObjectHash::from_data(&data);
    let path = store.object_path(&hash);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &data).unwrap();

    block_on(async {
        assert_eq!(store.get_object(&cx, &hash).await.unwrap(), Some(data));
        assert!(store.has_object(&cx, &hash).await.unwrap());
        assert_eq!(store.list_objects(&cx).await.unwrap(), vec![hash.clone()]);
        assert_eq!(store.get_object_info(&cx, &hash).await.unwrap(), None);
        assert!(store.delete_object(&cx, &hash).await.unwrap());
        assert!(!store.delete_object(&cx, &hash).await.unwrap());
    });
}

#[test]
fn filesystem_object_delete_reports_payload_and_metadata_errors() {
    let directory = tempfile::tempdir().unwrap();
    let store = FileSystemObjectStore::new(directory.path().to_path_buf());
    let cx = Cx::for_testing();
    let blocked_hash = ObjectHash::from_data(b"directory instead of payload");
    let payload = store.object_path(&blocked_hash);
    let sidecar = store.metadata_path(&blocked_hash);
    std::fs::create_dir_all(&payload).unwrap();
    std::fs::write(&sidecar, b"retain on payload failure").unwrap();

    block_on(async {
        assert!(matches!(
            store.has_object(&cx, &blocked_hash).await,
            AtpOutcome::Err(AtpError::Disk(DiskError::CorruptedData))
        ));
        assert!(matches!(
            store.delete_object(&cx, &blocked_hash).await,
            AtpOutcome::Err(AtpError::Disk(DiskError::IoError))
        ));
        assert!(payload.is_dir());
        assert_eq!(
            std::fs::read(&sidecar).unwrap(),
            b"retain on payload failure"
        );

        let data = b"delete payload but report sidecar failure";
        let hash = ObjectHash::from_data(data);
        let payload = store.object_path(&hash);
        let sidecar = store.metadata_path(&hash);
        std::fs::create_dir_all(payload.parent().unwrap()).unwrap();
        std::fs::write(&payload, data).unwrap();
        std::fs::create_dir(&sidecar).unwrap();
        assert!(matches!(
            store.delete_object(&cx, &hash).await,
            AtpOutcome::Err(AtpError::Disk(DiskError::IoError))
        ));
        assert!(!payload.exists());
        assert!(sidecar.is_dir());
    });
}

fn assert_store_cancelled<T: std::fmt::Debug>(outcome: AtpOutcome<T>, expected: &CancelReason) {
    match outcome {
        AtpOutcome::Cancelled(reason) => assert_eq!(&reason, expected),
        other => panic!("expected attributed cancellation, got {other:?}"),
    }
}

#[test]
fn filesystem_object_store_cancelled_context_has_no_effects() {
    let directory = tempfile::tempdir().unwrap();
    let store = FileSystemObjectStore::new(directory.path().to_path_buf());
    let cx = Cx::for_testing();
    let cancelled = Cx::for_testing();
    let reason = CancelReason::user("object store owner stopped");
    cancelled.set_cancel_reason(reason.clone());

    block_on(async {
        let object = store
            .store_object(
                &cx,
                b"existing object".to_vec(),
                "text/plain",
                ObjectMetadata::new(),
            )
            .await
            .unwrap();
        let new_data = b"must never reach disk".to_vec();
        let new_hash = ObjectHash::from_data(&new_data);
        assert_store_cancelled(
            store
                .store_object(&cancelled, new_data, "text/plain", ObjectMetadata::new())
                .await,
            &reason,
        );
        assert_store_cancelled(store.get_object(&cancelled, &object.hash).await, &reason);
        assert_store_cancelled(
            store.get_object_info(&cancelled, &object.hash).await,
            &reason,
        );
        assert_store_cancelled(store.has_object(&cancelled, &object.hash).await, &reason);
        assert_store_cancelled(store.list_objects(&cancelled).await, &reason);
        assert_store_cancelled(store.delete_object(&cancelled, &object.hash).await, &reason);
        assert!(!store.object_path(&new_hash).exists());
        assert!(!store.metadata_path(&new_hash).exists());
        assert_eq!(
            store.get_object(&cx, &object.hash).await.unwrap(),
            Some(b"existing object".to_vec())
        );
        assert_eq!(
            store.get_object_info(&cx, &object.hash).await.unwrap(),
            Some(object)
        );
    });
}

#[test]
fn filesystem_object_store_requires_explicit_io_authority() {
    let directory = tempfile::tempdir().unwrap();
    let store = FileSystemObjectStore::new(directory.path().join("uncreated-store"));
    let restricted = Cx::for_testing().restrict::<crate::cx::cap::None>();
    block_on(restricted.with_ambient(async {
        let cx = Cx::current().unwrap();
        let data = b"unauthorized".to_vec();
        let hash = ObjectHash::from_data(&data);
        assert!(matches!(
            store
                .store_object(&cx, data, "text/plain", ObjectMetadata::new())
                .await,
            AtpOutcome::Err(AtpError::Disk(DiskError::PermissionDenied))
        ));
        assert!(matches!(
            store.get_object(&cx, &hash).await,
            AtpOutcome::Err(AtpError::Disk(DiskError::PermissionDenied))
        ));
        assert!(matches!(
            store.get_object_info(&cx, &hash).await,
            AtpOutcome::Err(AtpError::Disk(DiskError::PermissionDenied))
        ));
        assert!(matches!(
            store.has_object(&cx, &hash).await,
            AtpOutcome::Err(AtpError::Disk(DiskError::PermissionDenied))
        ));
        assert!(matches!(
            store.list_objects(&cx).await,
            AtpOutcome::Err(AtpError::Disk(DiskError::PermissionDenied))
        ));
        assert!(matches!(
            store.delete_object(&cx, &hash).await,
            AtpOutcome::Err(AtpError::Disk(DiskError::PermissionDenied))
        ));
    }));
    assert!(!store.base_path.exists());
}

#[cfg(unix)]
#[test]
fn filesystem_object_publication_is_private_and_preserves_existing_modes() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let store = FileSystemObjectStore::new(directory.path().to_path_buf());
    let cx = Cx::for_testing();
    let data = b"private object".to_vec();
    block_on(async {
        let object = store
            .store_object(&cx, data.clone(), "text/plain", ObjectMetadata::new())
            .await
            .unwrap();
        let paths = [
            store.object_path(&object.hash),
            store.metadata_path(&object.hash),
        ];
        for path in &paths {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o077,
                0
            );
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        store
            .store_object(&cx, data, "application/octet-stream", ObjectMetadata::new())
            .await
            .unwrap();
        for path in &paths {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o640
            );
        }
    });
}
