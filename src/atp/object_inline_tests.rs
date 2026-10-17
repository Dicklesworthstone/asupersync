    use super::*;

    #[test]
    fn content_id_from_bytes_is_deterministic() {
        let content = b"hello world";
        let id1 = ContentId::from_bytes(content);
        let id2 = ContentId::from_bytes(content);
        assert_eq!(id1, id2);
    }

    #[test]
    fn content_id_streaming_matches_from_bytes_over_chunks() {
        // Bounded-memory transports compute content ids chunk-by-chunk; the
        // streamed result must be byte-identical to the all-at-once digest.
        let content: Vec<u8> = (0u32..5000).map(|i| (i % 251) as u8).collect();
        let one_shot = ContentId::from_bytes(&content);

        for chunk_size in [1usize, 7, 64, 256, 4096, content.len()] {
            let mut hasher = ContentId::streaming();
            for chunk in content.chunks(chunk_size.max(1)) {
                hasher.update(chunk);
            }
            assert_eq!(
                hasher.finalize(),
                one_shot,
                "streaming content id mismatch at chunk_size={chunk_size}"
            );
        }

        // Empty content must also agree.
        assert_eq!(
            ContentId::streaming().finalize(),
            ContentId::from_bytes(&[])
        );
    }

    #[test]
    fn content_id_uses_full_sha256_digest() {
        let id = ContentId::from_bytes(b"hello world");
        let mut hasher = Sha256::new();
        hasher.update(CONTENT_ID_DOMAIN);
        hasher.update(b"hello world");
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(id.hash(), &expected);
        assert!(id.hash()[8..].iter().any(|byte| *byte != 0));
    }

    #[test]
    fn manifest_id_is_domain_separated_from_content_id() {
        let canonical_bytes = b"{\"object\":\"same canonical bytes\"}";
        let content_id = ContentId::from_bytes(canonical_bytes);
        let manifest_id = ManifestId::from_manifest_bytes(canonical_bytes);

        assert_ne!(manifest_id.hash(), content_id.hash());

        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_ID_DOMAIN);
        hasher.update(canonical_bytes);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(manifest_id.hash(), &expected);
    }

    #[test]
    fn object_kinds_have_expected_properties() {
        assert!(ObjectKind::StreamObject.is_mutable());
        assert!(ObjectKind::ApplicationDefinedObject.is_mutable());
        assert!(!ObjectKind::FileObject.is_mutable());

        assert!(ObjectKind::DirectoryObject.can_contain_children());
        assert!(!ObjectKind::FileObject.can_contain_children());
        assert!(ObjectKind::ApplicationDefinedObject.can_contain_children());
    }

    #[test]
    fn file_object_creation_works() {
        let content = b"test content".to_vec();
        let file = Object::file(content.clone());

        assert_eq!(file.metadata.kind, ObjectKind::FileObject);
        assert_eq!(file.metadata.size_bytes, Some(content.len() as u64));
        assert_eq!(file.content, Some(content));
        assert!(file.children.is_empty());
        assert!(file.id.is_content_addressed());
    }

    #[test]
    fn directory_object_creation_works() {
        let child_id = ObjectId::content(ContentId::from_bytes(b"child"));
        let edge = ObjectEdge::new(child_id, "child.txt".to_string());
        let dir = Object::directory(vec![edge]);

        assert_eq!(dir.metadata.kind, ObjectKind::DirectoryObject);
        assert_eq!(dir.metadata.size_bytes, None);
        assert_eq!(dir.content, None);
        assert_eq!(dir.children.len(), 1);
        assert!(dir.id.is_manifest_addressed());
    }

    #[test]
    fn stream_object_creation_works() {
        let stream = Object::stream();

        assert_eq!(stream.metadata.kind, ObjectKind::StreamObject);
        assert!(stream.id.is_manifest_addressed());
        assert!(stream.children.is_empty());
    }

    #[test]
    fn stream_objects_get_distinct_manifest_ids() {
        let first = Object::stream();
        let second = Object::stream();

        assert_ne!(first.id, second.id);
    }

    #[test]
    fn application_defined_object_creation_works() {
        let mut metadata = BTreeMap::new();
        metadata.insert("key".to_string(), b"value".to_vec());

        let obj = Object::application_defined("test-extension".to_string(), 1, metadata.clone());

        assert_eq!(obj.metadata.kind, ObjectKind::ApplicationDefinedObject);
        assert!(obj.id.is_manifest_addressed());
        assert!(obj.metadata.application.is_some());

        let app_meta = obj.metadata.application.as_ref().unwrap();
        assert_eq!(app_meta.extension_type, "test-extension");
        assert_eq!(app_meta.schema_version, 1);
        assert_eq!(app_meta.metadata, metadata);
    }

    #[test]
    fn object_graph_basic_operations_work() {
        let mut graph = ObjectGraph::new();

        let file1 = Object::file(b"content1".to_vec());
        let file2 = Object::file(b"content2".to_vec());

        let file1_id = file1.id.clone();
        let file2_id = file2.id.clone();

        graph.add_root(file1).unwrap();
        graph.add_root(file2).unwrap();

        assert_eq!(graph.object_count(), 2);
        assert!(!graph.is_empty());
        assert!(graph.contains_object(&file1_id));
        assert!(graph.contains_object(&file2_id));

        let roots: BTreeSet<_> = graph.roots().cloned().collect();
        assert_eq!(roots.len(), 2);
        assert!(roots.contains(&file1_id));
        assert!(roots.contains(&file2_id));
    }

    #[test]
    fn object_graph_validation_detects_missing_children() {
        let mut graph = ObjectGraph::new();

        let missing_id = ObjectId::content(ContentId::from_bytes(b"missing"));
        let edge = ObjectEdge::new(missing_id.clone(), "missing.txt".to_string());
        let dir = Object::directory(vec![edge]);

        graph.add_root(dir).unwrap();

        let result = graph.validate();
        assert!(matches!(result, Err(ObjectGraphError::ObjectNotFound(id)) if id == missing_id));
    }

    #[test]
    fn object_graph_validation_detects_cycles() {
        let mut graph = ObjectGraph::new();

        // Create a cycle: dir1 -> dir2 -> dir1
        let dir1_id = ObjectId::content(ContentId::from_bytes(b"dir1"));
        let dir2_id = ObjectId::content(ContentId::from_bytes(b"dir2"));

        let edge1 = ObjectEdge::new(dir2_id.clone(), "dir2".to_string());
        let edge2 = ObjectEdge::new(dir1_id.clone(), "dir1".to_string());

        let mut dir1 = Object::directory(vec![edge1]);
        dir1.id = dir1_id.clone();

        let mut dir2 = Object::directory(vec![edge2]);
        dir2.id = dir2_id;

        graph.add_root(dir1).unwrap();
        graph.add_object(dir2).unwrap();

        let result = graph.validate();
        assert!(matches!(
            result,
            Err(ObjectGraphError::CircularReference(_))
        ));
    }

    #[test]
    fn metadata_policy_presets_work() {
        let portable = MetadataPolicy::portable();
        assert!(!portable.preserve_unix_permissions);
        assert!(!portable.preserve_timestamps);
        assert!(portable.verify_metadata);

        let full = MetadataPolicy::full_preservation();
        assert!(full.preserve_unix_permissions);
        assert!(full.preserve_timestamps);
        assert!(full.preserve_extended_attributes);

        let default = MetadataPolicy::default();
        assert!(default.preserve_unix_permissions);
        assert!(!default.preserve_timestamps);
    }

    #[test]
    fn object_edge_creation_works() {
        let id = ObjectId::content(ContentId::from_bytes(b"test"));
        let edge = ObjectEdge::new(id.clone(), "test.txt".to_string());

        assert_eq!(edge.child_id, id);
        assert_eq!(edge.name, "test.txt");
        assert!(!edge.is_symlink);
        assert!(edge.symlink_target.is_none());

        let symlink_edge = ObjectEdge::symlink(
            id.clone(),
            "link.txt".to_string(),
            PathBuf::from("/target/path"),
        );

        assert_eq!(symlink_edge.child_id, id);
        assert_eq!(symlink_edge.name, "link.txt");
        assert!(symlink_edge.is_symlink);
        assert_eq!(
            symlink_edge.symlink_target,
            Some(PathBuf::from("/target/path"))
        );
    }

    #[test]
    fn cannot_add_children_to_file_objects() {
        let mut file = Object::file(b"content".to_vec());
        let child_id = ObjectId::content(ContentId::from_bytes(b"child"));
        let edge = ObjectEdge::new(child_id, "child".to_string());

        let result = file.add_child(edge);
        assert!(matches!(
            result,
            Err(ObjectGraphError::CannotAddChildren(ObjectKind::FileObject))
        ));
    }

    #[test]
    fn duplicate_child_names_are_rejected() {
        let child_id1 = ObjectId::content(ContentId::from_bytes(b"child1"));
        let child_id2 = ObjectId::content(ContentId::from_bytes(b"child2"));

        let edge1 = ObjectEdge::new(child_id1, "same_name".to_string());
        let edge2 = ObjectEdge::new(child_id2, "same_name".to_string());

        let mut dir = Object::directory(vec![edge1]);
        let result = dir.add_child(edge2);

        assert!(matches!(
            result,
            Err(ObjectGraphError::DuplicateChildName(name)) if name == "same_name"
        ));
    }

    #[test]
    fn children_are_kept_sorted() {
        let child_id1 = ObjectId::content(ContentId::from_bytes(b"child1"));
        let child_id2 = ObjectId::content(ContentId::from_bytes(b"child2"));

        let edge1 = ObjectEdge::new(child_id1, "z_last".to_string());
        let edge2 = ObjectEdge::new(child_id2, "a_first".to_string());

        let dir = Object::directory(vec![edge1, edge2]);

        assert_eq!(dir.children.len(), 2);
        assert_eq!(dir.children[0].name, "a_first");
        assert_eq!(dir.children[1].name, "z_last");
    }

    #[test]
    fn all_object_kinds_are_listed() {
        assert_eq!(ObjectKind::ALL.len(), 9);
        assert!(ObjectKind::ALL.contains(&ObjectKind::FileObject));
        assert!(ObjectKind::ALL.contains(&ObjectKind::DirectoryObject));
        assert!(ObjectKind::ALL.contains(&ObjectKind::StreamObject));
        assert!(ObjectKind::ALL.contains(&ObjectKind::SnapshotObject));
        assert!(ObjectKind::ALL.contains(&ObjectKind::DatasetObject));
        assert!(ObjectKind::ALL.contains(&ObjectKind::ArtifactBundle));
        assert!(ObjectKind::ALL.contains(&ObjectKind::SparseImage));
        assert!(ObjectKind::ALL.contains(&ObjectKind::ContainerLayer));
        assert!(ObjectKind::ALL.contains(&ObjectKind::ApplicationDefinedObject));
    }

    #[test]
    fn object_graph_parent_index_tracks_objects_with_parents() {
        let mut graph = ObjectGraph::new();

        // Create file objects that will be children
        let child1 = Object::file(b"child1".to_vec());
        let child2 = Object::file(b"child2".to_vec());
        let child1_id = child1.id.clone();
        let child2_id = child2.id.clone();

        // Add children to graph first
        graph.add_object(child1).unwrap();
        graph.add_object(child2).unwrap();

        // Create directory with children
        let edge1 = ObjectEdge::new(child1_id.clone(), "child1.txt".to_string());
        let edge2 = ObjectEdge::new(child2_id.clone(), "child2.txt".to_string());
        let dir = Object::directory(vec![edge1, edge2]);
        let dir_id = dir.id.clone();

        // Add directory to graph
        graph.add_object(dir).unwrap();

        // Children should be tracked as having parents
        assert!(graph.has_parent(&child1_id), "child1 should have a parent");
        assert!(graph.has_parent(&child2_id), "child2 should have a parent");

        // Directory should not have a parent (it's a root)
        assert!(
            !graph.has_parent(&dir_id),
            "directory should not have a parent"
        );
    }

    #[test]
    fn object_graph_parent_index_maintains_o1_lookup_performance() {
        let mut graph = ObjectGraph::new();

        // Create a hierarchy: root -> intermediate -> leaf
        let leaf = Object::file(b"leaf content".to_vec());
        let leaf_id = leaf.id.clone();

        let edge_to_leaf = ObjectEdge::new(leaf_id.clone(), "leaf.txt".to_string());
        let intermediate = Object::directory(vec![edge_to_leaf]);
        let intermediate_id = intermediate.id.clone();

        let edge_to_intermediate =
            ObjectEdge::new(intermediate_id.clone(), "intermediate".to_string());
        let root = Object::directory(vec![edge_to_intermediate]);
        let root_id = root.id.clone();

        // Add objects in order
        graph.add_object(leaf).unwrap();
        graph.add_object(intermediate).unwrap();
        graph.add_root(root).unwrap();

        // Check parent relationships (these should be O(1) lookups)
        assert!(!graph.has_parent(&root_id), "root should not have parent");
        assert!(
            graph.has_parent(&intermediate_id),
            "intermediate should have parent"
        );
        assert!(graph.has_parent(&leaf_id), "leaf should have parent");

        // Verify that objects_with_parents set contains exactly the non-root objects
        assert_eq!(graph.objects_with_parents.len(), 2);
        assert!(graph.objects_with_parents.contains(&intermediate_id));
        assert!(graph.objects_with_parents.contains(&leaf_id));
        assert!(!graph.objects_with_parents.contains(&root_id));
    }

    #[test]
    fn object_graph_parent_index_removes_from_roots_when_child_added() {
        let mut graph = ObjectGraph::new();

        // Create a file that starts as a root
        let file = Object::file(b"content".to_vec());
        let file_id = file.id.clone();

        // Add as root initially
        graph.add_root(file).unwrap();

        // Verify it's in roots and not in objects_with_parents
        assert!(graph.roots().any(|root| root == &file_id));
        assert!(!graph.has_parent(&file_id));

        // Create a directory that contains the file as a child
        let edge = ObjectEdge::new(file_id.clone(), "file.txt".to_string());
        let dir = Object::directory(vec![edge]);
        let dir_id = dir.id.clone();

        // Add directory (which will update parent index for its children)
        graph.add_object(dir).unwrap();

        // File should now have a parent and be removed from roots
        assert!(graph.has_parent(&file_id), "file should now have a parent");
        assert!(
            !graph.has_parent(&dir_id),
            "directory should not have a parent"
        );

        // Check roots - file should be removed, directory remains a parentless root
        let roots: Vec<_> = graph.roots().cloned().collect();
        assert!(
            !roots.contains(&file_id),
            "file should be removed from roots"
        );
        assert!(
            roots.contains(&dir_id),
            "directory should be a root until another object parents it"
        );
    }

    #[test]
    fn object_graph_parent_index_consistency_with_existing_objects() {
        let mut graph = ObjectGraph::new();

        // Create multiple files
        let file1 = Object::file(b"file1".to_vec());
        let file2 = Object::file(b"file2".to_vec());
        let file3 = Object::file(b"file3".to_vec());

        let file1_id = file1.id.clone();
        let file2_id = file2.id.clone();
        let file3_id = file3.id.clone();

        // Add files first (they start as potential roots)
        graph.add_object(file1).unwrap();
        graph.add_object(file2).unwrap();
        graph.add_object(file3).unwrap();

        // Initially no files have parents
        assert!(!graph.has_parent(&file1_id));
        assert!(!graph.has_parent(&file2_id));
        assert!(!graph.has_parent(&file3_id));

        // Create directory that references some files
        let edge1 = ObjectEdge::new(file1_id.clone(), "file1.txt".to_string());
        let edge2 = ObjectEdge::new(file2_id.clone(), "file2.txt".to_string());
        // file3 is not referenced, so it remains without parent

        let dir = Object::directory(vec![edge1, edge2]);
        graph.add_object(dir).unwrap();

        // Check final parent states
        assert!(graph.has_parent(&file1_id), "file1 should have parent");
        assert!(graph.has_parent(&file2_id), "file2 should have parent");
        assert!(!graph.has_parent(&file3_id), "file3 should not have parent");

        // Verify parent index contents
        assert_eq!(graph.objects_with_parents.len(), 2);
        assert!(graph.objects_with_parents.contains(&file1_id));
        assert!(graph.objects_with_parents.contains(&file2_id));
        assert!(!graph.objects_with_parents.contains(&file3_id));
    }

    #[test]
    fn canonical_children_bytes_resist_field_boundary_collisions() {
        // Without length prefixes, the symlink target of one edge could trade
        // bytes with the following edge's name ("xy" + "b" vs "x" + "yb") and
        // produce identical canonical bytes for structurally different
        // directories. Compare the encodings directly so edge sort order
        // cannot mask the collision.
        let child_a = ObjectId::content(ContentId::from_bytes(b"child-a"));
        let child_b = ObjectId::content(ContentId::from_bytes(b"child-b"));

        let edges1 = vec![
            ObjectEdge::symlink(child_a.clone(), "a".to_string(), PathBuf::from("xy")),
            ObjectEdge::new(child_b.clone(), "b".to_string()),
        ];
        let edges2 = vec![
            ObjectEdge::symlink(child_a, "a".to_string(), PathBuf::from("x")),
            ObjectEdge::new(child_b, "yb".to_string()),
        ];

        assert_ne!(
            Object::canonical_children_bytes(&edges1),
            Object::canonical_children_bytes(&edges2),
            "different child structures must not collide on canonical bytes"
        );
    }

    #[test]
    fn canonical_app_metadata_bytes_resist_field_boundary_collisions() {
        // Key/value bytes must not be able to migrate across field boundaries.
        let obj1 = Object::application_defined(
            "ext".to_string(),
            1,
            BTreeMap::from([("ab".to_string(), b"c".to_vec())]),
        );
        let obj2 = Object::application_defined(
            "ext".to_string(),
            1,
            BTreeMap::from([("a".to_string(), b"bc".to_vec())]),
        );

        assert_ne!(
            obj1.id, obj2.id,
            "different application metadata must not collide on manifest ID"
        );
    }
