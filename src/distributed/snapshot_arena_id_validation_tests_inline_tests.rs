    use super::*;

    fn arena_id_bytes(index: u32, generation: u32) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&index.to_le_bytes());
        bytes[4..].copy_from_slice(&generation.to_le_bytes());
        bytes
    }

    #[test]
    fn snapshot_arena_id_contract_accepts_boundary_values() {
        assert!(snapshot_arena_id_is_admissible(
            SNAPSHOT_ARENA_ID_MAX_INDEX,
            u32::MAX
        ));

        let bytes = arena_id_bytes(SNAPSHOT_ARENA_ID_MAX_INDEX, u32::MAX);
        let region_id = Cursor::new(&bytes)
            .read_region_id()
            .expect("boundary RegionId must decode");
        let task_id = Cursor::new(&bytes)
            .read_task_id()
            .expect("boundary TaskId must decode");

        assert_eq!(region_id.arena_index().index(), SNAPSHOT_ARENA_ID_MAX_INDEX);
        assert_eq!(region_id.arena_index().generation(), u32::MAX);
        assert_eq!(task_id.arena_index().index(), SNAPSHOT_ARENA_ID_MAX_INDEX);
        assert_eq!(task_id.arena_index().generation(), u32::MAX);
    }

    #[test]
    fn read_region_id_rejects_index_above_wire_contract() {
        let index = SNAPSHOT_ARENA_ID_MAX_INDEX + 1;
        let generation = 0;
        let bytes = arena_id_bytes(index, generation);

        assert_eq!(
            Cursor::new(&bytes).read_region_id().unwrap_err(),
            SnapshotError::InvalidRegionId { index, generation }
        );
    }

    #[test]
    fn read_task_id_rejects_index_above_wire_contract() {
        let index = SNAPSHOT_ARENA_ID_MAX_INDEX + 1;
        let generation = 0;
        let bytes = arena_id_bytes(index, generation);

        assert_eq!(
            Cursor::new(&bytes).read_task_id().unwrap_err(),
            SnapshotError::InvalidTaskId { index, generation }
        );
    }

    #[test]
    fn asupersync_8mp6md_snapshot_generation_past_legacy_cap_roundtrips() {
        let region_id = RegionId::new_for_test(7, 10_001);
        let task_id = TaskId::new_for_test(9, u32::MAX);
        let child_id = RegionId::new_for_test(11, 50_000);
        let mut snapshot = RegionSnapshot::empty(region_id);
        snapshot.tasks.push(TaskSnapshot {
            task_id,
            state: TaskState::Running,
            priority: 3,
        });
        snapshot.children.push(child_id);

        let restored = RegionSnapshot::from_bytes(&snapshot.to_bytes())
            .expect("the reader must accept every generation emitted by the writer");

        assert_eq!(restored.region_id, region_id);
        assert_eq!(restored.tasks[0].task_id, task_id);
        assert_eq!(restored.children, vec![child_id]);
    }

    #[test]
    fn snapshot_decode_rejects_root_region_index_above_wire_contract() {
        let index = SNAPSHOT_ARENA_ID_MAX_INDEX + 1;
        let generation = 0;
        let mut bytes = RegionSnapshot::empty(RegionId::new_for_test(1, 0)).to_bytes();
        let root_region_index_offset = SNAP_MAGIC.len() + 1;
        bytes[root_region_index_offset..root_region_index_offset + 4]
            .copy_from_slice(&index.to_le_bytes());

        assert_eq!(
            RegionSnapshot::from_bytes(&bytes).unwrap_err(),
            SnapshotError::InvalidRegionId { index, generation }
        );
    }
