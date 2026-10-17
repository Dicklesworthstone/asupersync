    use super::*;

    fn chunk(content_id: &str, size: u64) -> DeltaChunkWire {
        DeltaChunkWire {
            index: 0,
            entry_index: 0,
            rel_path: "f".to_string(),
            entry_offset: 0,
            stream_offset: 0,
            size_bytes: size,
            content_id_hex: content_id.to_string(),
        }
    }

    fn missing_ids(plan: &RqDeltaChunkPlan) -> Vec<String> {
        plan.missing_chunks
            .iter()
            .map(|c| c.content_id_hex.clone())
            .collect()
    }

    #[test]
    fn append_ships_only_the_new_tail_chunk() {
        let sender = [chunk("A", 10), chunk("B", 20), chunk("C", 30)];
        let receiver = [chunk("A", 10), chunk("B", 20)];
        let plan = rq_plan_delta_chunks(&sender, &receiver);
        assert_eq!(missing_ids(&plan), vec!["C"]);
        assert_eq!(plan.shared_chunks, 2);
        assert_eq!(plan.stale_chunks, 0);
        assert_eq!(plan.missing_bytes, 30);
    }

    #[test]
    fn insert_ships_only_the_inserted_chunk_shifted_tail_is_reused() {
        // Content-defined chunking: inserting X keeps A,B,C ids stable.
        let sender = [chunk("A", 10), chunk("X", 5), chunk("B", 20), chunk("C", 30)];
        let receiver = [chunk("A", 10), chunk("B", 20), chunk("C", 30)];
        let plan = rq_plan_delta_chunks(&sender, &receiver);
        assert_eq!(missing_ids(&plan), vec!["X"]);
        assert_eq!(plan.shared_chunks, 3);
        assert_eq!(plan.stale_chunks, 0);
        assert_eq!(plan.missing_bytes, 5);
    }

    #[test]
    fn small_edit_ships_the_changed_chunk_and_marks_the_old_stale() {
        let sender = [chunk("A", 10), chunk("Bx", 20), chunk("C", 30)];
        let receiver = [chunk("A", 10), chunk("B", 20), chunk("C", 30)];
        let plan = rq_plan_delta_chunks(&sender, &receiver);
        assert_eq!(missing_ids(&plan), vec!["Bx"]);
        assert_eq!(plan.shared_chunks, 2); // A, C
        assert_eq!(plan.stale_chunks, 1); // old B
        assert_eq!(plan.missing_bytes, 20);
    }

    #[test]
    fn identical_manifests_ship_nothing() {
        let both = [chunk("A", 10), chunk("B", 20), chunk("C", 30)];
        let plan = rq_plan_delta_chunks(&both, &both);
        assert!(plan.missing_chunks.is_empty());
        assert_eq!(plan.shared_chunks, 3);
        assert_eq!(plan.stale_chunks, 0);
        assert_eq!(plan.missing_bytes, 0);
    }

    #[test]
    fn duplicate_content_is_served_from_one_local_copy() {
        // Receiver holds A once; both sender references to A are shared.
        let sender = [chunk("A", 10), chunk("A", 10)];
        let receiver = [chunk("A", 10)];
        let plan = rq_plan_delta_chunks(&sender, &receiver);
        assert!(plan.missing_chunks.is_empty());
        assert_eq!(plan.shared_chunks, 2);
        assert_eq!(plan.missing_bytes, 0);
    }
