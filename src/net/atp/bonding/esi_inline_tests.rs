    use super::*;
    use std::collections::BTreeSet;

    const DONOR_COUNTS: [u32; 5] = [1, 2, 3, 5, 8];
    const COVERAGE_LIMIT: u32 = 257;

    #[test]
    fn static_partitions_cover_prefix_without_overlap() {
        for donor_count in DONOR_COUNTS {
            let mut owner_by_esi = vec![None; COVERAGE_LIMIT as usize];

            for donor_index in 0..donor_count {
                let partition =
                    EsiPartition::new(donor_index, donor_count).expect("valid donor partition");

                for esi in 0..COVERAGE_LIMIT {
                    let owned = partition.owns_esi(esi);
                    assert_eq!(owned, esi % donor_count == donor_index);

                    if owned {
                        let owner = &mut owner_by_esi[esi as usize];
                        assert!(
                            owner.is_none(),
                            "ESI {esi} already owned by donor {:?} when donor {donor_index} claimed it",
                            owner
                        );
                        *owner = Some(donor_index);
                    }
                }
            }

            for (esi, owner) in owner_by_esi.iter().enumerate() {
                assert!(
                    owner.is_some(),
                    "donor_count {donor_count} left ESI {esi} unassigned"
                );
            }
        }
    }

    #[test]
    fn static_partitions_span_source_and_repair_ranges() {
        const SOURCE_SYMBOLS: u32 = 37;
        const REPAIR_LIMIT: u32 = SOURCE_SYMBOLS + 89;

        for donor_count in DONOR_COUNTS {
            let mut source_seen = BTreeSet::new();
            let mut repair_seen = BTreeSet::new();

            for donor_index in 0..donor_count {
                let partition =
                    EsiPartition::new(donor_index, donor_count).expect("valid donor partition");

                let source_owned = (0..SOURCE_SYMBOLS)
                    .filter(|esi| partition.owns_esi(*esi))
                    .collect::<Vec<_>>();
                let repair_owned = (SOURCE_SYMBOLS..REPAIR_LIMIT)
                    .filter(|esi| partition.owns_esi(*esi))
                    .collect::<Vec<_>>();

                assert!(
                    !source_owned.is_empty(),
                    "donor {donor_index}/{donor_count} owns no source ESIs"
                );
                assert!(
                    !repair_owned.is_empty(),
                    "donor {donor_index}/{donor_count} owns no repair ESIs"
                );

                for esi in source_owned {
                    assert!(esi < SOURCE_SYMBOLS);
                    assert_eq!(esi % donor_count, donor_index);
                    assert!(
                        source_seen.insert(esi),
                        "source ESI {esi} was assigned to multiple donors"
                    );
                }

                for esi in repair_owned {
                    assert!(esi >= SOURCE_SYMBOLS);
                    assert!(esi < REPAIR_LIMIT);
                    assert_eq!(esi % donor_count, donor_index);
                    assert!(
                        repair_seen.insert(esi),
                        "repair ESI {esi} was assigned to multiple donors"
                    );
                }
            }

            assert_eq!(source_seen.len(), SOURCE_SYMBOLS as usize);
            assert_eq!(repair_seen.len(), (REPAIR_LIMIT - SOURCE_SYMBOLS) as usize);
        }
    }

    #[test]
    fn donor_streams_are_pairwise_disjoint() {
        for donor_count in DONOR_COUNTS {
            let mut seen = BTreeSet::new();

            for donor_index in 0..donor_count {
                for esi in donor_esi_stream(donor_index, donor_count)
                    .expect("valid donor stream")
                    .take(64)
                {
                    assert!(
                        seen.insert(esi),
                        "donor_count {donor_count} assigned ESI {esi} to multiple donors"
                    );
                }
            }
        }
    }

    #[test]
    fn donor_count_one_owns_every_esi() {
        let partition = EsiPartition::new(0, 1).expect("single-donor partition");

        for esi in [0, 1, 2, 127, u32::MAX] {
            assert!(partition.owns_esi(esi));
            assert_eq!(owns_esi(0, 1, esi), Ok(true));
        }

        assert_eq!(
            donor_esi_stream(0, 1)
                .expect("single donor stream")
                .take(6)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn esi_for_donor_matches_residue_sequence() {
        for donor_count in DONOR_COUNTS {
            for donor_index in 0..donor_count {
                let expected = (0..16)
                    .map(|sequence| donor_index + donor_count * sequence)
                    .collect::<Vec<_>>();
                let actual = donor_esi_stream(donor_index, donor_count)
                    .expect("valid donor stream")
                    .take(expected.len())
                    .collect::<Vec<_>>();

                assert_eq!(actual, expected);

                for (sequence, esi) in expected.into_iter().enumerate() {
                    assert_eq!(
                        esi_for_donor(donor_index, donor_count, sequence as u32),
                        Ok(esi)
                    );
                    assert_eq!(owns_esi(donor_index, donor_count, esi), Ok(true));
                }
            }
        }
    }

    #[test]
    fn invalid_partitions_fail_closed() {
        assert_eq!(EsiPartition::new(0, 0), Err(EsiPartitionError::ZeroDonors));
        assert_eq!(
            EsiPartition::new(2, 2),
            Err(EsiPartitionError::DonorIndexOutOfRange {
                donor_index: 2,
                donor_count: 2,
            })
        );
        assert_eq!(
            owns_esi(2, 2, 0),
            Err(EsiPartitionError::DonorIndexOutOfRange {
                donor_index: 2,
                donor_count: 2,
            })
        );
    }

    #[test]
    fn overflow_is_reported_and_stream_exhausts_cleanly() {
        assert_eq!(
            esi_for_donor(u32::MAX - 1, u32::MAX, 1),
            Err(EsiPartitionError::SequenceOverflow {
                donor_index: u32::MAX - 1,
                donor_count: u32::MAX,
                sequence: 1,
            })
        );

        let mut sparse_stream =
            donor_esi_stream(u32::MAX - 1, u32::MAX).expect("largest valid donor stream");
        assert_eq!(sparse_stream.next(), Some(u32::MAX - 1));
        assert_eq!(sparse_stream.next(), None);
        assert_eq!(sparse_stream.next(), None);

        let mut full_u32_stream = donor_esi_stream(0, 1).expect("single donor stream");
        full_u32_stream.next_sequence = Some(u32::MAX);
        assert_eq!(full_u32_stream.next(), Some(u32::MAX));
        assert_eq!(full_u32_stream.next(), None);
    }
