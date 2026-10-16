    use super::*;

    #[test]
    fn topology_accepts_actor_owned_children() {
        let topology =
            TransferActorTopology::new(TransferRegionId::new(1), TransferRegionId::new(2))
                .with_child(TransferRegionId::new(3), TransferChildRole::PathRace)
                .with_child(TransferRegionId::new(4), TransferChildRole::Writer);

        assert!(topology.validate().is_ok());
        assert!(!topology.has_detached_child());
    }

    #[test]
    fn topology_rejects_detached_children() {
        let mut topology =
            TransferActorTopology::new(TransferRegionId::new(1), TransferRegionId::new(2));
        topology.child_regions.push(TransferChildRegion::new(
            TransferRegionId::new(3),
            TransferRegionId::new(99),
            TransferChildRole::Relay,
        ));

        assert!(matches!(
            topology.validate(),
            Err(TransferTopologyError::DetachedChild { .. })
        ));
        assert!(topology.has_detached_child());
    }
