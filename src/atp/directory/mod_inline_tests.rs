    use super::*;
    use tempfile::tempdir;

    fn peer(label: &str) -> PeerId {
        PeerId::from_label(label)
    }

    fn directory_with_alice() -> PeerDirectory {
        let mut directory = PeerDirectory::new();
        let alice_id = peer("alice");
        let mut alice = PeerRecord::new(alice_id, "Alice").expect("peer");
        alice.aliases.insert("alice@example".to_string());
        alice.path_hints.push(PathHint {
            kind: "lan".to_string(),
            endpoint: "192.168.1.10:4433".to_string(),
            last_seen_micros: 10,
            expires_at_micros: 20,
            trust_scope: Some(TrustScope::Personal),
        });
        directory.upsert_peer(alice, None);
        directory
            .upsert_device(
                alice_id,
                DeviceRecord::new(alice_id, "laptop", "gpu-box").expect("device"),
                None,
            )
            .expect("device");
        directory
    }

    #[test]
    fn resolves_unique_peer_and_requires_disambiguation_for_ambiguous_names() {
        let mut directory = directory_with_alice();
        let bob_id = peer("bob");
        let bob = PeerRecord::new(bob_id, "gpu-box").expect("peer");
        directory.upsert_peer(bob, None);

        assert_eq!(
            directory.resolve_name("alice").expect("alice"),
            DirectorySubject::Peer(peer("alice"))
        );
        let err = directory.resolve_name("gpu-box").expect_err("ambiguous");
        assert!(matches!(err, DirectoryError::AmbiguousName { .. }));
    }

    #[test]
    fn renamed_device_keeps_old_name_as_alias() {
        let mut directory = directory_with_alice();
        let alice_id = peer("alice");
        directory
            .rename_device(alice_id, "laptop", "workstation", None)
            .expect("rename");

        let subject = directory.resolve_name("gpu-box").expect("old alias");
        assert_eq!(
            subject,
            DirectorySubject::Device {
                peer_id: alice_id,
                device_id: "laptop".to_string()
            }
        );
        let view = directory.inspect(&subject).expect("inspect"); // ubs:ignore - test oracle
        let DirectoryEntryView::Device(device) = view else {
            panic!("expected device"); // ubs:ignore - test oracle
        };
        assert_eq!(device.device_name, "workstation");
    }

    #[test]
    fn group_grants_preserve_constraints_for_members() {
        let mut directory = directory_with_alice();
        let alice_id = peer("alice");
        let mut grant = DirectoryGrant::new(
            "grant-team-read",
            TrustScope::Team("eng".to_string()),
            ["read"],
        )
        .expect("grant");
        grant
            .constraints
            .insert("max_bytes".to_string(), "1048576".to_string());
        directory.upsert_group(GroupRecord::new("eng", "Engineering").expect("group"), None);
        directory
            .add_group_member("eng", DirectorySubject::Peer(alice_id), None)
            .expect("member");
        directory
            .attach_grant(
                DirectorySubject::Group("eng".to_string()),
                grant.clone(),
                None,
            )
            .expect("grant");

        let resolved = directory.resolve_group_grants("eng").expect("resolve");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].grant.constraints, grant.constraints);
        assert_eq!(
            resolved[0].grant.trust_scope,
            TrustScope::Team("eng".to_string())
        );
    }

    #[test]
    fn revoked_peer_no_longer_resolves_and_is_audited() {
        let mut directory = directory_with_alice();
        directory
            .revoke_peer(DirectorySubject::Peer(peer("alice")), "lost key", None)
            .expect("revoke");

        assert!(matches!(
            directory.resolve_name("alice"),
            Err(DirectoryError::NameNotFound(_))
        ));
        assert!(
            directory
                .audit_log
                .iter()
                .any(|record| record.operation == DirectoryOperation::PeerRevoked)
        );
    }

    #[test]
    fn stale_path_hints_are_reported() {
        let directory = directory_with_alice();
        let stale = directory.stale_path_hints(21);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].hint.endpoint, "192.168.1.10:4433");
    }

    #[test]
    fn directory_round_trips_as_json_with_audit_log() {
        let directory = directory_with_alice();
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("peers.json");
        directory.save_json(&path).expect("save");
        let loaded = PeerDirectory::load_json(&path).expect("load");

        assert_eq!(loaded.schema_version, PEER_DIRECTORY_SCHEMA_V1);
        assert_eq!(loaded.peers.len(), 1);
        assert!(!loaded.audit_log.is_empty());
    }
