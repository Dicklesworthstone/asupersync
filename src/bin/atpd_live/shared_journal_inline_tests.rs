    use super::super::super::{Cli, Command};
    use super::*;
    use clap::Parser;

    #[test]
    fn shared_journal_cli_requires_explicit_catalog_and_storage_budgets() {
        let args = [
            "atpd-live",
            "serve-journaled",
            "--config",
            "receiver.json",
            "--catalog",
            "/state/catalog",
            "--max-sessions",
            "2",
            "--max-sessions-per-client",
            "1",
            "--max-session-keys",
            "8",
            "--attempts-per-session",
            "8",
            "--journal-snapshots",
            "32",
            "--journal-bytes",
            "65536",
        ];
        assert!(matches!(
            Cli::try_parse_from(args).unwrap().command,
            Command::ServeJournaled { .. }
        ));
        assert!(Cli::try_parse_from(&args[..args.len() - 2]).is_err());
        assert!(
            JournalOptions {
                journal_snapshots: 0,
                journal_bytes: 65536
            }
            .policy(64)
            .is_err()
        );
        assert!(
            JournalOptions {
                journal_snapshots: 32,
                journal_bytes: 128 * 1024 * 1024 + 1
            }
            .policy(64)
            .is_err()
        );
        assert!(
            JournalOptions {
                journal_snapshots: 32,
                journal_bytes: 65536
            }
            .policy(0)
            .is_ok()
        );
    }

    #[test]
    fn restart_reserves_growth_for_disconnected_sessions_before_new_admission() {
        let root = tempfile::tempdir().unwrap().keep();
        let state = root.join("state");
        let inbox = root.join("inbox");
        for path in [&state, &inbox] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = state.join("catalog");
        Catalog::initialize(&path, 4, 65536).unwrap();
        let catalog = Catalog::open(&path).unwrap();
        let id = settings::selector(&"11".repeat(32)).unwrap();
        let policy = FilePolicy {
            data_bytes: 64,
            journal_bytes: 4096,
            snapshots: 16,
        };
        let (entry, _) = catalog
            .admit(
                ResumeSessionKey {
                    client: id,
                    nonce: [3; 32],
                },
                &inbox,
                policy,
            )
            .unwrap();
        let data = entry.data_path(&inbox);
        std::fs::write(&data, b"abc").unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = settings::InboxConfig {
            certificate_sha256: "11".repeat(32),
            directory: inbox,
            max_retained_bytes: 64,
            max_retained_entries: 3,
        };
        let inboxes = storage::load(&[config]).unwrap();
        reserve_restored(&catalog, &inboxes, 64).unwrap();
        assert_eq!(
            inboxes[&id]
                .reserve_private_file(1, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::StorageFull
        );
        assert!(reserve_restored(&catalog, &inboxes, 63).is_err());
        assert_eq!(std::fs::read(data).unwrap(), b"abc");
    }
