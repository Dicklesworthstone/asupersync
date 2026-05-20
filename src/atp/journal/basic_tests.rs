//! Basic tests for ATP journal functionality

#[cfg(test)]
mod basic_tests {
    use crate::atp::journal::{ChunkState, JournalConfig};
    use std::path::PathBuf;

    #[test]
    fn test_chunk_state_transitions() {
        let state = ChunkState::Wanted;
        assert_eq!(state, ChunkState::Wanted);

        // Basic state transitions
        assert_ne!(ChunkState::Wanted, ChunkState::Received);
        assert_ne!(ChunkState::Received, ChunkState::Verified);
        assert_ne!(ChunkState::Verified, ChunkState::Written);
    }

    #[test]
    fn test_journal_config_default() {
        let config = JournalConfig {
            base_dir: PathBuf::from("/tmp/test"),
            ..Default::default()
        };

        assert!(config.max_journal_size > 0);
        assert!(config.max_generations > 0);
    }
}
