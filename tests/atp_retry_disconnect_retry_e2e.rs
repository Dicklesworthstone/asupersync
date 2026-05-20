//! ATP Disconnect Retry E2E Test
//!
//! Tests idempotency key behavior during connection interruptions.

use asupersync::net::atp::protocol::outcome::{
    AtpError, AtpOutcome, IdempotencyKey, OutcomeClass, RetryPolicy, TransferTranscript,
    TransportError,
};

#[test]
fn disconnect_retry_preserves_idempotency() {
    // Simulate a file transfer with connection interruption
    let manifest_hash = b"test_manifest_sha256_hash";
    let peer_id = "peer_12345";
    let timestamp = 1000000000u64;

    // Initial transfer attempt
    let transfer_id = "transfer_abc123";
    let idempotency_key = IdempotencyKey::offer(manifest_hash, peer_id, timestamp);

    let mut transcript = TransferTranscript::new(
        transfer_id.to_string(),
        idempotency_key.clone(),
        manifest_hash.to_vec(),
        peer_id.to_string(),
        timestamp,
        1024 * 1024, // 1MB transfer
        100,         // 100 chunks
    );

    // Simulate partial progress before disconnect
    transcript.update_chunks_completed(50);
    transcript.add_path_attempt("direct_path".to_string());

    // Simulate connection timeout error
    let disconnect_outcome: AtpOutcome<()> =
        AtpOutcome::transport_error(TransportError::ConnectionTimeout);

    let end_time = timestamp + 30_000_000_000; // 30 seconds later
    transcript.complete(&disconnect_outcome, end_time);

    assert_eq!(transcript.outcome_class, OutcomeClass::Error);
    assert_eq!(
        transcript.error_code,
        Some("transport_connection_timeout".to_string())
    );
    assert_eq!(transcript.chunks_completed, 50);

    // Verify retry policy would allow retry
    let retry_policy = RetryPolicy::default_transfer();
    assert!(retry_policy.should_retry(&disconnect_outcome, 1));

    // Simulate retry with same idempotency key
    let retry_key = IdempotencyKey::offer(manifest_hash, peer_id, timestamp);
    assert_eq!(
        idempotency_key, retry_key,
        "Idempotency key must be identical for retry"
    );

    // Create retry transcript
    let mut retry_transcript = TransferTranscript::new(
        transfer_id.to_string(),
        retry_key,
        manifest_hash.to_vec(),
        peer_id.to_string(),
        end_time + 1000_000_000, // 1 second later
        1024 * 1024,
        100,
    );

    retry_transcript.set_retry_attempt(1);
    retry_transcript.add_path_attempt("relay_path".to_string());

    // Simulate successful completion on retry
    retry_transcript.update_chunks_completed(100);
    let success_outcome: AtpOutcome<()> = AtpOutcome::ok(());
    retry_transcript.complete(&success_outcome, end_time + 60_000_000_000); // 1 minute later

    assert_eq!(retry_transcript.outcome_class, OutcomeClass::Success);
    assert_eq!(retry_transcript.chunks_completed, 100);
    assert_eq!(retry_transcript.retry_attempt, 1);
    assert!(retry_transcript.progress_percent() == 100.0);
}

#[test]
fn duplicate_offer_detection() {
    let manifest_hash = b"duplicate_test_hash";
    let peer_id = "peer_duplicate";
    let timestamp = 1234567890u64;

    // First offer
    let key1 = IdempotencyKey::offer(manifest_hash, peer_id, timestamp);

    // Exact duplicate offer (should have same key)
    let key2 = IdempotencyKey::offer(manifest_hash, peer_id, timestamp);
    assert_eq!(key1, key2, "Duplicate offers must have identical keys");

    // Different timestamp (different key)
    let key3 = IdempotencyKey::offer(manifest_hash, peer_id, timestamp + 1);
    assert_ne!(
        key1, key3,
        "Offers with different timestamps must have different keys"
    );

    // Different peer (different key)
    let key4 = IdempotencyKey::offer(manifest_hash, "different_peer", timestamp);
    assert_ne!(
        key1, key4,
        "Offers from different peers must have different keys"
    );

    // Different manifest (different key)
    let key5 = IdempotencyKey::offer(b"different_manifest", peer_id, timestamp);
    assert_ne!(
        key1, key5,
        "Offers for different manifests must have different keys"
    );
}

#[test]
fn chunk_retry_idempotency() {
    let transfer_id = "chunk_retry_test";

    // First attempt at chunk 42
    let key1 = IdempotencyKey::chunk(transfer_id, 42, 1);

    // Retry same chunk (same attempt number - should be identical)
    let key1_dup = IdempotencyKey::chunk(transfer_id, 42, 1);
    assert_eq!(
        key1, key1_dup,
        "Chunk retry with same attempt should have same key"
    );

    // Different attempt number (different key)
    let key2 = IdempotencyKey::chunk(transfer_id, 42, 2);
    assert_ne!(
        key1, key2,
        "Chunk retry with different attempt should have different key"
    );

    // Different chunk index (different key)
    let key3 = IdempotencyKey::chunk(transfer_id, 43, 1);
    assert_ne!(key1, key3, "Different chunk should have different key");
}

#[test]
fn retry_policy_timeout_backoff() {
    let policy = RetryPolicy::default_transfer();

    // Test delay calculation
    let delay1 = policy.delay_for_attempt(1);
    let delay2 = policy.delay_for_attempt(2);
    let delay3 = policy.delay_for_attempt(3);

    // Should follow exponential backoff
    assert!(delay2 > delay1, "Delay should increase with retry attempts");
    assert!(delay3 > delay2, "Delay should increase with retry attempts");

    // Should not exceed max attempts
    let timeout_error: AtpOutcome<()> =
        AtpOutcome::transport_error(TransportError::ConnectionTimeout);

    assert!(policy.should_retry(&timeout_error, 1));
    assert!(policy.should_retry(&timeout_error, 2));
    assert!(
        !policy.should_retry(&timeout_error, 3),
        "Should not retry after max attempts"
    );
}

#[test]
fn mailbox_store_idempotency() {
    let mailbox_id = "user_mailbox_123";
    let message_hash = b"message_content_hash";

    // First store attempt
    let key1 = IdempotencyKey::mailbox_store(mailbox_id, message_hash, 1);

    // Duplicate store attempt (same sequence)
    let key1_dup = IdempotencyKey::mailbox_store(mailbox_id, message_hash, 1);
    assert_eq!(
        key1, key1_dup,
        "Duplicate mailbox store should have same key"
    );

    // Different sequence number
    let key2 = IdempotencyKey::mailbox_store(mailbox_id, message_hash, 2);
    assert_ne!(key1, key2, "Different sequence should have different key");

    // Different message
    let key3 = IdempotencyKey::mailbox_store(mailbox_id, b"different_message", 1);
    assert_ne!(key1, key3, "Different message should have different key");
}

#[test]
fn grant_and_revocation_idempotency() {
    let issuer_id = "authority_node";
    let subject_id = "client_node";
    let capability_hash = b"capability_definition_hash";
    let expiry = 1700000000u64;

    // Grant capability
    let grant_key = IdempotencyKey::grant(issuer_id, subject_id, capability_hash, expiry);

    // Duplicate grant (same parameters)
    let grant_key_dup = IdempotencyKey::grant(issuer_id, subject_id, capability_hash, expiry);
    assert_eq!(
        grant_key, grant_key_dup,
        "Duplicate grants should have same key"
    );

    // Different expiry
    let grant_key_diff =
        IdempotencyKey::grant(issuer_id, subject_id, capability_hash, expiry + 3600);
    assert_ne!(
        grant_key, grant_key_diff,
        "Grants with different expiry should have different keys"
    );

    // Different subject
    let grant_key_subj =
        IdempotencyKey::grant(issuer_id, "different_client", capability_hash, expiry);
    assert_ne!(
        grant_key, grant_key_subj,
        "Grants to different subjects should have different keys"
    );
}

#[test]
fn transcript_progress_tracking() {
    let key = IdempotencyKey::new("progress_test");
    let mut transcript = TransferTranscript::new(
        "transfer_progress".to_string(),
        key,
        vec![1, 2, 3, 4],
        "peer".to_string(),
        0,
        1000,
        10, // 10 chunks total
    );

    // Initial state
    assert_eq!(transcript.progress_percent(), 0.0);
    assert!(!transcript.is_complete());

    // Partial progress
    transcript.update_chunks_completed(3);
    assert_eq!(transcript.progress_percent(), 30.0);

    transcript.update_chunks_completed(7);
    assert_eq!(transcript.progress_percent(), 70.0);

    // Track repair groups
    transcript.increment_repair_groups();
    transcript.increment_repair_groups();
    assert_eq!(transcript.repair_groups_used, 2);

    // Complete successfully
    let success = AtpOutcome::ok(());
    transcript.complete(&success, 1000);

    assert_eq!(transcript.outcome_class, OutcomeClass::Success);
    assert!(transcript.is_complete());
    assert_eq!(transcript.duration_nanos(), Some(1000));
}

#[test]
fn all_operation_type_idempotency_keys_unique() {
    let manifest_hash = b"test";
    let peer_id = "peer";
    let timestamp = 123u64;

    // Generate keys for all operation types
    let offer_key = IdempotencyKey::offer(manifest_hash, peer_id, timestamp);
    let accept_key = IdempotencyKey::accept(&offer_key, peer_id, timestamp);
    let chunk_key = IdempotencyKey::chunk("transfer", 1, 1);
    let repair_key = IdempotencyKey::repair_group("block", 1, peer_id);
    let commit_key = IdempotencyKey::commit("transfer", b"hash", timestamp);
    let mailbox_key = IdempotencyKey::mailbox_store("mailbox", b"msg", 1);
    let grant_key = IdempotencyKey::grant("issuer", "subject", b"cap", timestamp);
    let relay_key = IdempotencyKey::relay_reservation("relay", "client", 1000, 3600);
    let journal_key = IdempotencyKey::resume_journal("transfer", b"checkpoint", 1);
    let proof_key = IdempotencyKey::final_proof("transfer", b"proof", "verifier");

    let all_keys = vec![
        offer_key,
        accept_key,
        chunk_key,
        repair_key,
        commit_key,
        mailbox_key,
        grant_key,
        relay_key,
        journal_key,
        proof_key,
    ];

    // Verify all keys are unique
    for i in 0..all_keys.len() {
        for j in (i + 1)..all_keys.len() {
            assert_ne!(
                all_keys[i], all_keys[j],
                "Keys for different operation types must be unique"
            );
        }
    }

    // Verify all keys have proper prefix
    for key in &all_keys {
        assert!(
            key.as_str().starts_with("atp_"),
            "All ATP keys should have 'atp_' prefix"
        );
    }
}
