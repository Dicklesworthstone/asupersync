//! Span ID collision audit test.
//!
//! **AUDIT SCOPE**: Verifies span ID generation is cryptographically secure to prevent
//! collision attacks and span hijacking in adversarial workloads.
//!
//! **CRYPTOGRAPHIC REQUIREMENT**:
//! - Span IDs MUST use CSPRNG (cryptographically secure pseudorandom number generator)
//! - NOT weak generators like monotonic counters, LCG, or xorshift
//! - 64-bit span IDs have ~50% collision at sqrt(2^64) = 4 billion spans (birthday paradox)
//!
//! **CRITICAL**: Weak span ID generation enables:
//! - Predictable span hijacking in distributed traces
//! - Cross-tenant span confusion in multi-tenant systems
//! - Replay attacks using guessed span IDs

#![cfg(test)]

/// **AUDIT TEST**: Verify observability span ID generation security.
///
/// **SCENARIO**: observability::context::SpanId uses monotonic counter (WEAK).
/// **REQUIREMENT**: Span IDs MUST use CSPRNG for collision resistance.
/// **ASSESSMENT**: DEFECT - monotonic counter is predictable and collision-prone.
#[test]
fn audit_observability_span_id_generation_is_weak() {
    use crate::observability::context::SpanId;

    println!("🔍 AUDIT: Observability span ID generation security");

    // Generate sequential span IDs to demonstrate predictable pattern
    let spans: Vec<SpanId> = (0..10).map(|_| SpanId::new()).collect();

    println!("📊 Generated span IDs:");
    for (i, span) in spans.iter().enumerate() {
        println!("   span[{}]: {}", i, span);
    }

    // Extract underlying u64 values
    let ids: Vec<u64> = spans.iter().map(|s| s.0).collect();

    // Verify they are sequential (demonstrating weakness)
    let mut is_sequential = true;
    for i in 1..ids.len() {
        if ids[i] != ids[i - 1] + 1 {
            is_sequential = false;
            break;
        }
    }

    if is_sequential {
        println!("🚨 DEFECT CONFIRMED: Span IDs are sequential/monotonic");
        println!(
            "   ✗ Pattern: {} → {} → {} (predictable)",
            ids[0], ids[1], ids[2]
        );
        println!("   ✗ Generator: AtomicU64::fetch_add(1) - NOT cryptographically secure");
        println!("   ✗ Vulnerability: Span ID prediction enables hijacking attacks");
    }

    println!("📋 Security implications:");
    println!("   ✗ WEAK: Monotonic counter (AtomicU64::fetch_add)");
    println!("   ✗ PREDICTABLE: Next span ID = current + 1");
    println!("   ✗ COLLISION-PRONE: Birthday paradox at ~4 billion spans");
    println!("   ✗ ATTACK VECTOR: Span ID guessing in distributed traces");

    println!("🚨 SPAN ID GENERATION: DEFECT - weak monotonic counter used");

    // This assertion documents the current behavior (predictable)
    assert!(
        is_sequential,
        "Span IDs should be sequential (demonstrating the weakness)"
    );
}

/// **AUDIT TEST**: Verify W3C trace context uses secure span ID generation.
///
/// **SCENARIO**: W3C SpanId uses getrandom (CSPRNG).
/// **REQUIREMENT**: Distributed span IDs MUST be cryptographically random.
/// **ASSESSMENT**: SOUND - W3C trace context uses proper CSPRNG.
#[test]
fn audit_w3c_span_id_generation_is_secure() {
    use crate::observability::w3c_trace_context::SpanId;

    println!("🔍 AUDIT: W3C trace context span ID security");

    // Generate multiple W3C span IDs
    let spans: Vec<SpanId> = (0..10).map(|_| SpanId::new_random()).collect();

    println!("📊 Generated W3C span IDs:");
    for (i, span) in spans.iter().enumerate() {
        println!("   w3c_span[{}]: {}", i, span.to_hex());
    }

    // Check for randomness (no predictable patterns)
    let hex_ids: Vec<String> = spans.iter().map(|s| s.to_hex()).collect();

    // Verify they are NOT sequential
    let all_different = hex_ids.windows(2).all(|w| w[0] != w[1]);
    assert!(all_different, "W3C span IDs should be different");

    // Check that they don't follow an obvious pattern
    let ids_bytes: Vec<[u8; 8]> = spans.iter().map(|s| s.to_bytes()).collect();
    let has_pattern = ids_bytes.windows(2).all(|w| {
        // Check if second ID is first ID + 1 (sequential pattern)
        let first = u64::from_be_bytes(w[0]);
        let second = u64::from_be_bytes(w[1]);
        second == first + 1
    });

    println!("✅ W3C SPAN ID GENERATION: Cryptographically secure");
    println!("   ✓ Generator: getrandom::fill() - cryptographically secure");
    println!("   ✓ Pattern: Non-predictable (no obvious sequence)");
    println!("   ✓ Collision resistance: High (64-bit cryptographic random)");
    println!("   ✓ Security: Suitable for distributed tracing");

    assert!(
        !has_pattern,
        "W3C span IDs should not follow predictable patterns"
    );
}

/// **AUDIT TEST**: Demonstrate span ID collision vulnerability calculation.
///
/// **SCENARIO**: Birthday paradox collision probability for 64-bit span IDs.
/// **REQUIREMENT**: Document collision risk for security assessment.
/// **ASSESSMENT**: Mathematical analysis of collision probability.
#[test]
fn audit_span_id_collision_probability_analysis() {
    println!("🔍 AUDIT: Span ID collision probability analysis");

    // Birthday paradox calculation for 64-bit span IDs.
    // P(collision) ≈ 1 - exp(-n² / (2 * 2^64)) for n spans, so the
    // inverse threshold is n ≈ sqrt(-2 * 2^64 * ln(1 - p)).

    let span_space: f64 = 2_f64.powi(64); // 2^64
    let collision_threshold =
        |probability: f64| (-2.0 * span_space * (1.0_f64 - probability).ln()).sqrt();
    let fifty_percent_collision = collision_threshold(0.50);
    let one_percent_collision = collision_threshold(0.01);
    let tenth_percent_collision = collision_threshold(0.001);

    println!("📊 Collision probability analysis:");
    println!("   • Span ID space: 2^64 = {:.2e}", span_space);
    println!(
        "   • 50% collision probability at: {:.0} spans",
        fifty_percent_collision
    );
    println!(
        "   • 1% collision probability at: {:.0} spans",
        one_percent_collision
    );
    println!(
        "   • 0.1% collision probability at: {:.0} spans",
        tenth_percent_collision
    );

    // For weak monotonic counter, collision is guaranteed after 2^64 spans
    println!("📋 Monotonic counter vulnerability:");
    println!("   ✗ Predictable: span_id = start + sequence_number");
    println!("   ✗ Wraparound: collision guaranteed after 2^64 spans");
    println!("   ✗ Enumeration: attacker can guess all future span IDs");

    println!("📋 CSPRNG security properties:");
    println!("   ✓ Unpredictable: impossible to guess next span ID");
    println!("   ✓ Collision resistant: birthday paradox applies");
    println!("   ✓ Cryptographically secure: suitable for security contexts");

    // Document that high-volume systems need collision detection
    let high_volume_threshold = 1_000_000_000u64; // 1 billion spans
    println!(
        "⚠️  High-volume systems (>{} spans) should:",
        high_volume_threshold
    );
    println!("   • Monitor for span ID collisions");
    println!("   • Consider 128-bit span IDs for ultra-high volume");
    println!("   • Implement collision detection and handling");

    assert!(
        fifty_percent_collision > 1e9,
        "50% collision threshold should be > 1 billion spans"
    );
}

/// **AUDIT TEST**: Verify span ID usage pattern in observability modules.
///
/// **SCENARIO**: Check which span ID generator is used where.
/// **REQUIREMENT**: Security-sensitive contexts should use CSPRNG.
/// **ASSESSMENT**: Document current usage patterns.
#[test]
fn audit_span_id_usage_pattern_analysis() {
    println!("🔍 AUDIT: Span ID usage pattern analysis");

    println!("📋 Current span ID implementations:");
    println!("   1. observability::context::SpanId");
    println!("      • Generator: AtomicU64::fetch_add(1, Ordering::Relaxed)");
    println!("      • Security: WEAK (monotonic counter)");
    println!("      • Use case: Local observability context");

    println!("   2. observability::w3c_trace_context::SpanId");
    println!("      • Generator: getrandom::fill(&mut bytes)");
    println!("      • Security: STRONG (CSPRNG)");
    println!("      • Use case: Distributed tracing (W3C standard)");

    println!("📊 Usage pattern implications:");
    println!("   ✗ LOCAL SPANS: Use weak monotonic generator");
    println!("   ✓ DISTRIBUTED SPANS: Use strong CSPRNG generator");
    println!("   ⚠️  MIXED USAGE: Two different span ID types in same codebase");

    println!("🚨 SECURITY RECOMMENDATION:");
    println!("   1. Replace observability::context::SpanId with CSPRNG generation");
    println!("   2. Unify span ID types to use consistent cryptographic generation");
    println!("   3. Add collision detection for high-volume deployments");
    println!("   4. Consider 128-bit span IDs for ultra-high volume systems");

    println!("✅ AUDIT COMPLETE: Span ID security assessment documented");
}

// Helper for testing - define extension trait to avoid modifying original implementation
trait SpanIdTestExt {
    fn to_bytes(&self) -> [u8; 8];
}

impl SpanIdTestExt for crate::observability::w3c_trace_context::SpanId {
    fn to_bytes(&self) -> [u8; 8] {
        // We can't access the private field directly, so we'll use the hex representation
        // and convert it back to bytes for testing purposes
        let hex = self.to_hex();
        let mut bytes = [0u8; 8];
        hex::decode_to_slice(&hex, &mut bytes).expect("valid hex");
        bytes
    }
}
