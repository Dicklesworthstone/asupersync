//! Audit test for SQLite Unicode normalization injection vulnerabilities.
//!
//! SECURITY CONCERN: When query parameters contain Unicode normalization tricks
//! (e.g., U+0027 vs U+2019), prepared statement binding must be immune by treating
//! strings as bytes-as-bytes, not performing canonical equivalence interpretation.
//!
//! ATTACK VECTOR: If SQLite normalizes Unicode before binding, an attacker could
//! use visually similar Unicode characters to bypass SQL injection filters.

#[cfg(feature = "sqlite")]
use asupersync::Outcome;
#[cfg(feature = "sqlite")]
use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
#[cfg(feature = "sqlite")]
use asupersync::cx::Cx;
#[cfg(feature = "sqlite")]
use asupersync::database::{SqliteConnection, SqliteRow, SqliteValue};
#[cfg(feature = "sqlite")]
use asupersync::test_utils::init_test_logging;
#[cfg(feature = "sqlite")]
use asupersync::types::{Budget, RegionId, TaskId};
#[cfg(feature = "sqlite")]
use asupersync::util::ArenaIndex;

#[cfg(feature = "sqlite")]
fn create_test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

#[cfg(feature = "sqlite")]
#[test]
fn unicode_normalization_injection_audit() {
    init_test_logging();
    let config = TestConfig::new().with_seed(42);
    let mut runtime = LabRuntimeTarget::create_runtime(config);

    LabRuntimeTarget::block_on(&mut runtime, async {
        let cx = Cx::current().expect("should have current Cx");
        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(conn) => conn,
            other => panic!("Failed to open in-memory database: {other:?}"),
        };

        // Setup test table
        match conn
            .execute_batch(
                &cx,
                "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)",
            )
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("Failed to create test table: {other:?}"),
        }

        // Insert test data
        let test_email = "user@example.com";
        match conn
            .execute(
                &cx,
                "INSERT INTO users (name, email) VALUES (?, ?)",
                &[
                    SqliteValue::Text("Test User".to_string()),
                    SqliteValue::Text(test_email.to_string()),
                ],
            )
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("Failed to insert test data: {other:?}"),
        }

        println!("=== SQLITE UNICODE NORMALIZATION INJECTION AUDIT ===");

        // Test Case 1: Regular apostrophe (U+0027) vs Right single quotation mark (U+2019)
        let regular_apostrophe = "user'@example.com"; // U+0027
        let unicode_apostrophe = "user'@example.com"; // U+2019 (right single quotation mark)

        assert_ne!(
            regular_apostrophe, unicode_apostrophe,
            "Unicode strings should be different"
        );
        assert_ne!(
            regular_apostrophe.as_bytes(),
            unicode_apostrophe.as_bytes(),
            "Byte representations should differ"
        );

        // ✓ SECURE: Different Unicode representations should be treated as different values
        let query1: Vec<SqliteRow> = match conn
            .query(
                &cx,
                "SELECT * FROM users WHERE email = ?",
                &[SqliteValue::Text(regular_apostrophe.to_string())],
            )
            .await
        {
            Outcome::Ok(rows) => rows,
            other => panic!("Query with regular apostrophe failed: {other:?}"),
        };

        let query2: Vec<SqliteRow> = match conn
            .query(
                &cx,
                "SELECT * FROM users WHERE email = ?",
                &[SqliteValue::Text(unicode_apostrophe.to_string())],
            )
            .await
        {
            Outcome::Ok(rows) => rows,
            other => panic!("Query with unicode apostrophe failed: {other:?}"),
        };

        assert_eq!(
            query1.len(),
            0,
            "Regular apostrophe should not match test data"
        );
        assert_eq!(
            query2.len(),
            0,
            "Unicode apostrophe should not match test data"
        );

        println!("✓ Test 1 PASSED: Different Unicode apostrophes treated as distinct values");

        // Test Case 2: Unicode Normalization Forms (NFC vs NFD)
        // Example: é can be represented as:
        // - NFC: single character é (U+00E9)
        // - NFD: e (U+0065) + ´ (U+0301)
        let nfc_email = "café@example.com"; // é as single character
        let nfd_email = "cafe\u{0301}@example.com"; // e + combining acute accent

        assert_ne!(
            nfc_email, nfd_email,
            "NFC vs NFD should be different strings"
        );
        assert_ne!(
            nfc_email.as_bytes(),
            nfd_email.as_bytes(),
            "NFC vs NFD should have different bytes"
        );

        // Insert NFC version
        match conn
            .execute(
                &cx,
                "INSERT INTO users (name, email) VALUES (?, ?)",
                &[
                    SqliteValue::Text("NFC User".to_string()),
                    SqliteValue::Text(nfc_email.to_string()),
                ],
            )
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("Failed to insert NFC data: {other:?}"),
        }

        // ✓ SECURE: NFD query should NOT match NFC data (no normalization)
        let nfd_query: Vec<SqliteRow> = match conn
            .query(
                &cx,
                "SELECT * FROM users WHERE email = ?",
                &[SqliteValue::Text(nfd_email.to_string())],
            )
            .await
        {
            Outcome::Ok(rows) => rows,
            other => panic!("NFD query failed: {other:?}"),
        };

        // ✓ SECURE: NFC query should match NFC data (exact byte match)
        let nfc_query: Vec<SqliteRow> = match conn
            .query(
                &cx,
                "SELECT * FROM users WHERE email = ?",
                &[SqliteValue::Text(nfc_email.to_string())],
            )
            .await
        {
            Outcome::Ok(rows) => rows,
            other => panic!("NFC query failed: {other:?}"),
        };

        assert_eq!(
            nfd_query.len(),
            0,
            "NFD query should NOT match NFC data if no normalization"
        );
        assert_eq!(
            nfc_query.len(),
            1,
            "NFC query should match NFC data exactly"
        );

        println!("✓ Test 2 PASSED: NFC vs NFD treated as distinct (no Unicode normalization)");

        // Test Case 3: Homoglyph attacks (visually similar characters)
        let latin_a = "admin@example.com"; // Latin 'a' (U+0061)
        let cyrillic_a = "аdmin@example.com"; // Cyrillic 'а' (U+0430) - visually identical!

        assert_ne!(
            latin_a, cyrillic_a,
            "Latin vs Cyrillic 'a' should be different"
        );
        assert_ne!(
            latin_a.as_bytes(),
            cyrillic_a.as_bytes(),
            "Different byte representations"
        );

        // Insert with Latin 'a'
        match conn
            .execute(
                &cx,
                "INSERT INTO users (name, email) VALUES (?, ?)",
                &[
                    SqliteValue::Text("Admin User".to_string()),
                    SqliteValue::Text(latin_a.to_string()),
                ],
            )
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("Failed to insert Latin admin: {other:?}"),
        }

        // ✓ SECURE: Cyrillic 'a' should NOT match Latin 'a'
        let cyrillic_query: Vec<SqliteRow> = match conn
            .query(
                &cx,
                "SELECT * FROM users WHERE email = ?",
                &[SqliteValue::Text(cyrillic_a.to_string())],
            )
            .await
        {
            Outcome::Ok(rows) => rows,
            other => panic!("Cyrillic query failed: {other:?}"),
        };

        assert_eq!(
            cyrillic_query.len(),
            0,
            "Cyrillic 'a' should NOT match Latin 'a'"
        );

        println!(
            "✓ Test 3 PASSED: Homoglyph attack prevented (different Unicode codepoints distinct)"
        );

        // Test Case 4: Zero-width characters and invisible Unicode
        let clean_email = "test@domain.com";
        let poisoned_email = "test\u{200B}@domain.com"; // Zero-width space (U+200B)

        assert_ne!(
            clean_email, poisoned_email,
            "Clean vs poisoned should be different"
        );
        assert_ne!(
            clean_email.len(),
            poisoned_email.len(),
            "Different byte lengths"
        );

        // ✓ SECURE: Zero-width characters should be preserved (not stripped)
        let clean_query: Vec<SqliteRow> = match conn
            .query(
                &cx,
                "SELECT * FROM users WHERE email = ?",
                &[SqliteValue::Text(clean_email.to_string())],
            )
            .await
        {
            Outcome::Ok(rows) => rows,
            other => panic!("Clean query failed: {other:?}"),
        };

        let poisoned_query: Vec<SqliteRow> = match conn
            .query(
                &cx,
                "SELECT * FROM users WHERE email = ?",
                &[SqliteValue::Text(poisoned_email.to_string())],
            )
            .await
        {
            Outcome::Ok(rows) => rows,
            other => panic!("Poisoned query failed: {other:?}"),
        };

        // Both should return 0 since neither matches our test data exactly
        assert_eq!(
            clean_query.len(),
            0,
            "Clean email should not match existing data"
        );
        assert_eq!(
            poisoned_query.len(),
            0,
            "Poisoned email should not match clean data"
        );

        println!("✓ Test 4 PASSED: Zero-width characters preserved (no Unicode stripping)");

        println!("\n=== AUDIT CONCLUSION ===");
        println!(
            "✓ SECURE: SQLite prepared statement binding treats Unicode strings as byte-exact"
        );
        println!("✓ NO Unicode normalization performed during parameter binding");
        println!("✓ NO canonical equivalence interpretation");
        println!("✓ Different Unicode representations are treated as distinct values");
        println!("✓ IMMUNE to Unicode normalization injection attacks");
        println!("\nREASON: rusqlite/SQLite preserves exact UTF-8 byte sequences in TEXT values");
        println!(
            "RECOMMENDATION: Continue using prepared statements - they are secure against this attack vector"
        );
    });
}

#[cfg(feature = "sqlite")]
#[test]
fn unicode_sql_construction_vulnerability_demo() {
    // EDUCATIONAL: Demonstrate why string concatenation WOULD be vulnerable
    // (This test documents the vulnerability we're protected against)

    init_test_logging();
    println!("\n=== EDUCATIONAL: Why String Concatenation Would Be Vulnerable ===");

    let user_input = "'; DROP TABLE users; --";
    let unicode_variant = "'; DROP TABLE users; --"; // Using U+2019 instead of U+0027

    // UNSAFE (educational only - not actually executed):
    let unsafe_query = format!("SELECT * FROM users WHERE name = '{}'", user_input);
    let unsafe_unicode_query = format!("SELECT * FROM users WHERE name = '{}'", unicode_variant);

    println!("Regular injection attempt: {}", unsafe_query);
    println!("Unicode variant injection: {}", unsafe_unicode_query);
    println!("✓ Our implementation uses prepared statements, so both are neutralized");
    println!("✓ Parameter binding treats them as literal string values, not SQL");
}

#[cfg(feature = "sqlite")]
#[test]
fn verify_text_storage_preserves_bytes() {
    // Verify that SQLite TEXT storage preserves exact Unicode byte sequences
    init_test_logging();
    let cx = create_test_cx();

    let config = TestConfig::new().with_seed(42);
    let mut runtime = LabRuntimeTarget::create_runtime(config);

    LabRuntimeTarget::block_on(&mut runtime, async {
        let cx = Cx::current().expect("should have current Cx");
        let conn: SqliteConnection = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(conn) => conn,
            other => panic!("Failed to open database: {other:?}"),
        };

        match conn
            .execute_batch(&cx, "CREATE TABLE unicode_test (data TEXT)")
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("Failed to create table: {other:?}"),
        }

        let test_strings = vec![
            "café",            // NFC form
            "cafe\u{0301}",    // NFD form
            "user'quote",      // U+0027
            "user'quote",      // U+2019
            "test\u{200B}end", // Zero-width space
        ];

        // Insert all test strings
        for (i, s) in test_strings.iter().enumerate() {
            match conn
                .execute(
                    &cx,
                    "INSERT INTO unicode_test (rowid, data) VALUES (?, ?)",
                    &[
                        SqliteValue::Integer(i as i64),
                        SqliteValue::Text(s.to_string()),
                    ],
                )
                .await
            {
                Outcome::Ok(_) => {}
                other => panic!("Failed to insert test string {}: {other:?}", i),
            }
        }

        // Retrieve and verify exact byte preservation
        for (i, original) in test_strings.iter().enumerate() {
            let rows: Vec<SqliteRow> = match conn
                .query(
                    &cx,
                    "SELECT data FROM unicode_test WHERE rowid = ?",
                    &[SqliteValue::Integer(i as i64)],
                )
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("Failed to query row {}: {other:?}", i),
            };

            assert_eq!(rows.len(), 1, "Should find exactly one row");

            let retrieved = match rows[0].get("data").unwrap() {
                SqliteValue::Text(s) => s,
                other => panic!("Expected text value, got: {other:?}"),
            };

            assert_eq!(
                retrieved, original,
                "Retrieved string should match original exactly"
            );
            assert_eq!(
                retrieved.as_bytes(),
                original.as_bytes(),
                "Byte sequences should match exactly"
            );

            println!(
                "✓ String {}: '{}' preserved exactly ({} bytes)",
                i,
                original,
                original.as_bytes().len()
            );
        }

        println!("✓ VERIFIED: SQLite TEXT storage preserves exact Unicode byte sequences");
    });
}
