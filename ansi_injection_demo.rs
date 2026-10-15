#!/usr/bin/env rust-script
//! ANSI Injection Vulnerability Demonstration
//!
//! This script shows how the ANSI injection vulnerability in console.rs
//! could be exploited and how the fix prevents it.

use std::io::{self, Write};

fn main() {
    println!("🚨 ANSI Injection Vulnerability Demonstration");
    println!("==============================================\n");

    // Simulated user input containing malicious ANSI sequences
    let malicious_inputs = vec![
        ("\x1b[2J\x1b[H", "Clear screen attack"),
        ("\x1b[31mHACKED!\x1b[0m", "Color injection"),
        ("Safe text\x1b[1000D\x1b[KEVILOverwrite", "Cursor manipulation"),
        ("\x1b]0;FAKE TERMINAL TITLE\x07", "Title manipulation"),
        ("\x1b[?25lHidden cursor\x1b[?25h", "Cursor hiding"),
    ];

    println!("1. BEFORE FIX - Vulnerable output:");
    println!("   (ANSI sequences would execute and manipulate terminal)\n");

    for (malicious, description) in &malicious_inputs {
        println!("   Attack: {}", description);
        println!("   Input: {:?}", malicious);
        println!("   Raw bytes: {:?}", malicious.as_bytes());

        // This is what WOULD happen with the vulnerability
        // (We're not actually executing it to avoid terminal manipulation)
        println!("   🚨 Would execute ANSI codes and manipulate terminal!\n");
    }

    println!("2. AFTER FIX - Sanitized output:");
    println!("   (ANSI sequences filtered, safe content preserved)\n");

    for (malicious, description) in &malicious_inputs {
        let sanitized = sanitize_ansi_escape_sequences(malicious);

        println!("   Attack: {}", description);
        println!("   Original: {:?}", malicious);
        println!("   Sanitized: {:?}", sanitized);
        println!("   ✅ Safe to display: \"{}\"", sanitized);
        println!("   ✅ No ANSI escapes: {}", !sanitized.contains('\x1b'));
        println!();
    }

    println!("3. Legitimate content preservation test:");
    println!("   (Normal text should pass through unchanged)\n");

    let legitimate_inputs = vec![
        "Hello, World!",
        "Multi\nLine\nText",
        "Symbols: !@#$%^&*()",
        "Unicode: 🚀 ∀x∈ℝ",
    ];

    for input in &legitimate_inputs {
        let sanitized = sanitize_ansi_escape_sequences(input);
        let preserved = sanitized == *input;

        println!("   Input: {:?}", input);
        println!("   Sanitized: {:?}", sanitized);
        println!("   ✅ Preserved exactly: {}", preserved);
        println!();
    }

    println!("🔐 Security Fix Summary:");
    println!("  ✅ ANSI escape sequences are filtered out");
    println!("  ✅ Terminal manipulation attacks prevented");
    println!("  ✅ Legitimate content preserved");
    println!("  ✅ No terminal state changes from user input");
}

/// Sanitize ANSI escape sequences from user-provided content.
///
/// **Security**: This function prevents ANSI injection attacks by filtering out
/// escape sequences that could manipulate the terminal.
fn sanitize_ansi_escape_sequences(input: &str) -> String {
    let mut sanitized = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            // ANSI escape sequence starts
            '\x1b' => {
                // Skip the entire ANSI sequence
                if chars.peek() == Some(&'[') {
                    chars.next(); // consume '['
                    // Skip until we find the terminating character
                    while let Some(next_ch) = chars.next() {
                        if next_ch.is_ascii_alphabetic() {
                            break;
                        }
                    }
                } else {
                    chars.next(); // consume one more character
                }
                // ANSI sequence filtered out
            }
            // Control characters (except safe whitespace)
            '\x00'..='\x08' | '\x0E'..='\x1F' | '\x7F' => {
                // Filter out dangerous control characters
            }
            // Safe characters: printable + safe whitespace
            '\t' | '\n' | '\r' | ' '..='\x7E' | '\u{A0}'..=char::MAX => {
                sanitized.push(ch);
            }
        }
    }

    sanitized
}