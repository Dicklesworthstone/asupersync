#![no_main]

//! Cargo-fuzz target for `asupersync::grpc::HealthService` service-name
//! validation under arbitrary input bytes.
//!
//! Drives the public health-service surface (`try_set_status`,
//! `get_status`, `is_serving`, `check`) with `Arbitrary`-derived
//! service-name strings — including the path-traversal corners
//! `".."`, `"../foo"`, `"foo/../bar"`, the C-string-injection
//! corners (NUL byte, CRLF, embedded `\0`), the protocol-special
//! characters (`*`, `>`, `:`, `/`, `\`), control characters, and
//! Unicode normalization edges (CJK, combining marks, RTL
//! overrides).
//!
//! Properties asserted per fuzz iteration:
//!
//!   1. **No panic.** Every call into HealthService — set, get, check —
//!      must complete without unwinding for any byte sequence the
//!      caller can construct. A panic here is exploitable as a
//!      remote DoS by anything that lets a peer choose the service
//!      name (the wire-level gRPC HealthCheckRequest carries it
//!      verbatim).
//!
//!   2. **Length-cap contract.** `try_set_status` MUST return
//!      `Err(HealthError::ServiceNameTooLong)` iff the name's
//!      `.len()` (byte count) exceeds `MAX_SERVICE_NAME_LEN`. Names
//!      below the cap MUST succeed (Ok), regardless of the bytes
//!      they contain — the current contract is byte-length only,
//!      no character-set filter. If the contract is later tightened
//!      to also reject path-traversal / control-char names, this
//!      assertion will start failing on those inputs and force the
//!      bead-track to pick up the new rule.
//!
//!   3. **Round-trip on success.** When `try_set_status(n, s)` returns
//!      Ok, `get_status(n)` MUST return Some(s). No silent rewriting
//!      of the name, no truncation, no normalization.
//!
//!   4. **`check` never panics, even on the un-registered branch.**
//!      Per the existing security fix (br-asupersync-doa4lv), missing
//!      services return `PermissionDenied`; that path must be reached
//!      cleanly for any bytes.
//!
//! Why this fuzzer in addition to the existing health unit tests:
//! the in-tree tests cover well-formed `package.Service` names; this
//! target adds the systematic adversarial-byte coverage. The current
//! contract is len-only — the fuzzer's value is partly to lock that
//! contract today and partly to surface any name shape that crashes
//! the lookup or version-tracking machinery downstream.
//!
//! ```bash
//! cargo +nightly fuzz run grpc_health_service_name -- -max_total_time=120
//! ```

use arbitrary::Arbitrary;
use asupersync::grpc::health::{HealthError, MAX_SERVICE_NAME_LEN};
use asupersync::grpc::{HealthCheckRequest, HealthService, ServingStatus};
use libfuzzer_sys::fuzz_target;

/// Bound on the per-iteration name length. Must allow generating
/// names BOTH below and above MAX_SERVICE_NAME_LEN so the cap path
/// is exercised. 4 KiB is comfortably above the 256-byte cap and
/// keeps each iteration sub-second.
const MAX_NAME_BYTES: usize = 4 * 1024;

#[derive(Arbitrary, Debug)]
enum NameShape {
    /// Pure arbitrary bytes — String::from_utf8_lossy on the body.
    /// libFuzzer is best at hill-climbing this lane.
    RawBytes(Vec<u8>),

    /// Path-traversal corners: deliberately stitches `..`, `/`,
    /// `\` into the name so seeds always have those tokens
    /// available.
    PathLike {
        prefix: String,
        traversal: TraversalKind,
        suffix: String,
    },

    /// Protocol-injection corners: NUL, CRLF, control chars,
    /// gRPC subject-wildcards. Catches a bug where the name flows
    /// into a `format!()`-built subject that the lower layer
    /// then mis-parses.
    ProtocolInjection {
        head: String,
        injection: InjectionKind,
        tail: String,
    },

    /// Length-boundary corners centered exactly on
    /// MAX_SERVICE_NAME_LEN (255 / 256 / 257). libFuzzer tends to
    /// drift away from these without a deliberate selector.
    AtLengthBoundary {
        offset_from_cap: i8, // -8..=8 so 248..=264
        fill: u8,
    },
}

#[derive(Arbitrary, Debug)]
enum TraversalKind {
    DotDot,          // `..`
    DotDotSlash,     // `../`
    SlashDotDot,     // `/..`
    DotDotBackslash, // `..\\`
    EncodedDotDot,   // `%2E%2E`
}

#[derive(Arbitrary, Debug)]
enum InjectionKind {
    Nul,       // \0
    Crlf,      // \r\n
    Cr,        // \r
    Lf,        // \n
    Tab,       // \t
    Star,      // *
    Greater,   // >
    Colon,     // :
    Backslash, // \\
    NestedNul, // \0middle\0
}

fn build_name(shape: &NameShape) -> String {
    match shape {
        NameShape::RawBytes(bytes) => {
            // bound the fuzzer's allocation: cargo-fuzz can otherwise
            // hand us a multi-MiB Vec<u8> per iteration and the
            // String::from_utf8_lossy + String::push_str chain copies
            // it twice.
            let trimmed: &[u8] = if bytes.len() > MAX_NAME_BYTES {
                &bytes[..MAX_NAME_BYTES]
            } else {
                &bytes[..]
            };
            String::from_utf8_lossy(trimmed).into_owned()
        }
        NameShape::PathLike {
            prefix,
            traversal,
            suffix,
        } => {
            let token = match traversal {
                TraversalKind::DotDot => "..",
                TraversalKind::DotDotSlash => "../",
                TraversalKind::SlashDotDot => "/..",
                TraversalKind::DotDotBackslash => "..\\",
                TraversalKind::EncodedDotDot => "%2E%2E",
            };
            let mut out = String::new();
            out.push_str(&truncate_to(prefix, MAX_NAME_BYTES / 4));
            out.push_str(token);
            out.push_str(&truncate_to(suffix, MAX_NAME_BYTES / 4));
            out
        }
        NameShape::ProtocolInjection {
            head,
            injection,
            tail,
        } => {
            let mut out = String::new();
            out.push_str(&truncate_to(head, MAX_NAME_BYTES / 4));
            match injection {
                InjectionKind::Nul => out.push('\0'),
                InjectionKind::Crlf => out.push_str("\r\n"),
                InjectionKind::Cr => out.push('\r'),
                InjectionKind::Lf => out.push('\n'),
                InjectionKind::Tab => out.push('\t'),
                InjectionKind::Star => out.push('*'),
                InjectionKind::Greater => out.push('>'),
                InjectionKind::Colon => out.push(':'),
                InjectionKind::Backslash => out.push('\\'),
                InjectionKind::NestedNul => out.push_str("\0middle\0"),
            }
            out.push_str(&truncate_to(tail, MAX_NAME_BYTES / 4));
            out
        }
        NameShape::AtLengthBoundary {
            offset_from_cap,
            fill,
        } => {
            // i8 in [-128, 127]; clamp tighter so the resulting len
            // stays within MAX_NAME_BYTES.
            let target = MAX_SERVICE_NAME_LEN as isize + (*offset_from_cap as isize);
            let len = target.clamp(0, MAX_NAME_BYTES as isize) as usize;
            let byte = if fill.is_ascii() && *fill != 0 {
                *fill
            } else {
                b'a'
            };
            // Construct a String of exactly `len` ASCII bytes — easiest
            // way to land on a precise byte length boundary.
            String::from_utf8(vec![byte; len]).expect("ascii-only fill is valid utf8")
        }
    }
}

fn truncate_to(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    // Truncate on a char boundary to keep the result valid UTF-8.
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fuzz_target!(|shape: NameShape| {
    let name = build_name(&shape);
    if name.len() > MAX_NAME_BYTES {
        // After build, names should already be within bound — but defend
        // against any future codepath that bypasses truncate_to.
        return;
    }

    let svc = HealthService::new();

    // Property 1: try_set_status never panics.
    let result = svc.try_set_status(name.clone(), ServingStatus::Serving);

    // Property 2: length-cap contract. The error case must be
    // exclusively name.len() > MAX_SERVICE_NAME_LEN.
    match (&result, name.len() > MAX_SERVICE_NAME_LEN) {
        (Err(HealthError::ServiceNameTooLong { len, max }), true) => {
            assert_eq!(*len, name.len(), "reported len must match input");
            assert_eq!(
                *max, MAX_SERVICE_NAME_LEN,
                "reported cap must match constant"
            );
        }
        (Ok(()), false) => {} // ✓
        (Err(_), false) => panic!(
            "try_set_status rejected an under-cap name (len={}): name_dbg={:?}",
            name.len(),
            name,
        ),
        (Ok(()), true) => panic!(
            "try_set_status accepted an over-cap name (len={}, cap={MAX_SERVICE_NAME_LEN})",
            name.len(),
        ),
    }

    // Property 3: round-trip on success. get_status must return what
    // try_set_status accepted.
    if result.is_ok() {
        let got = svc.get_status(&name);
        assert_eq!(
            got,
            Some(ServingStatus::Serving),
            "round-trip failed for name (len={}): set Serving, got {got:?}",
            name.len(),
        );

        // is_serving must agree with the get_status result.
        assert!(
            svc.is_serving(&name),
            "is_serving disagrees with get_status for accepted name",
        );
    }

    // Property 4: check() never panics for any name shape. The
    // missing-service path returns PermissionDenied per
    // br-asupersync-doa4lv; the registered path returns the status.
    let missing_service_name = format!("never-registered-{name}");
    let missing_request = HealthCheckRequest::new(missing_service_name);
    let _ = svc.check(&missing_request); // must not panic

    let registered_request = HealthCheckRequest::new(name.clone());
    let registered_check = svc.check(&registered_request);
    if result.is_ok() {
        // Registered service must be reachable through check().
        assert!(
            registered_check.is_ok(),
            "registered service unreachable via check(): name_len={}, err={registered_check:?}",
            name.len(),
        );
    }
});
