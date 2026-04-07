//! Proc macros for asupersync structured concurrency runtime.
//!
//! This crate provides procedural macros that simplify working with the asupersync
//! async runtime's structured concurrency primitives. The macros handle the boilerplate
//! for creating scopes, spawning tasks, joining results, and racing computations.
//!
//! # Available Macros
//!
//! - [`scope!`] - Create a structured concurrency scope
//! - [`spawn!`] - Spawn a task within the current scope
//! - [`join!`] - Join multiple futures, waiting for all to complete
//! - [`join_all!`] - Join multiple futures into an array
//! - [`race!`] - Race multiple futures, returning the first to complete
//! - [`session_protocol!`] - Generate typestate session protocols
//! - [`conformance`] - Annotate conformance tests
//!
//! # Contract With `asupersync`
//!
//! The root `asupersync` crate re-exports only the supported runtime DSL:
//! `scope!`, `spawn!`, `join!`, `join_all!`, and `race!`, and only when the
//! `proc-macros` feature is enabled.
//!
//! This crate also defines `session_protocol!` and `#[conformance]`, but those
//! remain explicit-path macros on `asupersync_macros`; they are not part of the
//! default root macro contract.
//!
//! # Example
//!
//! ```ignore
//! use asupersync_macros::{scope, spawn, join, race};
//!
//! async fn example(cx: &Cx, state: &mut RuntimeState) {
//!     scope!(cx, state: state, {
//!         let handle1 = spawn!(async { compute_a().await });
//!         let handle2 = spawn!(async { compute_b().await });
//!
//!         // Wait for both
//!         let (result_a, result_b) = join!(handle1, handle2);
//!     });
//! }
//! ```

mod join;
mod race;
mod scope;
mod session;
mod spawn;
mod util;

use proc_macro::TokenStream;

/// Creates a structured concurrency scope.
///
/// The `scope!` macro creates a [`Scope`](asupersync::Scope) binding for the
/// current `Cx` region and makes it available as `scope` inside the body.
///
/// Today this is an ergonomic binding helper, not a fresh child-region
/// boundary. For actual child-region ownership and quiescence, call
/// [`Scope::region`](asupersync::Scope::region) explicitly.
///
/// # Syntax
///
/// ```ignore
/// scope!(cx, {
///     // body with spawned tasks
/// })
/// scope!(cx, state: &mut state, {
///     let _child = spawn!(async { work().await });
/// })
/// ```
///
/// # Arguments
///
/// - `cx` - The capability context (`&Cx`)
/// - `body` - A block containing the scope's work
/// - `state` - Optional runtime state binding used by nested `spawn!` calls
///
/// # Returns
///
/// The result of the scope body.
///
/// # Example
///
/// ```ignore
/// scope!(cx, state: &mut state, {
///     spawn!(async { work_a().await });
///     spawn!(async { work_b().await });
///     // Both tasks are awaited before scope exits
/// })
/// ```
#[proc_macro]
pub fn scope(input: TokenStream) -> TokenStream {
    scope::scope_impl(input)
}

/// Spawns a task within the current scope.
///
/// The `spawn!` macro expands to [`Scope::spawn_registered`], so it requires
/// ambient `__state` and `__cx` bindings in addition to the target `Scope`.
///
/// The easiest supported path is to use it inside `scope!(..., state: ..., { ... })`.
///
/// # Syntax
///
/// ```ignore
/// spawn!(async { /* work */ })
/// spawn!(async move { /* work with captured values */ })
/// ```
///
/// # Returns
///
/// A `TaskHandle` that can be awaited to get the task's result.
///
/// # Example
///
/// ```ignore
/// let handle = spawn!(async {
///     expensive_computation().await
/// });
/// let result = handle.await;
/// ```
#[proc_macro]
pub fn spawn(input: TokenStream) -> TokenStream {
    spawn::spawn_impl(input)
}

/// Joins multiple futures, waiting for all to complete.
///
/// The `join!` macro is a supported proc-macro convenience surface, but the
/// current implementation still awaits branches sequentially. It preserves
/// left-to-right evaluation and tuple ordering today; parallel polling remains
/// future work.
///
/// # Syntax
///
/// ```ignore
/// join!(future1, future2, ...)
/// ```
///
/// # Returns
///
/// A tuple of all the futures' results in the order they were specified.
///
/// # Outcome Semantics
///
/// The combined outcome follows the severity lattice:
/// - If all succeed: `Outcome::Ok((r1, r2, ...))`
/// - If any fails: the most severe outcome is propagated
///
/// # Example
///
/// ```ignore
/// let (a, b, c) = join!(
///     fetch_user().await,
///     fetch_profile().await,
///     fetch_settings().await
/// );
/// ```
#[proc_macro]
pub fn join(input: TokenStream) -> TokenStream {
    join::join_impl(input)
}

/// Joins multiple futures into an array, waiting for all to complete.
///
/// The `join_all!` macro is like `join!` but returns an array instead of a
/// tuple. Like `join!`, the current implementation still awaits branches
/// sequentially.
///
/// # Syntax
///
/// ```ignore
/// join_all!(future1, future2, ...)
/// ```
///
/// # Returns
///
/// An array of all the futures' results in the order they were specified.
/// Since all results must be the same type, this enables easier iteration.
///
/// # Example
///
/// ```ignore
/// let results: [i32; 3] = join_all!(
///     fetch_value(1).await,
///     fetch_value(2).await,
///     fetch_value(3).await
/// );
/// for result in results {
///     println!("{}", result);
/// }
/// ```
#[proc_macro]
pub fn join_all(input: TokenStream) -> TokenStream {
    join::join_all_impl(input)
}

/// Races multiple futures, returning the first to complete.
///
/// The `race!` macro expands to the inline [`Cx::race*`](asupersync::Cx::race)
/// family. The losing futures are cancelled by drop, but they are not drained.
///
/// If you need the stronger "losers are drained" invariant, race spawned tasks
/// with [`Scope::race`](asupersync::Scope::race) instead.
///
/// # Syntax
///
/// ```ignore
/// race!(cx, { future1, future2, ... })
/// race!(cx, { "name" => future1, "other" => future2, ... })
/// race!(cx, timeout: Duration::from_secs(5), { future1, future2, ... })
/// ```
///
/// # Returns
///
/// The result of the winning future.
///
/// # Loser Cleanup
///
/// All non-winning futures are dropped, which requests cancellation for inline
/// futures but does not await their cleanup path.
///
/// # Example
///
/// ```ignore
/// let result = race!(cx, {
///     primary_service.fetch().await,
///     backup_service.fetch().await,
/// });
/// // One completed; the loser was cancelled by drop but not drained.
/// ```
#[proc_macro]
pub fn race(input: TokenStream) -> TokenStream {
    race::race_impl(input)
}

/// Marks a test with the specification section and requirement it validates.
///
/// # Syntax
///
/// ```ignore
/// #[conformance(spec = "3.2.1", requirement = "Region close waits for all children")]
/// #[test]
/// fn test_region_close_waits() { /* ... */ }
/// ```
///
/// The macro is validation-only: it checks that `spec` and `requirement` are
/// present and string literals, then leaves the item unchanged.
#[proc_macro_attribute]
pub fn conformance(attr: TokenStream, item: TokenStream) -> TokenStream {
    match parse_conformance_args(&attr) {
        Ok(_) => item,
        Err(message) => util::compile_error(&message).into(),
    }
}

/// Generates typestate-encoded session types from a protocol DSL.
///
/// The macro takes a protocol specification and generates a module containing
/// message structs, paired session type aliases (initiator + responder), and
/// constructor functions. The responder type is the dual of the initiator:
/// `Send`↔`Recv`, `Select`↔`Offer`.
///
/// # Syntax
///
/// ```ignore
/// session_protocol! {
///     module_name<T> for ObligationVariant {
///         msg MessageName;
///         msg MessageWithFields { field: Type };
///
///         send MessageName => select {
///             send T => end,
///             send OtherMsg => end,
///         }
///     }
/// }
/// ```
///
/// # Body Actions
///
/// - `send Type => body` — send a value, then continue
/// - `recv Type => body` — receive a value, then continue
/// - `select { a, b }` — local choice (becomes `Offer` for responder)
/// - `offer { a, b }` — remote choice (becomes `Select` for responder)
/// - `loop { body }` — recursion point (generates `renew_loop` constructor)
/// - `continue` — jump back to enclosing `loop`
/// - `end` — protocol termination
///
/// # Generated Items
///
/// - `pub mod <name>` containing:
///   - Message structs with `Debug, Clone` (+ `Copy` for unit structs)
///   - `InitiatorSession` type alias
///   - `ResponderSession` type alias
///   - `new_session(channel_id) -> (Chan<Initiator, ...>, Chan<Responder, ...>)`
///   - (if `loop` used) `InitiatorLoop`, `ResponderLoop` type aliases
///   - (if `loop` used) `renew_loop(channel_id)` constructor
///
/// # Example
///
/// ```ignore
/// session_protocol! {
///     lease for Lease {
///         msg AcquireMsg;
///         msg RenewMsg;
///         msg ReleaseMsg;
///
///         send AcquireMsg => loop {
///             select {
///                 send RenewMsg => continue,
///                 send ReleaseMsg => end,
///             }
///         }
///     }
/// }
/// ```
#[proc_macro]
pub fn session_protocol(input: TokenStream) -> TokenStream {
    session::session_protocol_impl(input)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConformanceArgs {
    spec: String,
    requirement: String,
}

fn parse_conformance_args(attr: &TokenStream) -> Result<ConformanceArgs, String> {
    parse_conformance_args_str(&attr.to_string())
}

fn parse_conformance_args_str(input: &str) -> Result<ConformanceArgs, String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("conformance attribute requires arguments".to_string());
    }

    let mut spec = None;
    let mut requirement = None;

    for part in split_args(raw) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = split_key_value(part)?;
        let value = parse_string_literal(value)?;
        match key {
            "spec" => spec = Some(value),
            "requirement" => requirement = Some(value),
            other => {
                return Err(format!(
                    "conformance attribute has unknown key '{other}', expected 'spec' or 'requirement'"
                ));
            }
        }
    }

    let spec = spec.ok_or_else(|| "conformance attribute missing 'spec'".to_string())?;
    let requirement =
        requirement.ok_or_else(|| "conformance attribute missing 'requirement'".to_string())?;

    Ok(ConformanceArgs { spec, requirement })
}

fn split_args(input: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escape = false;

    for ch in input.chars() {
        if in_string {
            current.push(ch);
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                current.push(ch);
            }
            ',' => {
                parts.push(current);
                current = String::new();
            }
            _ => current.push(ch),
        }
    }

    if !current.trim().is_empty() {
        parts.push(current);
    }

    parts
}

fn split_key_value(input: &str) -> Result<(&str, &str), String> {
    let mut iter = input.splitn(2, '=');
    let key = iter
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "conformance attribute expects key = \"value\" pairs".to_string())?;
    let value = iter
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("conformance attribute missing value for '{key}'"))?;
    Ok((key, value))
}

fn parse_string_literal(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if !trimmed.starts_with('"') || !trimmed.ends_with('"') {
        return Err(format!(
            "conformance attribute values must be string literals, got: {trimmed}"
        ));
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let next = chars.next().ok_or_else(|| {
                "conformance attribute contains dangling escape sequence".to_string()
            })?;
            match next {
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                other => {
                    return Err(format!(
                        "conformance attribute contains unsupported escape: \\{other}"
                    ));
                }
            }
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::parse_conformance_args_str;

    #[test]
    fn parse_conformance_args_ok() {
        let args =
            parse_conformance_args_str(r#"spec = "3.2.1", requirement = "Region close waits""#)
                .unwrap();
        assert_eq!(args.spec, "3.2.1");
        assert_eq!(args.requirement, "Region close waits");
    }

    #[test]
    fn parse_conformance_args_missing_spec() {
        let err = parse_conformance_args_str(r#"requirement = "Region close waits""#).unwrap_err();
        assert!(err.contains("missing 'spec'"));
    }

    #[test]
    fn parse_conformance_args_missing_requirement() {
        let err = parse_conformance_args_str(r#"spec = "3.2.1""#).unwrap_err();
        assert!(err.contains("missing 'requirement'"));
    }
}
