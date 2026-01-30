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
//! - [`race!`] - Race multiple futures, returning the first to complete
//!
//! # Example
//!
//! ```ignore
//! use asupersync_macros::{scope, spawn, join, race};
//!
//! async fn example(cx: &mut Cx) {
//!     scope!(cx, {
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
mod spawn;
mod util;

use proc_macro::TokenStream;

/// Creates a structured concurrency scope.
///
/// The `scope!` macro creates a region that owns spawned tasks and guarantees
/// quiescence on exit. All tasks spawned within the scope are cancelled and
/// drained before the scope completes.
///
/// # Syntax
///
/// ```ignore
/// scope!(cx, {
///     // body with spawned tasks
/// })
/// ```
///
/// # Arguments
///
/// - `cx` - The capability context (`&mut Cx`)
/// - `body` - A block containing the scope's work
///
/// # Returns
///
/// The result of the scope body.
///
/// # Example
///
/// ```ignore
/// scope!(cx, {
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
/// The `spawn!` macro spawns an async task that is owned by the enclosing region.
/// The task cannot orphan - it will be cancelled and drained when the region closes.
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
/// The `join!` macro runs multiple futures concurrently and waits for all of them
/// to complete. If any future is cancelled or panics, the others continue running
/// and the final outcome reflects the most severe result.
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
/// The `join_all!` macro is like `join!` but returns an array instead of a tuple.
/// All futures must return the same type.
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
/// The `race!` macro runs multiple futures concurrently and returns when the first
/// one completes. The losing futures are automatically cancelled and drained,
/// ensuring no orphaned work.
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
/// All non-winning futures are cancelled via the cancellation protocol:
/// 1. Cancel request sent
/// 2. Futures drain to cleanup points
/// 3. Finalizers run
/// 4. Outcomes discarded
///
/// # Example
///
/// ```ignore
/// let result = race!(cx, {
///     primary_service.fetch().await,
///     backup_service.fetch().await,
/// });
/// // One completed, the other was cancelled and drained
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
    match parse_conformance_args(attr) {
        Ok(_) => item,
        Err(message) => util::compile_error(&message).into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConformanceArgs {
    spec: String,
    requirement: String,
}

fn parse_conformance_args(attr: TokenStream) -> Result<ConformanceArgs, String> {
    let raw = attr.to_string();
    let raw = raw.trim();
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
                ))
            }
        }
    }

    let spec = spec.ok_or_else(|| "conformance attribute missing 'spec'".to_string())?;
    let requirement = requirement
        .ok_or_else(|| "conformance attribute missing 'requirement'".to_string())?;

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
                    ))
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
    use super::parse_conformance_args;
    use proc_macro2::TokenStream as TokenStream2;
    use std::str::FromStr;

    #[test]
    fn parse_conformance_args_ok() {
        let tokens = TokenStream2::from_str(
            r#"spec = "3.2.1", requirement = "Region close waits""#,
        )
        .unwrap();
        let args = parse_conformance_args(tokens.into()).unwrap();
        assert_eq!(args.spec, "3.2.1");
        assert_eq!(args.requirement, "Region close waits");
    }

    #[test]
    fn parse_conformance_args_missing_spec() {
        let tokens =
            TokenStream2::from_str(r#"requirement = "Region close waits""#).unwrap();
        let err = parse_conformance_args(tokens.into()).unwrap_err();
        assert!(err.contains("missing 'spec'"));
    }

    #[test]
    fn parse_conformance_args_missing_requirement() {
        let tokens = TokenStream2::from_str(r#"spec = "3.2.1""#).unwrap();
        let err = parse_conformance_args(tokens.into()).unwrap_err();
        assert!(err.contains("missing 'requirement'"));
    }
}
