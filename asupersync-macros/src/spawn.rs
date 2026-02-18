//! Implementation of the `spawn!` macro.
//!
//! The spawn macro creates a task owned by the enclosing region.
//! The task cannot orphan and will be cancelled when the region closes.
//!
//! # Ambient Variables
//!
//! The generated code expects these variables to be in scope:
//! - `__state: &mut RuntimeState` - The runtime state for task registration
//! - `__cx: &Cx` - The capability context for creating child contexts
//!
//! These are typically provided by the `scope!` macro.
//!
//! # Usage
//!
//! ```ignore
//! // Basic usage (uses implicit `scope` variable)
//! let handle = spawn!(async { compute().await });
//!
//! // With explicit scope
//! let handle = spawn!(my_scope, async { compute().await });
//!
//! // With name for debugging/tracing
//! let handle = spawn!("worker", async { compute().await });
//!
//! // With scope and name
//! let handle = spawn!(my_scope, "worker", async { compute().await });
//! ```

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    Error, Expr, Lit, LitStr, Token, parse::Parse, parse_macro_input, punctuated::Punctuated,
    spanned::Spanned,
};

/// Input to the spawn! macro.
///
/// Supported forms:
/// - `spawn!(future)`
/// - `spawn!("name", future)`
/// - `spawn!(scope, future)`
/// - `spawn!(scope, "name", future)`
struct SpawnInput {
    scope: Option<Expr>,
    name: Option<LitStr>,
    future: Expr,
}

impl Parse for SpawnInput {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let args: Punctuated<Expr, Token![,]> = Punctuated::parse_terminated(input)?;
        let mut items: Vec<Expr> = args.into_iter().collect();

        if items.is_empty() {
            return Err(Error::new(
                input.span(),
                "spawn! requires a future expression",
            ));
        }

        let is_str_lit = |expr: &Expr| match expr {
            Expr::Lit(lit) => matches!(lit.lit, Lit::Str(_)),
            _ => false,
        };

        let take_str = |expr: &Expr| match expr {
            Expr::Lit(lit) => match &lit.lit {
                Lit::Str(s) => Some(s.clone()),
                _ => None,
            },
            _ => None,
        };

        let (scope, name, future) = match items.len() {
            1 => {
                if is_str_lit(&items[0]) {
                    return Err(Error::new(
                        items[0].span(),
                        "spawn! argument must be a future expression",
                    ));
                }
                (None, None, items.remove(0))
            }
            2 => {
                if is_str_lit(&items[0]) {
                    if is_str_lit(&items[1]) {
                        return Err(Error::new(
                            items[1].span(),
                            "spawn! argument must be a future expression",
                        ));
                    }
                    let name = take_str(&items[0]).expect("string literal checked");
                    (None, Some(name), items.remove(1))
                } else if is_str_lit(&items[1]) {
                    return Err(Error::new(
                        items[1].span(),
                        "spawn! requires a future expression",
                    ));
                } else {
                    (Some(items.remove(0)), None, items.remove(0))
                }
            }
            3 => {
                let scope = items.remove(0);
                let name = take_str(&items[0]).ok_or_else(|| {
                    Error::new(items[0].span(), "spawn! name must be a string literal")
                })?;
                let future = items.remove(1);
                (Some(scope), Some(name), future)
            }
            _ => {
                return Err(Error::new(
                    input.span(),
                    "spawn! accepts at most three arguments: [scope], [\"name\"], future",
                ));
            }
        };

        Ok(Self {
            scope,
            name,
            future,
        })
    }
}

/// Generates the spawn implementation.
///
/// This expands to a `scope.spawn_registered(...)` call with the provided
/// future wrapped in an `async move` block. The generated code expects
/// `__state` and `__cx` ambient variables to be in scope.
pub fn spawn_impl(input: TokenStream) -> TokenStream {
    let SpawnInput {
        scope,
        name,
        future,
    } = parse_macro_input!(input as SpawnInput);

    let expanded = generate_spawn(scope.as_ref(), name.as_ref(), &future);
    TokenStream::from(expanded)
}

fn generate_spawn(scope: Option<&Expr>, name: Option<&LitStr>, future: &Expr) -> TokenStream2 {
    let scope_expr: Expr =
        scope.map_or_else(|| syn::parse_quote! { scope }, std::clone::Clone::clone);

    // Generate the spawn call using spawn_registered which handles
    // both creating the task and storing it in the runtime state.
    // The name is used for tracing/debugging purposes.
    let name_trace = name.map_or_else(
        || quote! {},
        |name_lit| {
            quote! {
                // Task name for tracing: #name_lit
                let _ = #name_lit;
            }
        },
    );

    quote! {
        {
            // spawn! macro expansion
            let __scope = &#scope_expr;
            #name_trace
            __scope.spawn_registered(__state, __cx, |__child_cx| {
                // Suppress unused warning if cx isn't used in the future
                let _ = &__child_cx;
                async move {
                    (#future).await
                }
            }).expect("spawn! failed: region closed or not found")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Parsing tests
    // =========================================================================

    #[test]
    fn test_parse_spawn_future_only() {
        let input: proc_macro2::TokenStream = quote! { async { 42 } };
        let parsed: SpawnInput = syn::parse2(input).unwrap();
        assert!(parsed.scope.is_none());
        assert!(parsed.name.is_none());
        assert!(matches!(parsed.future, Expr::Async(_)));
    }

    #[test]
    fn test_parse_spawn_with_scope() {
        let input: proc_macro2::TokenStream = quote! { scope, async move { captured } };
        let parsed: SpawnInput = syn::parse2(input).unwrap();
        assert!(parsed.scope.is_some());
        assert!(parsed.name.is_none());
        assert!(matches!(parsed.future, Expr::Async(_)));
    }

    #[test]
    fn test_parse_spawn_with_name() {
        let input: proc_macro2::TokenStream = quote! { "worker", async { 42 } };
        let parsed: SpawnInput = syn::parse2(input).unwrap();
        assert!(parsed.scope.is_none());
        assert!(parsed.name.is_some());
        assert!(matches!(parsed.future, Expr::Async(_)));
    }

    #[test]
    fn test_parse_spawn_with_scope_and_name() {
        let input: proc_macro2::TokenStream = quote! { scope, "worker", async { 42 } };
        let parsed: SpawnInput = syn::parse2(input).unwrap();
        assert!(parsed.scope.is_some());
        assert!(parsed.name.is_some());
        assert!(matches!(parsed.future, Expr::Async(_)));
    }

    #[test]
    fn test_parse_error_empty() {
        let input: proc_macro2::TokenStream = quote! {};
        let result: Result<SpawnInput, _> = syn::parse2(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_string_only() {
        let input: proc_macro2::TokenStream = quote! { "worker" };
        let result: Result<SpawnInput, _> = syn::parse2(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_too_many_args() {
        let input: proc_macro2::TokenStream = quote! { a, b, c, d };
        let result: Result<SpawnInput, _> = syn::parse2(input);
        assert!(result.is_err());
    }

    // =========================================================================
    // Code generation tests
    // =========================================================================

    #[test]
    fn test_generate_basic_spawn() {
        let input: proc_macro2::TokenStream = quote! { async { 42 } };
        let parsed: SpawnInput = syn::parse2(input).unwrap();
        let generated = generate_spawn(parsed.scope.as_ref(), parsed.name.as_ref(), &parsed.future);

        let generated_str = generated.to_string();
        // Should reference the implicit `scope` variable
        assert!(generated_str.contains("scope"), "Should use implicit scope");
        // Should call spawn_registered
        assert!(
            generated_str.contains("spawn_registered"),
            "Should call spawn_registered"
        );
        // Should reference __state and __cx
        assert!(generated_str.contains("__state"), "Should use __state");
        assert!(generated_str.contains("__cx"), "Should use __cx");
        // Should contain async move
        assert!(
            generated_str.contains("async move"),
            "Should wrap in async move"
        );
    }

    #[test]
    fn test_generate_spawn_with_explicit_scope() {
        let input: proc_macro2::TokenStream = quote! { my_scope, async { 42 } };
        let parsed: SpawnInput = syn::parse2(input).unwrap();
        let generated = generate_spawn(parsed.scope.as_ref(), parsed.name.as_ref(), &parsed.future);

        let generated_str = generated.to_string();
        // Should use the explicit scope name
        assert!(
            generated_str.contains("my_scope"),
            "Should use explicit scope"
        );
        assert!(
            generated_str.contains("spawn_registered"),
            "Should call spawn_registered"
        );
    }

    #[test]
    fn test_generate_spawn_with_name() {
        let input: proc_macro2::TokenStream = quote! { "worker", async { 42 } };
        let parsed: SpawnInput = syn::parse2(input).unwrap();
        let generated = generate_spawn(parsed.scope.as_ref(), parsed.name.as_ref(), &parsed.future);

        let generated_str = generated.to_string();
        // Should include the task name
        assert!(
            generated_str.contains("\"worker\""),
            "Should include task name"
        );
        assert!(
            generated_str.contains("spawn_registered"),
            "Should call spawn_registered"
        );
    }

    #[test]
    fn test_generate_spawn_with_scope_and_name() {
        let input: proc_macro2::TokenStream = quote! { my_scope, "task1", async { 42 } };
        let parsed: SpawnInput = syn::parse2(input).unwrap();
        let generated = generate_spawn(parsed.scope.as_ref(), parsed.name.as_ref(), &parsed.future);

        let generated_str = generated.to_string();
        assert!(
            generated_str.contains("my_scope"),
            "Should use explicit scope"
        );
        assert!(
            generated_str.contains("\"task1\""),
            "Should include task name"
        );
        assert!(
            generated_str.contains("spawn_registered"),
            "Should call spawn_registered"
        );
    }

    #[test]
    fn test_generate_spawn_closure_receives_cx() {
        let input: proc_macro2::TokenStream = quote! { async { 42 } };
        let parsed: SpawnInput = syn::parse2(input).unwrap();
        let generated = generate_spawn(parsed.scope.as_ref(), parsed.name.as_ref(), &parsed.future);

        let generated_str = generated.to_string();
        // The closure should receive __child_cx
        assert!(
            generated_str.contains("__child_cx"),
            "Closure should receive child cx"
        );
    }
}
