//! Implementation of the `join!` macro.
//!
//! The join macro runs multiple futures concurrently and waits for all
//! to complete, collecting their results into a tuple.
//!
//! # Syntax
//!
//! ```ignore
//! // Tuple form - await multiple futures/handles
//! let (r1, r2, r3) = join!(h1, h2, h3);
//!
//! // With cx for cancellation propagation
//! let (r1, r2, r3) = join!(cx; h1, h2, h3);
//! ```
//!
//! # Semantics
//!
//! 1. All futures are awaited (in Phase 0, sequentially; in Phase 1+, concurrently)
//! 2. Results are returned as a tuple matching input order
//! 3. If any future returns Panicked, the aggregate outcome reflects the worst severity
//! 4. When `cx` is provided, it can be used for cancellation propagation (future enhancement)
//!
//! # Algebraic Laws
//!
//! - Associativity: `join!(join!(a, b), c) ≃ join!(a, join!(b, c))`
//! - Commutativity: `join!(a, b) ≃ join!(b, a)` (up to tuple order)

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    Expr, Token,
};

/// Input to the join! macro.
///
/// Supports two forms:
/// 1. `join!(future1, future2, ...)` - just futures
/// 2. `join!(cx; future1, future2, ...)` - cx followed by semicolon, then futures
struct JoinInput {
    /// Optional capability context for cancellation propagation.
    cx: Option<Expr>,
    /// The futures/handles to join.
    futures: Punctuated<Expr, Token![,]>,
}

impl Parse for JoinInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Try to detect if the first element is a cx followed by semicolon
        let cx = if input.peek2(Token![;]) {
            let cx_expr: Expr = input.parse()?;
            let _semi: Token![;] = input.parse()?;
            Some(cx_expr)
        } else {
            None
        };

        let futures = Punctuated::parse_terminated(input)?;

        Ok(Self { cx, futures })
    }
}

/// Generates the join implementation.
///
/// # Generated Code
///
/// For `join!(h1, h2, h3)`, generates:
/// ```ignore
/// {
///     let __join_fut_0 = h1;
///     let __join_fut_1 = h2;
///     let __join_fut_2 = h3;
///     let __join_result_0 = __join_fut_0.await;
///     let __join_result_1 = __join_fut_1.await;
///     let __join_result_2 = __join_fut_2.await;
///     (__join_result_0, __join_result_1, __join_result_2)
/// }
/// ```
///
/// For `join!(cx; h1, h2, h3)`, generates similar code with cx available
/// for future cancellation propagation enhancements.
///
/// # Phase 0 Implementation
///
/// In Phase 0 (single-threaded), futures are awaited sequentially.
/// This is correct because true concurrent polling requires the
/// multi-threaded scheduler from Phase 1.
///
/// # Phase 1+ Enhancement
///
/// When the multi-threaded runtime is available, this can be enhanced to:
/// - Use `futures::join!` or custom concurrent polling
/// - Propagate cancellation through cx
/// - Support fail-fast semantics on panic
pub fn join_impl(input: TokenStream) -> TokenStream {
    let JoinInput { cx, futures } = parse_macro_input!(input as JoinInput);

    let expanded = generate_join(cx.as_ref(), &futures);
    TokenStream::from(expanded)
}

fn generate_join(cx: Option<&Expr>, futures: &Punctuated<Expr, Token![,]>) -> TokenStream2 {
    let future_count = futures.len();

    // Handle empty case
    if future_count == 0 {
        return quote! { () };
    }

    // Handle single future case - just await it directly
    if future_count == 1 {
        let fut = futures.first().unwrap();
        return quote! {
            (#fut.await,)
        };
    }

    // Generate unique identifiers for futures and results
    let fut_idents: Vec<_> = (0..future_count)
        .map(|i| syn::Ident::new(&format!("__join_fut_{i}"), proc_macro2::Span::call_site()))
        .collect();

    let result_idents: Vec<_> = (0..future_count)
        .map(|i| {
            syn::Ident::new(
                &format!("__join_result_{i}"),
                proc_macro2::Span::call_site(),
            )
        })
        .collect();

    // Generate bindings for each future (evaluate immediately, don't await yet)
    let fut_bindings: Vec<_> = futures
        .iter()
        .zip(fut_idents.iter())
        .map(|(future, ident)| {
            quote! { let #ident = #future; }
        })
        .collect();

    // Generate await statements for each future
    let await_stmts: Vec<_> = fut_idents
        .iter()
        .zip(result_idents.iter())
        .map(|(fut_ident, result_ident)| {
            quote! { let #result_ident = #fut_ident.await; }
        })
        .collect();

    // Generate the result tuple
    let result_tuple: Vec<_> = result_idents
        .iter()
        .map(|ident| quote! { #ident })
        .collect();

    // If cx is provided, we can use it for future enhancements
    // For now, we just acknowledge it in a comment
    let cx_comment = if cx.is_some() {
        quote! {
            // Capability context provided for cancellation propagation
            // (Phase 1+ will use this for concurrent polling with cancellation)
            let _ = &#cx;
        }
    } else {
        quote! {}
    };

    quote! {
        {
            #cx_comment
            // Bind all futures first (ensures evaluation order is left-to-right)
            #(#fut_bindings)*
            // Await all futures (Phase 0: sequential, Phase 1+: concurrent)
            #(#await_stmts)*
            // Return results as tuple
            (#(#result_tuple),*)
        }
    }
}

/// Generates the `join_all` implementation for array form.
///
/// # Generated Code
///
/// For `join_all!(h1, h2, h3)`, generates:
/// ```ignore
/// {
///     let __join_fut_0 = h1;
///     let __join_fut_1 = h2;
///     let __join_fut_2 = h3;
///     let __join_result_0 = __join_fut_0.await;
///     let __join_result_1 = __join_fut_1.await;
///     let __join_result_2 = __join_fut_2.await;
///     [__join_result_0, __join_result_1, __join_result_2]
/// }
/// ```
///
/// Unlike `join!` which returns a tuple, `join_all!` returns an array.
/// All futures must return the same type.
pub fn join_all_impl(input: TokenStream) -> TokenStream {
    let JoinInput { cx, futures } = parse_macro_input!(input as JoinInput);

    let expanded = generate_join_all(cx.as_ref(), &futures);
    TokenStream::from(expanded)
}

fn generate_join_all(cx: Option<&Expr>, futures: &Punctuated<Expr, Token![,]>) -> TokenStream2 {
    let future_count = futures.len();

    // Handle empty case - empty array
    if future_count == 0 {
        return quote! { [] };
    }

    // Handle single future case - single element array
    if future_count == 1 {
        let fut = futures.first().unwrap();
        return quote! {
            [#fut.await]
        };
    }

    // Generate unique identifiers for futures and results
    let fut_idents: Vec<_> = (0..future_count)
        .map(|i| syn::Ident::new(&format!("__join_fut_{i}"), proc_macro2::Span::call_site()))
        .collect();

    let result_idents: Vec<_> = (0..future_count)
        .map(|i| {
            syn::Ident::new(
                &format!("__join_result_{i}"),
                proc_macro2::Span::call_site(),
            )
        })
        .collect();

    // Generate bindings for each future (evaluate immediately, don't await yet)
    let fut_bindings: Vec<_> = futures
        .iter()
        .zip(fut_idents.iter())
        .map(|(future, ident)| {
            quote! { let #ident = #future; }
        })
        .collect();

    // Generate await statements for each future
    let await_stmts: Vec<_> = fut_idents
        .iter()
        .zip(result_idents.iter())
        .map(|(fut_ident, result_ident)| {
            quote! { let #result_ident = #fut_ident.await; }
        })
        .collect();

    // Generate the result array
    let result_array: Vec<_> = result_idents
        .iter()
        .map(|ident| quote! { #ident })
        .collect();

    // If cx is provided, we can use it for future enhancements
    let cx_comment = if cx.is_some() {
        quote! {
            // Capability context provided for cancellation propagation
            // (Phase 1+ will use this for concurrent polling with cancellation)
            let _ = &#cx;
        }
    } else {
        quote! {}
    };

    quote! {
        {
            #cx_comment
            // Bind all futures first (ensures evaluation order is left-to-right)
            #(#fut_bindings)*
            // Await all futures (Phase 0: sequential, Phase 1+: concurrent)
            #(#await_stmts)*
            // Return results as array
            [#(#result_array),*]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_future() {
        let input: proc_macro2::TokenStream = quote! { future_a };
        let parsed: JoinInput = syn::parse2(input).unwrap();
        assert_eq!(parsed.futures.len(), 1);
    }

    #[test]
    fn test_parse_multiple_futures() {
        let input: proc_macro2::TokenStream = quote! { future_a, future_b, future_c };
        let parsed: JoinInput = syn::parse2(input).unwrap();
        assert_eq!(parsed.futures.len(), 3);
    }

    #[test]
    fn test_parse_trailing_comma() {
        let input: proc_macro2::TokenStream = quote! { future_a, future_b, };
        let parsed: JoinInput = syn::parse2(input).unwrap();
        assert_eq!(parsed.futures.len(), 2);
    }

    #[test]
    fn test_parse_with_cx() {
        let input: proc_macro2::TokenStream = quote! { cx; future_a, future_b };
        let parsed: JoinInput = syn::parse2(input).unwrap();
        assert!(parsed.cx.is_some());
        assert_eq!(parsed.futures.len(), 2);
    }
}
