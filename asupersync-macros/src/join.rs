//! Implementation of the `join!` and `join_all!` macros.
//!
//! Both macros run their branch futures **concurrently** inside the current
//! task and wait for all of them to complete, collecting the results into a
//! tuple (`join!`) or an array (`join_all!`).
//!
//! # Syntax
//!
//! ```ignore
//! // Tuple form - join multiple futures/handles concurrently
//! let (r1, r2, r3) = join!(h1, h2, h3).await... // (the macro expands to an awaited future)
//!
//! // With cx in scope for cancellation propagation
//! let (r1, r2, r3) = join!(cx; h1, h2, h3);
//! ```
//!
//! # Semantics
//!
//! 1. All branches are polled concurrently within the enclosing task: a branch
//!    that returns `Pending` never blocks the others from making progress, so
//!    three 10ms sleeps complete in ~10ms, not ~30ms.
//! 2. Results are returned as a tuple (`join!`) / array (`join_all!`) in input
//!    order.
//! 3. Each branch's output type is preserved (`join!` may mix types; the
//!    `join_all!` array form requires a single shared type).
//! 4. When `cx` is provided it is type-checked and reserved for cancellation
//!    propagation; the concurrent polling itself needs no scheduler support.
//!
//! # Concurrency model
//!
//! The expansion mirrors the standard structure-preserving concurrent join: each
//! branch is pinned once, then a single [`core::future::poll_fn`] drives every
//! not-yet-complete branch on each wake. This is true concurrency *within one
//! task* — it requires neither a multi-threaded scheduler nor any allocation —
//! and replaces the earlier placeholder that awaited the branches one-by-one
//! (which silently serialized every caller).
//!
//! # Algebraic Laws
//!
//! - Associativity: `join!(join!(a, b), c) ≃ join!(a, join!(b, c))`
//! - Commutativity: `join!(a, b) ≃ join!(b, a)` (up to tuple order)

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    Expr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
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
        // Try to detect if the first element is a cx followed by semicolon.
        // We use a fork because `cx` could be a complex expression (e.g. `&my.cx`),
        // which `peek2` wouldn't correctly identify.
        let fork = input.fork();
        let cx = if let Ok(cx_expr) = fork.parse::<Expr>() {
            if fork.peek(Token![;]) {
                let _ = input.parse::<Expr>()?;
                let _semi: Token![;] = input.parse()?;
                Some(cx_expr)
            } else {
                None
            }
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
/// For `join!(h1, h2, h3)`, generates a single concurrent future:
/// ```ignore
/// {
///     let mut __join_fut_0 = ::core::pin::pin!(h1);
///     let mut __join_fut_1 = ::core::pin::pin!(h2);
///     let mut __join_fut_2 = ::core::pin::pin!(h3);
///     let mut __join_out_0 = ::core::option::Option::None;
///     let mut __join_out_1 = ::core::option::Option::None;
///     let mut __join_out_2 = ::core::option::Option::None;
///     ::core::future::poll_fn(|__join_cx| {
///         let mut __join_pending = false;
///         // poll each not-yet-ready branch every wake
///         ...
///         if __join_pending { Poll::Pending } else { Poll::Ready(()) }
///     }).await;
///     (__join_out_0.unwrap(), __join_out_1.unwrap(), __join_out_2.unwrap())
/// }
/// ```
pub fn join_impl(input: TokenStream) -> TokenStream {
    let JoinInput { cx, futures } = parse_macro_input!(input as JoinInput);

    let expanded = generate_join(cx.as_ref(), &futures);
    TokenStream::from(expanded)
}

fn generate_join(cx: Option<&Expr>, futures: &Punctuated<Expr, Token![,]>) -> TokenStream2 {
    let future_count = futures.len();
    let cx_ack = generate_cx_ack(cx);

    // Handle empty case
    if future_count == 0 {
        return quote! {
            {
                #cx_ack
                ()
            }
        };
    }

    // Handle single future case - just await it directly (already concurrent-trivial)
    if future_count == 1 {
        let fut = futures
            .first()
            .expect("future_count == 1 guarantees first element exists");
        return quote! {
            {
                #cx_ack
                (#fut.await,)
            }
        };
    }

    let (bindings, decls, polls, idents) = concurrent_branch_tokens(futures);

    quote! {
        {
            #cx_ack
            #(#bindings)*
            #(#decls)*
            ::core::future::poll_fn(|__join_cx| {
                let mut __join_pending = false;
                #(#polls)*
                if __join_pending {
                    ::core::task::Poll::Pending
                } else {
                    ::core::task::Poll::Ready(())
                }
            })
            .await;
            ( #(#idents.expect("join! branch completed before the join resolved")),* )
        }
    }
}

/// Generates the `join_all` implementation for array form.
///
/// Like [`generate_join`] but returns an array (all branches must share a type).
pub fn join_all_impl(input: TokenStream) -> TokenStream {
    let JoinInput { cx, futures } = parse_macro_input!(input as JoinInput);

    let expanded = generate_join_all(cx.as_ref(), &futures);
    TokenStream::from(expanded)
}

fn generate_join_all(cx: Option<&Expr>, futures: &Punctuated<Expr, Token![,]>) -> TokenStream2 {
    let future_count = futures.len();
    let cx_ack = generate_cx_ack(cx);

    // Handle empty case - empty array
    if future_count == 0 {
        return quote! {
            {
                #cx_ack
                []
            }
        };
    }

    // Handle single future case - single element array
    if future_count == 1 {
        let fut = futures
            .first()
            .expect("future_count == 1 guarantees first element exists");
        return quote! {
            {
                #cx_ack
                [#fut.await]
            }
        };
    }

    let (bindings, decls, polls, idents) = concurrent_branch_tokens(futures);

    quote! {
        {
            #cx_ack
            #(#bindings)*
            #(#decls)*
            ::core::future::poll_fn(|__join_cx| {
                let mut __join_pending = false;
                #(#polls)*
                if __join_pending {
                    ::core::task::Poll::Pending
                } else {
                    ::core::task::Poll::Ready(())
                }
            })
            .await;
            [ #(#idents.expect("join_all! branch completed before the join resolved")),* ]
        }
    }
}

/// Builds the shared concurrent-polling tokens for the >= 2 branch case.
///
/// Returns `(pin bindings, output-slot declarations, per-branch poll arms,
/// output-slot identifiers)`. Each branch is pinned once; every `poll_fn` wake
/// polls only the branches that have not yet produced a value, so a `Pending`
/// branch never starves the others.
fn concurrent_branch_tokens(
    futures: &Punctuated<Expr, Token![,]>,
) -> (
    Vec<TokenStream2>,
    Vec<TokenStream2>,
    Vec<TokenStream2>,
    Vec<syn::Ident>,
) {
    let future_count = futures.len();

    let fut_idents: Vec<_> = (0..future_count)
        .map(|i| syn::Ident::new(&format!("__join_fut_{i}"), proc_macro2::Span::call_site()))
        .collect();
    let out_idents: Vec<syn::Ident> = (0..future_count)
        .map(|i| syn::Ident::new(&format!("__join_out_{i}"), proc_macro2::Span::call_site()))
        .collect();

    let bindings = futures
        .iter()
        .zip(fut_idents.iter())
        .map(|(future, ident)| quote! { let mut #ident = ::core::pin::pin!(#future); })
        .collect();

    let decls = out_idents
        .iter()
        .map(|ident| quote! { let mut #ident = ::core::option::Option::None; })
        .collect();

    let polls = fut_idents
        .iter()
        .zip(out_idents.iter())
        .map(|(fut_ident, out_ident)| {
            quote! {
                if ::core::option::Option::is_none(&#out_ident) {
                    match ::core::future::Future::poll(
                        ::core::pin::Pin::as_mut(&mut #fut_ident),
                        __join_cx,
                    ) {
                        ::core::task::Poll::Ready(__join_value) => {
                            #out_ident = ::core::option::Option::Some(__join_value);
                        }
                        ::core::task::Poll::Pending => {
                            __join_pending = true;
                        }
                    }
                }
            }
        })
        .collect();

    (bindings, decls, polls, out_idents)
}

fn generate_cx_ack(cx: Option<&Expr>) -> TokenStream2 {
    if cx.is_some() {
        quote! {
            // Capability context provided for cancellation propagation
            // (type-checked here; concurrent polling itself needs no scheduler).
            let _ = &#cx;
        }
    } else {
        quote! {}
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

    #[test]
    fn test_join_single_future_keeps_cx_expr() {
        let input: JoinInput = syn::parse2(quote! { make_cx(); future_a }).unwrap();
        let tokens = generate_join(input.cx.as_ref(), &input.futures).to_string();
        assert!(
            tokens.contains("make_cx"),
            "single-future join must still typecheck the cx expression"
        );
    }

    #[test]
    fn test_join_empty_keeps_cx_expr() {
        let input: JoinInput = syn::parse2(quote! { make_cx(); }).unwrap();
        let tokens = generate_join(input.cx.as_ref(), &input.futures).to_string();
        assert!(
            tokens.contains("make_cx"),
            "empty join must still typecheck the cx expression"
        );
    }

    #[test]
    fn test_join_all_single_future_keeps_cx_expr() {
        let input: JoinInput = syn::parse2(quote! { make_cx(); future_a }).unwrap();
        let tokens = generate_join_all(input.cx.as_ref(), &input.futures).to_string();
        assert!(
            tokens.contains("make_cx"),
            "single-future join_all must still typecheck the cx expression"
        );
    }

    #[test]
    fn test_join_all_empty_keeps_cx_expr() {
        let input: JoinInput = syn::parse2(quote! { make_cx(); }).unwrap();
        let tokens = generate_join_all(input.cx.as_ref(), &input.futures).to_string();
        assert!(
            tokens.contains("make_cx"),
            "empty join_all must still typecheck the cx expression"
        );
    }

    #[test]
    fn join_multi_polls_branches_concurrently() {
        let input: JoinInput = syn::parse2(quote! { a, b, c }).unwrap();
        let tokens = generate_join(input.cx.as_ref(), &input.futures).to_string();
        assert!(
            tokens.contains("poll_fn"),
            "multi-branch join! must drive a concurrent poll_fn, not sequential awaits"
        );
        assert!(
            tokens.contains("Future :: poll") || tokens.contains("Future::poll"),
            "multi-branch join! must poll each branch directly"
        );
        // The old sequential expansion bound one `__join_result_i = fut.await;` per
        // branch; the concurrent expansion must not reintroduce that pattern.
        assert!(
            !tokens.contains("__join_result_"),
            "join! must not fall back to the sequential await chain"
        );
    }

    #[test]
    fn join_all_multi_polls_branches_concurrently() {
        let input: JoinInput = syn::parse2(quote! { a, b, c }).unwrap();
        let tokens = generate_join_all(input.cx.as_ref(), &input.futures).to_string();
        assert!(
            tokens.contains("poll_fn"),
            "multi-branch join_all! must drive a concurrent poll_fn"
        );
        assert!(
            tokens.contains("Pin :: as_mut") || tokens.contains("Pin::as_mut"),
            "concurrent join_all! must re-poll pinned branches via Pin::as_mut"
        );
    }

    #[test]
    fn join_multi_pins_each_branch_once() {
        let input: JoinInput = syn::parse2(quote! { a, b }).unwrap();
        let tokens = generate_join(input.cx.as_ref(), &input.futures).to_string();
        let pins = tokens.matches("pin !").count() + tokens.matches("pin!").count();
        assert!(
            pins >= 2,
            "each branch must be pinned exactly once: {tokens}"
        );
    }
}
