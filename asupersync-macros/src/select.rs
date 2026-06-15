//! Implementation of the `select!` macro.
//!
//! `select!` is the N-ary, **heterogeneous** member of the race family: each
//! branch may await a future of a different type and run its own handler arm.
//! It lifts the fixed `Race2`/`Race3`/`Race4` arity ceiling and — like `race!`
//! — keeps the project's "losers are drained" invariant on its blocking path.
//!
//! # Two forms
//!
//! 1. **Blocking, drain-correct** (no `else` arm). Each branch is rewritten into
//!    an `async move { let <pat> = <future>.await; <handler> }` block. Because
//!    every handler arm yields the *same* type `R`, these per-branch blocks are
//!    a homogeneous future list that routes straight through the proven
//!    [`Cx::race_drained`](asupersync::Cx::race_drained) engine: the first
//!    branch to win resolves the `select!`, and every losing branch is
//!    protocol-cancelled **and drained** (awaited to termination) before the
//!    macro returns. Resolves to `Result<R, JoinError>`.
//!
//! 2. **Non-blocking default** (with a trailing `else => <handler>` arm). Each
//!    branch future is polled **exactly once** in source order; the first ready
//!    branch wins, otherwise the `else` handler runs immediately. This is the
//!    Go-style `default` arm: it never waits, so it cannot drain — the
//!    not-ready branches are dropped (cancelled by drop). Resolves to `R`. This
//!    is the one explicit non-blocking opt-out, documented exactly like the
//!    `timeout:` exception on `race!`.
//!
//! # Determinism / tie-break
//!
//! Every `select!` is replay-deterministic: the same seed always produces the
//! same winner. The two forms differ in *how* a tie (several branches ready in
//! the same scheduler turn) is broken:
//!
//! - The **blocking** form resolves through the runtime drain engine
//!   ([`Scope::race_all`](asupersync::Scope::race_all)), which picks among the
//!   same-turn-ready branches with the lab's **seeded** scheduler RNG. The
//!   choice is fixed by the seed (replay-stable), not by source position, so a
//!   different seed may pick a different same-turn winner.
//! - The **`else`** form polls branches in strict **source order** and takes
//!   the first ready branch, so it is biased toward the first listed branch
//!   regardless of seed.
//!
//! The `biased` keyword is accepted on the blocking form for `tokio::select!`
//! familiarity and documents that selection is deterministic; it does not turn
//! the seeded drain tie-break into strict source order. For guaranteed
//! source-order selection, use the `else` (non-blocking) form.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    Error, Expr, Pat, Token, braced,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

/// A single `<pat> = <future> => <handler>` select branch.
struct SelectBranch {
    pat: Pat,
    future: Expr,
    handler: Expr,
}

/// Parsed input to the `select!` macro.
///
/// Supported forms:
/// - `select!(cx, { x = fut_a() => h_a, y = fut_b() => h_b })`
/// - `select!(cx, biased, { x = fut_a() => h_a, y = fut_b() => h_b })`
/// - `select!(cx, { x = fut_a() => h_a, else => fallback })`
struct SelectInput {
    cx: Expr,
    biased: bool,
    branches: Vec<SelectBranch>,
    els: Option<Expr>,
}

impl Parse for SelectInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() || input.peek(syn::token::Brace) {
            return Err(Error::new(input.span(), "select! requires cx argument"));
        }

        let cx: Expr = input.parse()?;

        let _comma: Token![,] = input.parse().map_err(|_| {
            Error::new(
                input.span(),
                "expected comma after cx: select!(cx, { ... })",
            )
        })?;

        // Optional `biased,` mode marker.
        let mut biased = false;
        if input.peek(syn::Ident) {
            let ident: syn::Ident = input.fork().parse()?;
            if ident == "biased" {
                let _: syn::Ident = input.parse()?;
                let _comma: Token![,] = input.parse().map_err(|_| {
                    Error::new(
                        input.span(),
                        "expected comma after biased: select!(cx, biased, { ... })",
                    )
                })?;
                biased = true;
            }
        }

        let content;
        let _brace = braced!(content in input);

        let mut branches = Vec::new();
        let mut els = None;
        while !content.is_empty() {
            if content.peek(Token![else]) {
                let _else: Token![else] = content.parse()?;
                let _arrow: Token![=>] = content.parse().map_err(|_| {
                    Error::new(
                        content.span(),
                        "expected `=>` after else: `else => fallback`",
                    )
                })?;
                els = Some(content.parse()?);

                if content.peek(Token![,]) {
                    let _comma: Token![,] = content.parse()?;
                }
                if !content.is_empty() {
                    return Err(Error::new(
                        content.span(),
                        "select! else arm must be the last arm",
                    ));
                }
                break;
            }

            let pat = Pat::parse_single(&content)?;
            let _eq: Token![=] = content.parse().map_err(|_| {
                Error::new(
                    content.span(),
                    "expected `=` in select branch: `binding = future => handler`",
                )
            })?;
            let future: Expr = content.parse()?;
            let _arrow: Token![=>] = content.parse().map_err(|_| {
                Error::new(
                    content.span(),
                    "expected `=>` in select branch: `binding = future => handler`",
                )
            })?;
            let handler: Expr = content.parse()?;

            branches.push(SelectBranch {
                pat,
                future,
                handler,
            });

            // Commas between arms are optional (tokio-style leniency).
            if content.peek(Token![,]) {
                let _comma: Token![,] = content.parse()?;
            }
        }

        if branches.is_empty() {
            return Err(Error::new(
                input.span(),
                "select! requires at least one branch",
            ));
        }

        if !input.is_empty() {
            return Err(Error::new(
                input.span(),
                "unexpected tokens after select! branches",
            ));
        }

        Ok(Self {
            cx,
            biased,
            branches,
            els,
        })
    }
}

/// Expands the `select!` macro.
pub fn select_impl(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as SelectInput);
    TokenStream::from(generate_select(&parsed))
}

/// Rewrites a branch into a homogeneous `async move` block whose output is the
/// shared handler type `R`: `async move { let <pat> = <future>.await; <handler> }`.
fn branch_future(branch: &SelectBranch) -> TokenStream2 {
    let pat = &branch.pat;
    let fut = &branch.future;
    let handler = &branch.handler;
    quote! {
        async move {
            let #pat = (#fut).await;
            #handler
        }
    }
}

fn generate_select(input: &SelectInput) -> TokenStream2 {
    let SelectInput {
        cx, branches, els, ..
    } = input;

    // `biased` is accepted for tokio familiarity. The blocking form's tie-break
    // is the runtime drain engine's seeded (replay-stable) selection, not strict
    // source order; the `else` form polls strictly in source order. The flag is
    // therefore documentation-level today — read here so the field stays live.
    let _ = input.biased;

    let branch_futs: Vec<TokenStream2> = branches.iter().map(branch_future).collect();

    match els {
        None => {
            // Blocking, drain-correct path: route the homogeneous per-branch
            // future list through the proven `race_drained` engine so every
            // loser is protocol-cancelled and drained before the macro returns.
            let boxed: Vec<TokenStream2> = branch_futs
                .iter()
                .map(|fut| quote! { ::std::boxed::Box::pin(#fut) })
                .collect();
            quote! {
                {
                    (#cx).race_drained(::std::vec![#(#boxed),*]).await
                }
            }
        }
        Some(else_handler) => {
            // Non-blocking default path: poll each branch exactly once in source
            // order, take the first ready branch, otherwise run `else`. The
            // not-ready branches are dropped (this path does not drain — it is
            // the explicit non-blocking opt-out).
            let fut_idents: Vec<_> = (0..branches.len())
                .map(|i| {
                    syn::Ident::new(&format!("__select_fut_{i}"), proc_macro2::Span::call_site())
                })
                .collect();

            let bindings: Vec<TokenStream2> = fut_idents
                .iter()
                .zip(branch_futs.iter())
                .map(|(id, fut)| quote! { let mut #id = ::core::pin::pin!(#fut); })
                .collect();

            let polls: Vec<TokenStream2> = fut_idents
                .iter()
                .map(|id| {
                    quote! {
                        match ::core::future::Future::poll(
                            ::core::pin::Pin::as_mut(&mut #id),
                            __select_cx,
                        ) {
                            ::core::task::Poll::Ready(__select_value) => {
                                return ::core::task::Poll::Ready(__select_value);
                            }
                            ::core::task::Poll::Pending => {}
                        }
                    }
                })
                .collect();

            quote! {
                {
                    let _ = &(#cx);
                    #(#bindings)*
                    // Hold the `else` handler in a one-shot `FnOnce` so the
                    // poll closure (an `FnMut`) can run it by value exactly once
                    // without moving a captured value out of an `FnMut`. The
                    // handler stays lazy — it runs only when no branch is ready.
                    let mut __select_else = ::core::option::Option::Some(move || #else_handler);
                    ::core::future::poll_fn(|__select_cx| {
                        #(#polls)*
                        let __select_default = ::core::option::Option::take(&mut __select_else)
                            .expect("select! else arm polled after completion");
                        ::core::task::Poll::Ready(__select_default())
                    })
                    .await
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses the input as a `SelectInput`, asserting it is rejected, and
    /// returns the error message. Avoids `Result::unwrap_err`, which would
    /// require `SelectInput: Debug` (and thus `syn`'s `extra-traits` feature).
    fn parse_err(input: TokenStream2) -> String {
        match syn::parse2::<SelectInput>(input) {
            Ok(_) => panic!("expected select! parse error, but parsing succeeded"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn parse_basic_two_branch() {
        let input = quote! { cx, { a = fut_a() => a, b = fut_b() => b } };
        let parsed: SelectInput = syn::parse2(input).unwrap();
        assert!(!parsed.biased);
        assert_eq!(parsed.branches.len(), 2);
        assert!(parsed.els.is_none());
    }

    #[test]
    fn parse_single_branch_is_allowed() {
        let input = quote! { cx, { a = fut_a() => a } };
        let parsed: SelectInput = syn::parse2(input).unwrap();
        assert_eq!(parsed.branches.len(), 1);
    }

    #[test]
    fn parse_biased_flag() {
        let input = quote! { cx, biased, { a = fut_a() => a, b = fut_b() => b } };
        let parsed: SelectInput = syn::parse2(input).unwrap();
        assert!(parsed.biased);
        assert_eq!(parsed.branches.len(), 2);
    }

    #[test]
    fn parse_else_arm() {
        let input = quote! { cx, { a = fut_a() => a, else => fallback() } };
        let parsed: SelectInput = syn::parse2(input).unwrap();
        assert_eq!(parsed.branches.len(), 1);
        assert!(parsed.els.is_some());
    }

    #[test]
    fn parse_patterns_in_binding() {
        let input = quote! { cx, { (x, y) = fut_a() => x + y, _ = fut_b() => 0 } };
        let parsed: SelectInput = syn::parse2(input).unwrap();
        assert_eq!(parsed.branches.len(), 2);
    }

    #[test]
    fn missing_cx_is_rejected() {
        let err = parse_err(quote! { { a = fut_a() => a } });
        assert!(err.contains("requires cx argument"), "got: {err}");
    }

    #[test]
    fn empty_branches_are_rejected() {
        let err = parse_err(quote! { cx, { } });
        assert!(err.contains("at least one branch"), "got: {err}");
    }

    #[test]
    fn two_else_arms_are_rejected() {
        // A second `else` is a non-last arm after the first `else`, so it is
        // rejected by the else-must-be-last rule.
        let err = parse_err(quote! { cx, { a = f() => a, else => 1, else => 2 } });
        assert!(err.contains("else arm must be the last arm"), "got: {err}");
    }

    #[test]
    fn else_must_be_last() {
        let err = parse_err(quote! { cx, { a = f() => a, else => 1, b = g() => b } });
        assert!(err.contains("else arm must be the last arm"), "got: {err}");
    }

    /// The drain guarantee (u1z5hn.6 "lie #2", extended to heterogeneous
    /// select) is structural: the blocking (no-else) form must route through
    /// the drain-correct `race_drained` engine, never a drop-only select.
    #[test]
    fn blocking_form_routes_through_race_drained() {
        let parsed: SelectInput =
            syn::parse2(quote! { cx, { a = fut_a() => a, b = fut_b() => b } }).unwrap();
        let tokens = generate_select(&parsed).to_string();
        assert!(
            tokens.contains("race_drained"),
            "blocking select! must use the drained engine, got: {tokens}"
        );
        // No drop-only `. race (` method call may survive.
        assert!(
            !tokens.replace("race_drained", "").contains("race"),
            "no drop-only race* call may survive, got: {tokens}"
        );
        assert!(
            !tokens.contains("poll_fn"),
            "blocking select! must not poll inline, got: {tokens}"
        );
    }

    /// Each branch is rewritten into an `async move { let <pat> = <fut>.await;
    /// <handler> }` block so the per-branch outputs unify to the handler type.
    #[test]
    fn blocking_form_awaits_future_and_runs_handler() {
        let parsed: SelectInput =
            syn::parse2(quote! { cx, { x = fetch() => process(x) } }).unwrap();
        let tokens = generate_select(&parsed).to_string();
        assert!(tokens.contains("let x"), "binding must be bound: {tokens}");
        assert!(tokens.contains("fetch"), "future must be awaited: {tokens}");
        assert!(
            tokens.contains(". await"),
            "branch future must be awaited: {tokens}"
        );
        assert!(
            tokens.contains("process"),
            "handler must run after await: {tokens}"
        );
    }

    /// The `else` form is the non-blocking default: it polls inline and never
    /// reaches the spawning `race_drained` engine.
    #[test]
    fn else_form_polls_inline_and_skips_race_drained() {
        let parsed: SelectInput =
            syn::parse2(quote! { cx, { a = fut_a() => a, else => fallback() } }).unwrap();
        let tokens = generate_select(&parsed).to_string();
        assert!(
            tokens.contains("poll_fn"),
            "else select! must poll inline via poll_fn, got: {tokens}"
        );
        assert!(
            !tokens.contains("race_drained"),
            "else select! is non-blocking and must not spawn/drain, got: {tokens}"
        );
        assert!(
            tokens.contains("fallback"),
            "else handler must appear in the expansion, got: {tokens}"
        );
        assert!(
            tokens.contains("Pin :: as_mut") || tokens.contains("Pin::as_mut"),
            "else select! must re-poll pinned branches via Pin::as_mut, got: {tokens}"
        );
    }

    /// The biased mode shares the deterministic source-order engine; the flag is
    /// accepted and the expansion is still drain-correct.
    #[test]
    fn biased_blocking_form_still_drains() {
        let parsed: SelectInput =
            syn::parse2(quote! { cx, biased, { a = fut_a() => a, b = fut_b() => b } }).unwrap();
        assert!(parsed.biased);
        let tokens = generate_select(&parsed).to_string();
        assert!(
            tokens.contains("race_drained"),
            "biased select! must still use the drained engine, got: {tokens}"
        );
    }
}
