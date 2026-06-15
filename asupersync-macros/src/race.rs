//! Implementation of the `race!` macro.
//!
//! The race macro runs multiple inline futures and returns the first result.
//!
//! Losing branches are protocol-cancelled **and drained** before the macro
//! returns: the expansion routes through `Cx::race_drained*`, which spawns each
//! branch as a region task and resolves them via `Scope::race_all`. This is the
//! drain guarantee that differentiates `race!` from a plain drop-the-losers
//! select — resources held by a losing branch are resolved, not abandoned. The
//! older drop-only expansion (`Cx::race*`) is no longer emitted.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    Error, Expr, Ident, LitStr, Token, braced,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

/// A single race branch.
struct RaceBranch {
    name: Option<LitStr>,
    future: Expr,
}

/// Input to the race! macro.
///
/// Supported forms:
/// - `race!(cx, { fut1(), fut2() })`
/// - `race!(cx, { "name" => fut1(), "other" => fut2() })`
/// - `race!(cx, timeout: Duration::from_secs(5), { fut1(), fut2() })`
struct RaceInput {
    cx: Expr,
    timeout: Option<Expr>,
    branches: Vec<RaceBranch>,
}

impl Parse for RaceInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() || input.peek(syn::token::Brace) {
            return Err(Error::new(input.span(), "race! requires cx argument"));
        }

        let cx: Expr = input.parse()?;

        let _comma: Token![,] = input
            .parse()
            .map_err(|_| Error::new(input.span(), "expected comma after cx: race!(cx, { ... })"))?;

        let mut timeout = None;
        if input.peek(Ident) {
            let ident: Ident = input.fork().parse()?;
            if ident == "timeout" {
                let _: Ident = input.parse()?;
                let _colon: Token![:] = input
                    .parse()
                    .map_err(|_| Error::new(input.span(), "expected colon after timeout"))?;
                timeout = Some(input.parse()?);
                let _comma: Token![,] = input.parse().map_err(|_| {
                    Error::new(
                        input.span(),
                        "expected comma after timeout: race!(cx, timeout: expr, { ... })",
                    )
                })?;
            }
        }

        let content;
        let _brace = braced!(content in input);

        let mut branches = Vec::new();
        let mut named = None;
        while !content.is_empty() {
            let branch = if content.peek(LitStr) && content.peek2(Token![=>]) {
                let name: LitStr = content.parse()?;
                let _arrow: Token![=>] = content.parse()?;
                let future: Expr = content.parse()?;
                RaceBranch {
                    name: Some(name),
                    future,
                }
            } else {
                let future: Expr = content.parse()?;
                RaceBranch { name: None, future }
            };

            let is_named = branch.name.is_some();
            if let Some(prev) = named {
                if prev != is_named {
                    return Err(Error::new(
                        content.span(),
                        "race! branches must be either all named or all unnamed",
                    ));
                }
            } else {
                named = Some(is_named);
            }

            branches.push(branch);

            if content.peek(Token![,]) {
                let _comma: Token![,] = content.parse()?;
            }
        }

        if branches.len() < 2 {
            return Err(Error::new(
                input.span(),
                "race! requires at least two branches",
            ));
        }

        if !input.is_empty() {
            return Err(Error::new(
                input.span(),
                "unexpected tokens after race! branches",
            ));
        }

        Ok(Self {
            cx,
            timeout,
            branches,
        })
    }
}

/// Generates the race implementation.
///
/// This expands to a drain-correct `cx.race_drained(...)`/`cx.race_drained_named(...)`
/// call (or timeout variants), with each branch boxed and spawned by the
/// `Cx::race_drained*` engine so losers are cancelled and drained.
pub fn race_impl(input: TokenStream) -> TokenStream {
    let RaceInput {
        cx,
        timeout,
        branches,
    } = parse_macro_input!(input as RaceInput);

    let expanded = generate_race(&cx, timeout.as_ref(), &branches);
    TokenStream::from(expanded)
}

fn generate_race(cx: &Expr, timeout: Option<&Expr>, branches: &[RaceBranch]) -> TokenStream2 {
    let named = branches.first().and_then(|b| b.name.as_ref()).is_some();

    let boxed_futures: Vec<TokenStream2> = branches
        .iter()
        .map(|branch| {
            let fut = &branch.future;
            let fut_expr = quote! {
                ::std::boxed::Box::pin(#fut)
            };
            if let Some(name) = &branch.name {
                quote! { (#name, #fut_expr) }
            } else {
                fut_expr
            }
        })
        .collect();

    let call = match (timeout, named) {
        (Some(timeout_expr), true) => quote! {
            (#cx).race_drained_timeout_named(#timeout_expr, vec![#(#boxed_futures),*]).await
        },
        (Some(timeout_expr), false) => quote! {
            (#cx).race_drained_timeout(#timeout_expr, vec![#(#boxed_futures),*]).await
        },
        (None, true) => quote! {
            (#cx).race_drained_named(vec![#(#boxed_futures),*]).await
        },
        (None, false) => quote! {
            (#cx).race_drained(vec![#(#boxed_futures),*]).await
        },
    };

    quote! {
        {
            #call
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_race() {
        let input: proc_macro2::TokenStream = quote! { cx, { fut_a(), fut_b() } };
        let parsed: RaceInput = syn::parse2(input).unwrap();
        assert!(parsed.timeout.is_none());
        assert_eq!(parsed.branches.len(), 2);
        assert!(parsed.branches.iter().all(|b| b.name.is_none()));
    }

    #[test]
    fn test_parse_named_race() {
        let input: proc_macro2::TokenStream =
            quote! { cx, { "primary" => fut_a(), "replica" => fut_b() } };
        let parsed: RaceInput = syn::parse2(input).unwrap();
        assert_eq!(parsed.branches.len(), 2);
        assert!(parsed.branches.iter().all(|b| b.name.is_some()));
    }

    #[test]
    fn test_parse_timeout_race() {
        let input: proc_macro2::TokenStream =
            quote! { cx, timeout: std::time::Duration::from_secs(5), { fut_a(), fut_b() } };
        let parsed: RaceInput = syn::parse2(input).unwrap();
        assert!(parsed.timeout.is_some());
        assert_eq!(parsed.branches.len(), 2);
    }

    fn unnamed_branch(future: Expr) -> RaceBranch {
        RaceBranch { name: None, future }
    }

    fn named_branch(name: &str, future: Expr) -> RaceBranch {
        RaceBranch {
            name: Some(LitStr::new(name, proc_macro2::Span::call_site())),
            future,
        }
    }

    /// The drain guarantee (u1z5hn.6 "lie #2") is structural: the unnamed
    /// expansion must route through the drain-correct `race_drained` engine,
    /// never the drop-only `Cx::race`.
    #[test]
    fn unnamed_race_expands_to_drained_engine() {
        let cx: Expr = syn::parse_quote!(cx);
        let branches = vec![
            unnamed_branch(syn::parse_quote!(fut_a())),
            unnamed_branch(syn::parse_quote!(fut_b())),
        ];
        let tokens = generate_race(&cx, None, &branches).to_string();
        assert!(
            tokens.contains("race_drained"),
            "unnamed race! must use the drained engine, got: {tokens}"
        );
        assert!(
            !tokens.contains("race_named") && !tokens.contains("race_timeout"),
            "unnamed race! must not emit the named/timeout variants, got: {tokens}"
        );
    }

    /// A regression guard: the old drop-only `(cx).race(...)` /
    /// `(cx).race_named(...)` expansions must never reappear. We check that the
    /// only `race`-prefixed call tokens are the drained ones by asserting the
    /// expansion contains no bare `race` method call segment.
    #[test]
    fn race_expansions_never_emit_drop_only_calls() {
        let cx: Expr = syn::parse_quote!(cx);
        let timeout: Expr = syn::parse_quote!(dur);

        let unnamed = vec![
            unnamed_branch(syn::parse_quote!(a())),
            unnamed_branch(syn::parse_quote!(b())),
        ];
        let named = vec![
            named_branch("primary", syn::parse_quote!(a())),
            named_branch("replica", syn::parse_quote!(b())),
        ];

        let cases = [
            generate_race(&cx, None, &unnamed).to_string(),
            generate_race(&cx, None, &named).to_string(),
            generate_race(&cx, Some(&timeout), &unnamed).to_string(),
            generate_race(&cx, Some(&timeout), &named).to_string(),
        ];

        for tokens in cases {
            assert!(
                tokens.contains("race_drained"),
                "every race! expansion must route through race_drained, got: {tokens}"
            );
            // `. race (` would be the drop-only method call; `race_drained`
            // tokenizes as a single ident so it cannot match this.
            assert!(
                !tokens.replace("race_drained", "").contains("race"),
                "no drop-only race* call may survive, got: {tokens}"
            );
        }
    }

    #[test]
    fn named_race_expands_to_drained_named_engine() {
        let cx: Expr = syn::parse_quote!(cx);
        let branches = vec![
            named_branch("primary", syn::parse_quote!(fut_a())),
            named_branch("replica", syn::parse_quote!(fut_b())),
        ];
        let tokens = generate_race(&cx, None, &branches).to_string();
        assert!(
            tokens.contains("race_drained_named"),
            "named race! must use race_drained_named, got: {tokens}"
        );
    }

    #[test]
    fn timeout_race_expands_to_drained_timeout_engine() {
        let cx: Expr = syn::parse_quote!(cx);
        let timeout: Expr = syn::parse_quote!(std::time::Duration::from_secs(5));
        let unnamed = vec![
            unnamed_branch(syn::parse_quote!(fut_a())),
            unnamed_branch(syn::parse_quote!(fut_b())),
        ];
        let named = vec![
            named_branch("primary", syn::parse_quote!(fut_a())),
            named_branch("replica", syn::parse_quote!(fut_b())),
        ];
        assert!(
            generate_race(&cx, Some(&timeout), &unnamed)
                .to_string()
                .contains("race_drained_timeout"),
            "timeout race! must use race_drained_timeout"
        );
        assert!(
            generate_race(&cx, Some(&timeout), &named)
                .to_string()
                .contains("race_drained_timeout_named"),
            "named timeout race! must use race_drained_timeout_named"
        );
    }
}
