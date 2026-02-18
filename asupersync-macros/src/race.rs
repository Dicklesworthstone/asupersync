//! Implementation of the `race!` macro.
//!
//! The race macro runs multiple futures concurrently and returns the result
//! of the first to complete. Losers are automatically cancelled and drained.

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
/// This expands to a `cx.race(...)`/`cx.race_named(...)` call (or timeout variants),
/// with each branch wrapped in an `async move` block.
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
                ::std::boxed::Box::pin(async move {
                    (#fut).await
                })
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
            (#cx).race_timeout_named(#timeout_expr, vec![#(#boxed_futures),*]).await
        },
        (Some(timeout_expr), false) => quote! {
            (#cx).race_timeout(#timeout_expr, vec![#(#boxed_futures),*]).await
        },
        (None, true) => quote! {
            (#cx).race_named(vec![#(#boxed_futures),*]).await
        },
        (None, false) => quote! {
            (#cx).race(vec![#(#boxed_futures),*]).await
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
}
