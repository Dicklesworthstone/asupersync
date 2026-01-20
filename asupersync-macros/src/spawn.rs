//! Implementation of the `spawn!` macro.
//!
//! The spawn macro creates a task owned by the enclosing region.
//! The task cannot orphan and will be cancelled when the region closes.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::Parse,
    parse_macro_input,
    punctuated::Punctuated,
    Error, Expr, Lit, LitStr, Token,
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
                    let name = take_str(&items[0]).expect("string literal checked");
                    (None, Some(name), items.remove(1))
                } else {
                    (Some(items.remove(0)), None, items.remove(0))
                }
            }
            3 => {
                let scope = items.remove(0);
                let name = take_str(&items[0]).ok_or_else(|| {
                    Error::new(
                        items[0].span(),
                        "spawn! name must be a string literal",
                    )
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
/// # Placeholder Implementation
///
/// This is a placeholder that will be fully implemented in `asupersync-5tic`.
/// Currently generates code that:
/// 1. Returns the future expression directly
///
/// The full implementation will:
/// - Call `scope.spawn()` with the future
/// - Return a `TaskHandle` for the spawned task
/// - Ensure proper ownership by the region
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
    let scope_expr: Expr = match scope {
        Some(expr) => expr.clone(),
        None => syn::parse_quote! { scope },
    };

    let spawn_call = if let Some(name_lit) = name {
        quote! {
            __scope.spawn_named(#name_lit, |cx| async move {
                let _ = &cx;
                (#future).await
            })
        }
    } else {
        quote! {
            __scope.spawn(|cx| async move {
                let _ = &cx;
                (#future).await
            })
        }
    };

    quote! {
        {
            let __scope = #scope_expr;
            #spawn_call
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
