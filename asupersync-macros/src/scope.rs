//! Implementation of the `scope!` macro.
//!
//! The scope macro creates a structured concurrency region that owns all
//! spawned tasks and guarantees quiescence on exit.
//!
//! # Syntax
//!
//! ```ignore
//! // Basic usage
//! scope!(cx, {
//!     // body - `scope` variable is available here
//! })
//!
//! // With explicit name (for debugging)
//! scope!(cx, "http_handler", {
//!     // body
//! })
//!
//! // With budget
//! scope!(cx, budget: Budget::deadline(Duration::from_secs(5)), {
//!     // body
//! })
//!
//! // With name and budget
//! scope!(cx, "handler", budget: Budget::deadline(Duration::from_secs(5)), {
//!     // body
//! })
//! ```

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    spanned::Spanned,
    Expr, Ident, LitStr, Stmt, Token,
};

/// Optional name for the scope (for debugging/tracing).
#[derive(Clone)]
struct ScopeName(LitStr);

/// Optional budget specification.
#[derive(Clone)]
struct ScopeBudget(Expr);

/// Input to the scope! macro with all variants supported.
///
/// Supports:
/// - `scope!(cx, { body })`
/// - `scope!(cx, "name", { body })`
/// - `scope!(cx, budget: expr, { body })`
/// - `scope!(cx, "name", budget: expr, { body })`
struct ScopeInput {
    /// The capability context expression.
    cx: Expr,
    /// Optional scope name for debugging.
    name: Option<ScopeName>,
    /// Optional budget override.
    budget: Option<ScopeBudget>,
    /// The body block.
    body: syn::Block,
}

impl Parse for ScopeInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() || input.peek(syn::token::Brace) {
            return Err(syn::Error::new(input.span(), "scope! requires cx argument"));
        }

        // Parse the cx expression
        let cx: Expr = input.parse()?;

        // Expect comma after cx
        let _comma: Token![,] = input.parse().map_err(|_| {
            syn::Error::new(
                input.span(),
                "expected comma after context expression: scope!(cx, { body })",
            )
        })?;

        // Now we need to figure out what comes next:
        // - A string literal (name)
        // - `budget:` keyword
        // - A block (body)

        let mut name = None;
        let mut budget = None;

        // Check for optional name (string literal)
        if input.peek(LitStr) {
            let name_lit: LitStr = input.parse()?;
            name = Some(ScopeName(name_lit));

            let _comma: Token![,] = input.parse().map_err(|_| {
                syn::Error::new(
                    input.span(),
                    "expected comma after scope name: scope!(cx, \"name\", { body })",
                )
            })?;
        }

        // Check for optional budget specification
        if input.peek(Ident) {
            let ident: Ident = input.fork().parse()?;
            if ident == "budget" {
                // Consume the ident
                let _: Ident = input.parse()?;
                // Expect colon
                let _colon: Token![:] = input.parse().map_err(|_| {
                    syn::Error::new(input.span(), "expected colon after 'budget': budget: expr")
                })?;
                // Parse the budget expression
                let budget_expr: Expr = input.parse()?;
                budget = Some(ScopeBudget(budget_expr));

                let _comma: Token![,] = input.parse().map_err(|_| {
                    syn::Error::new(
                        input.span(),
                        "expected comma after budget: scope!(cx, budget: expr, { body })",
                    )
                })?;
            }
        }

        // Parse the body block
        let body: syn::Block = input.parse().map_err(|_| {
            syn::Error::new(
                input.span(),
                "expected block for scope body: scope!(cx, { body })",
            )
        })?;

        if let Some(span) = return_span(&body.stmts) {
            return Err(syn::Error::new(
                span,
                "scope! body must not use return; use break or early return pattern",
            ));
        }

        // Check for trailing content
        if !input.is_empty() {
            return Err(syn::Error::new(
                input.span(),
                "unexpected tokens after scope body",
            ));
        }

        Ok(Self {
            cx,
            name,
            budget,
            body,
        })
    }
}

/// Generates the scope implementation.
///
/// The macro expands to code that:
/// 1. Creates a scope from the context
/// 2. Makes the `scope` variable available in the body
/// 3. Wraps the body in an async block
/// 4. Awaits the result
///
/// # Phase 0 Implementation
///
/// In Phase 0 (single-threaded), the scope is created from the current
/// context's region. Full child region creation with quiescence guarantees
/// will be implemented in later phases.
pub fn scope_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ScopeInput);

    let expanded = generate_scope(&input);
    TokenStream::from(expanded)
}

fn generate_scope(input: &ScopeInput) -> TokenStream2 {
    let cx = &input.cx;
    let body = &input.body;

    // Generate scope creation based on whether budget is specified
    let scope_creation = match &input.budget {
        Some(ScopeBudget(budget_expr)) => {
            quote! {
                let __scope = __cx.scope_with_budget(#budget_expr);
            }
        }
        None => {
            quote! {
                let __scope = __cx.scope();
            }
        }
    };

    // Generate optional tracing for named scopes
    let trace_name = match &input.name {
        Some(ScopeName(name_lit)) => {
            quote! {
                // Named scope for tracing/debugging (wired in observability phase)
                let _ = #name_lit;
            }
        }
        None => {
            quote! {}
        }
    };

    // Extract just the statements from the body block
    let body_stmts = &body.stmts;

    quote! {
        {
            // scope! macro expansion
            let __cx = &#cx;
            #scope_creation
            #trace_name
            async move {
                let scope = __scope;
                #(#body_stmts)*
            }.await
        }
    }
}

fn return_span(stmts: &[Stmt]) -> Option<proc_macro2::Span> {
    for stmt in stmts {
        if let Stmt::Expr(expr, _) = stmt {
            if matches!(expr, Expr::Return(_)) {
                return Some(expr.span());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_scope() {
        let input: proc_macro2::TokenStream = quote! { cx, { let x = 1; } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        assert!(parsed.name.is_none());
        assert!(parsed.budget.is_none());
    }

    #[test]
    fn test_parse_named_scope() {
        let input: proc_macro2::TokenStream = quote! { cx, "my_scope", { let x = 1; } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        assert!(parsed.name.is_some());
        assert_eq!(parsed.name.unwrap().0.value(), "my_scope");
        assert!(parsed.budget.is_none());
    }

    #[test]
    fn test_parse_budget_scope() {
        let input: proc_macro2::TokenStream =
            quote! { cx, budget: Budget::deadline(Duration::from_secs(5)), { let x = 1; } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        assert!(parsed.name.is_none());
        assert!(parsed.budget.is_some());
    }

    #[test]
    fn test_parse_named_budget_scope() {
        let input: proc_macro2::TokenStream =
            quote! { cx, "handler", budget: Budget::INFINITE, { let x = 1; } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        assert!(parsed.name.is_some());
        assert_eq!(parsed.name.unwrap().0.value(), "handler");
        assert!(parsed.budget.is_some());
    }

    #[test]
    fn test_parse_complex_cx_expression() {
        let input: proc_macro2::TokenStream = quote! { &context.cx, { do_work(); } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        assert!(matches!(parsed.cx, Expr::Reference(_)));
    }

    #[test]
    fn test_parse_trailing_comma_in_body() {
        // Body can have trailing expressions
        let input: proc_macro2::TokenStream = quote! { cx, { 42 } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        assert!(parsed.name.is_none());
    }

    #[test]
    fn test_error_missing_body() {
        let input: proc_macro2::TokenStream = quote! { cx, "name" };
        let result: Result<ScopeInput, _> = syn::parse2(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_missing_comma() {
        let input: proc_macro2::TokenStream = quote! { cx { body } };
        let result: Result<ScopeInput, _> = syn::parse2(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_return_in_body() {
        let input: proc_macro2::TokenStream = quote! { cx, { return 1; } };
        let result: Result<ScopeInput, _> = syn::parse2(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_basic_scope() {
        let input: proc_macro2::TokenStream = quote! { cx, { 42 } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        let generated = generate_scope(&parsed);

        let generated_str = generated.to_string();
        assert!(generated_str.contains("__cx"));
        assert!(generated_str.contains("scope"));
        assert!(generated_str.contains("async move"));
        assert!(generated_str.contains("let scope = __scope"));
        // TokenStream renders `.await` with space as `. await`
        assert!(
            generated_str.contains(". await") || generated_str.contains(".await"),
            "Expected .await in: {generated_str}",
        );
    }

    #[test]
    fn test_generate_budget_scope() {
        let input: proc_macro2::TokenStream = quote! { cx, budget: Budget::INFINITE, { 42 } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        let generated = generate_scope(&parsed);

        let generated_str = generated.to_string();
        assert!(generated_str.contains("scope_with_budget"));
    }

    #[test]
    fn test_scope_variable_available() {
        // Test that the generated code makes `scope` available
        let input: proc_macro2::TokenStream = quote! { cx, {
            let _ = scope.region_id();
            42
        } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        let generated = generate_scope(&parsed);

        // The generated code should include the scope binding and body
        let generated_str = generated.to_string();
        assert!(generated_str.contains("let scope ="));
        assert!(generated_str.contains("scope . region_id"));
    }
}
