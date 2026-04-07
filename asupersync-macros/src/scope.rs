//! Implementation of the `scope!` macro.
//!
//! The scope macro creates a [`Scope`](asupersync::Scope) binding for the
//! current `Cx` region.
//!
//! It is an ergonomic helper, not a fresh child-region boundary. Child-region
//! ownership and quiescence still require explicit `Scope::region(...)`.
//!
//! # Syntax
//!
//! ```ignore
//! // Basic usage
//! scope!(cx, {
//!     // body - `scope` variable is available here
//! })
//!
//! // With explicit runtime state for nested spawn! calls
//! scope!(cx, state: &mut state, {
//!     let _child = spawn!(async { 42 });
//! })
//!
//! // With explicit name (for debugging)
//! scope!(cx, "http_handler", {
//!     // body
//! })
//!
//! // With budget
//! scope!(cx, budget: Budget::with_deadline_secs(5), {
//!     // body
//! })
//!
//! // With name and budget
//! scope!(cx, "handler", budget: Budget::with_deadline_secs(5), {
//!     // body
//! })
//!
//! // Options can be combined
//! scope!(cx, "handler", state: &mut state, budget: Budget::with_deadline_secs(5), {
//!     let _child = spawn!(async { 42 });
//! })
//! ```

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    Expr, Ident, LitStr, Stmt, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
    spanned::Spanned,
};

/// Optional name for the scope (for debugging/tracing).
#[derive(Clone)]
struct ScopeName(LitStr);

/// Optional budget specification.
#[derive(Clone)]
struct ScopeBudget(Expr);

/// Optional runtime state binding for nested `spawn!` calls.
#[derive(Clone)]
struct ScopeState(Expr);

/// Input to the scope! macro with all variants supported.
///
/// Supports:
/// - `scope!(cx, { body })`
/// - `scope!(cx, state: expr, { body })`
/// - `scope!(cx, "name", { body })`
/// - `scope!(cx, budget: expr, { body })`
/// - `scope!(cx, "name", state: expr, budget: expr, { body })`
struct ScopeInput {
    /// The capability context expression.
    cx: Expr,
    /// Optional scope name for debugging.
    name: Option<ScopeName>,
    /// Optional budget override.
    budget: Option<ScopeBudget>,
    /// Optional runtime state for nested spawn! calls.
    state: Option<ScopeState>,
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
        let mut state = None;

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

        loop {
            if !input.peek(Ident) {
                break;
            }

            let ident: Ident = input.fork().parse()?;
            if ident == "budget" {
                if budget.is_some() {
                    return Err(syn::Error::new(
                        ident.span(),
                        "duplicate budget: scope! accepts at most one budget: expr option",
                    ));
                }

                let _: Ident = input.parse()?;
                let _colon: Token![:] = input.parse().map_err(|_| {
                    syn::Error::new(input.span(), "expected colon after 'budget': budget: expr")
                })?;
                let budget_expr: Expr = input.parse()?;
                budget = Some(ScopeBudget(budget_expr));
            } else if ident == "state" {
                if state.is_some() {
                    return Err(syn::Error::new(
                        ident.span(),
                        "duplicate state: scope! accepts at most one state: expr option",
                    ));
                }

                let _: Ident = input.parse()?;
                let _colon: Token![:] = input.parse().map_err(|_| {
                    syn::Error::new(input.span(), "expected colon after 'state': state: expr")
                })?;
                let state_expr: Expr = input.parse()?;
                state = Some(ScopeState(state_expr));
            } else {
                break;
            }

            let _comma: Token![,] = input.parse().map_err(|_| {
                syn::Error::new(
                    input.span(),
                    "expected comma after scope option before body block",
                )
            })?;
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
            state,
            body,
        })
    }
}

/// Generates the scope implementation.
///
/// The macro expands to code that:
/// 1. Creates a `Scope` from the current `Cx`
/// 2. Makes the `scope` variable available in the body
/// 3. Optionally binds `__state` for nested `spawn!` calls
/// 4. Wraps the body in an async block
/// 5. Awaits the result
///
/// # Phase 0 Implementation
///
/// Today the scope is created from the current context's region. Full child
/// region creation with a new quiescence boundary is still an explicit
/// `Scope::region(...)` operation.
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

    let state_binding = match &input.state {
        Some(ScopeState(state_expr)) => {
            quote! {
                let __state = #state_expr;
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
            #state_binding
            async move {
                let scope = __scope;
                #(#body_stmts)*
            }.await
        }
    }
}

fn return_span(stmts: &[Stmt]) -> Option<proc_macro2::Span> {
    use syn::visit::Visit;

    struct ReturnVisitor {
        span: Option<proc_macro2::Span>,
    }

    impl<'ast> Visit<'ast> for ReturnVisitor {
        fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
            if self.span.is_none() {
                self.span = Some(node.span());
            }
            // Continue visiting in case there are other things,
            // but we only need the first one.
            syn::visit::visit_expr_return(self, node);
        }

        // We shouldn't look inside nested closures, async blocks, or nested functions
        // because a return inside them is perfectly valid and returns
        // from the closure/function, not the scope body!
        fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {
            // Do not traverse into closures
        }

        fn visit_expr_async(&mut self, _node: &'ast syn::ExprAsync) {
            // Do not traverse into nested async blocks
        }

        fn visit_item(&mut self, _node: &'ast syn::Item) {
            // Do not traverse into any nested items (functions, impls, modules, etc.)
            // as returns inside them are perfectly valid and do not return
            // from the scope body.
        }
    }

    let mut visitor = ReturnVisitor { span: None };
    for stmt in stmts {
        visitor.visit_stmt(stmt);
        if visitor.span.is_some() {
            break;
        }
    }
    visitor.span
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
            quote! { cx, budget: Budget::with_deadline_secs(5), { let x = 1; } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        assert!(parsed.name.is_none());
        assert!(parsed.budget.is_some());
    }

    #[test]
    fn test_parse_state_scope() {
        let input: proc_macro2::TokenStream = quote! { cx, state: &mut state, { let x = 1; } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        assert!(parsed.name.is_none());
        assert!(parsed.budget.is_none());
        assert!(parsed.state.is_some());
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
    fn test_parse_named_state_budget_scope() {
        let input: proc_macro2::TokenStream =
            quote! { cx, "handler", state: &mut state, budget: Budget::INFINITE, { let x = 1; } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        assert!(parsed.name.is_some());
        assert_eq!(parsed.name.unwrap().0.value(), "handler");
        assert!(parsed.budget.is_some());
        assert!(parsed.state.is_some());
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
    fn test_error_duplicate_state() {
        let input: proc_macro2::TokenStream =
            quote! { cx, state: &mut a, state: &mut b, { let x = 1; } };
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
    fn test_generate_scope_with_state_binding() {
        let input: proc_macro2::TokenStream = quote! { cx, state: &mut state, { 42 } };
        let parsed: ScopeInput = syn::parse2(input).unwrap();
        let generated = generate_scope(&parsed);

        let generated_str = generated.to_string();
        assert!(generated_str.contains("let __state ="));
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
