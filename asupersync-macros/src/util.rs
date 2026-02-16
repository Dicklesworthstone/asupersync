//! Shared utilities for asupersync proc macros.
//!
//! This module provides common parsing utilities, error handling helpers,
//! and shared code generation patterns used across all macros.
//!
//! Note: These utilities are provided for the full macro implementations in
//! dependent tasks (asupersync-86gw, asupersync-5tic, asupersync-mwff, asupersync-hcpl).
//! They are currently unused but will be utilized when the placeholder
//! implementations are replaced with full versions.

// Allow dead code for utility functions that are provided for future macro implementations
#![allow(dead_code)]

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, Result, parse::ParseStream};

/// Creates a compile error from a message and span.
pub fn compile_error(message: &str) -> TokenStream {
    let msg = message;
    quote! {
        compile_error!(#msg)
    }
}

/// Parses a comma-separated list of expressions.
pub fn parse_comma_separated<T>(
    input: ParseStream,
    parse_fn: impl Fn(ParseStream) -> Result<T>,
) -> Result<Vec<T>> {
    let mut items = Vec::new();

    while !input.is_empty() {
        items.push(parse_fn(input)?);

        if !input.is_empty() {
            let _comma: syn::Token![,] = input
                .parse()
                .map_err(|_| Error::new(input.span(), "expected comma between arguments"))?;

            // Allow trailing comma
            if input.is_empty() {
                break;
            }
        }
    }

    Ok(items)
}

/// Generates a unique identifier for internal use.
pub fn unique_ident(prefix: &str, index: usize) -> syn::Ident {
    syn::Ident::new(
        &format!("__{prefix}_{index}"),
        proc_macro2::Span::call_site(),
    )
}

/// Wraps an expression to ensure it's evaluated only once.
pub fn wrap_once_cell(expr: &syn::Expr, ident: &syn::Ident) -> TokenStream {
    quote! {
        let #ident = #expr;
    }
}
