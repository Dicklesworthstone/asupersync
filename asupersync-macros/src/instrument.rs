//! Implementation of the `#[instrument]` compatibility attribute.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use std::collections::BTreeSet;
use syn::ext::IdentExt;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{
    Block, Error, FnArg, Ident, ImplItemFn, ItemFn, LitStr, Pat, Result, Signature, Token,
    parse_macro_input,
};

pub fn instrument_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as InstrumentArgs);
    let item_clone = item.clone();

    if let Ok(function) = syn::parse::<ItemFn>(item) {
        return match expand_item_fn(function, &args) {
            Ok(tokens) => tokens.into(),
            Err(err) => err.to_compile_error().into(),
        };
    }

    if let Ok(method) = syn::parse::<ImplItemFn>(item_clone) {
        return match expand_impl_item_fn(method, &args) {
            Ok(tokens) => tokens.into(),
            Err(err) => err.to_compile_error().into(),
        };
    }

    Error::new(
        proc_macro2::Span::call_site(),
        "#[instrument] supports free functions and impl methods",
    )
    .to_compile_error()
    .into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstrumentLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Default for InstrumentLevel {
    fn default() -> Self {
        Self::Info
    }
}

impl InstrumentLevel {
    fn parse(input: ParseStream) -> Result<Self> {
        let raw = if input.peek(LitStr) {
            input.parse::<LitStr>()?.value()
        } else {
            input.parse::<Ident>()?.to_string()
        };

        match raw.to_ascii_lowercase().as_str() {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(Error::new(
                proc_macro2::Span::call_site(),
                "instrument level must be one of trace, debug, info, warn, or error",
            )),
        }
    }

    fn as_tokens(self) -> TokenStream2 {
        match self {
            Self::Trace => quote!(::asupersync::tracing_compat::Level::TRACE),
            Self::Debug => quote!(::asupersync::tracing_compat::Level::DEBUG),
            Self::Info => quote!(::asupersync::tracing_compat::Level::INFO),
            Self::Warn => quote!(::asupersync::tracing_compat::Level::WARN),
            Self::Error => quote!(::asupersync::tracing_compat::Level::ERROR),
        }
    }
}

#[derive(Default)]
struct InstrumentArgs {
    name: Option<LitStr>,
    level: InstrumentLevel,
    skip: BTreeSet<String>,
}

impl Parse for InstrumentArgs {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut args = Self::default();

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            match key.to_string().as_str() {
                "skip" => {
                    let content;
                    syn::parenthesized!(content in input);
                    while !content.is_empty() {
                        let ident = content.call(Ident::parse_any)?;
                        args.skip.insert(ident.to_string());
                        if content.is_empty() {
                            break;
                        }
                        content.parse::<Token![,]>()?;
                    }
                }
                "name" => {
                    input.parse::<Token![=]>()?;
                    args.name = Some(input.parse()?);
                }
                "level" => {
                    input.parse::<Token![=]>()?;
                    args.level = InstrumentLevel::parse(input)?;
                }
                _ => {
                    return Err(Error::new(
                        key.span(),
                        "unsupported instrument argument; expected name, level, or skip",
                    ));
                }
            }

            if input.is_empty() {
                break;
            }
            input.parse::<Token![,]>()?;
        }

        Ok(args)
    }
}

fn expand_item_fn(function: ItemFn, args: &InstrumentArgs) -> Result<TokenStream2> {
    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = function;
    let block = build_instrumented_block(&sig, &block, args)?;

    Ok(quote! {
        #(#attrs)*
        #vis #sig #block
    })
}

fn expand_impl_item_fn(method: ImplItemFn, args: &InstrumentArgs) -> Result<TokenStream2> {
    let ImplItemFn {
        attrs,
        vis,
        defaultness,
        sig,
        block,
    } = method;
    let block = build_instrumented_block(&sig, &block, args)?;

    Ok(quote! {
        #(#attrs)*
        #vis #defaultness #sig #block
    })
}

fn build_instrumented_block(
    sig: &Signature,
    block: &Block,
    args: &InstrumentArgs,
) -> Result<TokenStream2> {
    let span_name = args
        .name
        .clone()
        .unwrap_or_else(|| LitStr::new(&sig.ident.to_string(), sig.ident.span()));
    let level = args.level.as_tokens();
    let fields = collect_fields(sig, args)?;
    let span = if fields.is_empty() {
        quote!(::asupersync::tracing_compat::span!(#level, #span_name))
    } else {
        quote!(::asupersync::tracing_compat::span!(#level, #span_name, #(#fields),*))
    };

    if sig.asyncness.is_some() {
        Ok(quote!({
            let __asupersync_span = #span;
            {
                use ::asupersync::tracing_compat::Instrument as _;
                (async move #block)
                    .instrument(__asupersync_span)
                    .await
            }
        }))
    } else {
        Ok(quote!({
            let __asupersync_span = #span;
            let __asupersync_guard = __asupersync_span.enter();
            #block
        }))
    }
}

fn collect_fields(sig: &Signature, args: &InstrumentArgs) -> Result<Vec<TokenStream2>> {
    let mut fields = Vec::new();

    for input in &sig.inputs {
        match input {
            FnArg::Receiver(_) => {
                if !args.skip.contains("self") {
                    fields.push(quote!(self = ?self));
                }
            }
            FnArg::Typed(pat_type) => {
                let Pat::Ident(pat_ident) = pat_type.pat.as_ref() else {
                    return Err(Error::new(
                        pat_type.pat.span(),
                        "#[instrument] only supports identifier parameters; use skip(...) for complex patterns",
                    ));
                };
                let ident = &pat_ident.ident;
                if args.skip.contains(&ident.to_string()) {
                    continue;
                }
                fields.push(quote!(#ident = ?#ident));
            }
        }
    }

    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn parses_empty_args() {
        let args: InstrumentArgs = syn::parse_str("").expect("empty args should parse");
        assert!(args.name.is_none());
        assert_eq!(args.level, InstrumentLevel::Info);
        assert!(args.skip.is_empty());
    }

    #[test]
    fn parses_name_level_and_skip() {
        let args: InstrumentArgs =
            syn::parse_str("name = \"worker\", level = \"debug\", skip(self, secret)")
                .expect("args should parse");
        assert_eq!(args.name.expect("name").value(), "worker");
        assert_eq!(args.level, InstrumentLevel::Debug);
        assert!(args.skip.contains("self"));
        assert!(args.skip.contains("secret"));
    }

    #[test]
    fn builds_fields_for_receiver_and_args() {
        let sig: Signature = parse_quote!(fn work(&self, task_id: u64, label: &str));
        let args: InstrumentArgs = syn::parse_str("skip(label)").expect("skip args should parse");

        let fields = collect_fields(&sig, &args).expect("fields should build");
        let rendered: Vec<String> = fields.iter().map(ToString::to_string).collect();
        assert_eq!(rendered, vec!["self = ? self", "task_id = ? task_id"]);
    }

    #[test]
    fn rejects_complex_patterns() {
        let sig: Signature = parse_quote!(fn work((left, right): (u8, u8)));
        let err = collect_fields(&sig, &InstrumentArgs::default()).expect_err("must reject");
        assert!(err.to_string().contains("identifier parameters"));
    }

    #[test]
    fn expands_async_function_to_instrumented_future() {
        let function: ItemFn = parse_quote!(
            async fn work(task_id: u64) -> u64 {
                task_id + 1
            }
        );
        let tokens = expand_item_fn(function, &InstrumentArgs::default())
            .expect("expansion should succeed")
            .to_string();
        assert!(tokens.contains(". instrument"));
        assert!(tokens.contains("task_id = ? task_id"));
    }
}
