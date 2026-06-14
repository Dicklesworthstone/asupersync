//! Implementation of `#[asupersync::main]` and `#[asupersync::test]`.

use proc_macro::TokenStream;
use proc_macro2::{Literal, TokenStream as TokenStream2};
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{
    Error, FnArg, GenericArgument, Ident, ItemFn, LitInt, LitStr, Pat, PathArguments, Result,
    ReturnType, Token, Type, parse_macro_input,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum RuntimeFlavor {
    #[default]
    CurrentThread,
    MultiThread,
}

#[derive(Default)]
struct EntryArgs {
    flavor: RuntimeFlavor,
    workers: Option<usize>,
    poll_budget: Option<u32>,
}

impl Parse for EntryArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut args = Self::default();

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            match key.to_string().as_str() {
                "flavor" => {
                    input.parse::<Token![=]>()?;
                    args.flavor = parse_flavor(input)?;
                }
                "workers" => {
                    input.parse::<Token![=]>()?;
                    let value: LitInt = input.parse()?;
                    let workers = value.base10_parse::<usize>()?;
                    if workers == 0 {
                        return Err(Error::new(value.span(), "workers must be at least 1"));
                    }
                    args.workers = Some(workers);
                }
                "budget" => {
                    input.parse::<Token![=]>()?;
                    let value: LitInt = input.parse()?;
                    let poll_budget = value.base10_parse::<u32>()?;
                    if poll_budget == 0 {
                        return Err(Error::new(value.span(), "budget must be at least 1"));
                    }
                    args.poll_budget = Some(poll_budget);
                }
                _ => {
                    return Err(unsupported_entry_arg(&key));
                }
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else if !input.is_empty() {
                return Err(input.error("expected `,` between asupersync entry arguments"));
            }
        }

        Ok(args)
    }
}

pub fn main_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as EntryArgs);
    let input = parse_macro_input!(item as ItemFn);
    expand_entry(&args, input, EntryKind::Main)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

pub fn test_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as EntryArgs);
    let input = parse_macro_input!(item as ItemFn);
    expand_entry(&args, input, EntryKind::Test)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    Main,
    Test,
}

fn expand_entry(args: &EntryArgs, mut function: ItemFn, kind: EntryKind) -> Result<TokenStream2> {
    validate_entry_signature(&function, kind)?;
    let cx_ident = take_optional_cx_arg(&mut function)?;

    let ItemFn {
        attrs,
        vis,
        mut sig,
        block,
    } = function;
    sig.asyncness = None;

    let builder = builder_tokens(args);
    let cx_binding = cx_ident.map(|ident| {
        quote! {
            let __asupersync_entry_cx =
                ::asupersync::Cx::current().expect("asupersync entry macro installed a root Cx");
            let #ident = &__asupersync_entry_cx;
        }
    });
    let test_attr = (kind == EntryKind::Test).then(|| quote!(#[test]));

    Ok(quote! {
        #(#attrs)*
        #test_attr
        #vis #sig {
            let __asupersync_entry_runtime = #builder
                .build()
                .expect("asupersync entry macro failed to build the runtime");
            __asupersync_entry_runtime.block_on(async move {
                #cx_binding
                #block
            })
        }
    })
}

fn validate_entry_signature(function: &ItemFn, kind: EntryKind) -> Result<()> {
    let sig = &function.sig;
    if sig.asyncness.is_none() {
        return Err(Error::new(
            sig.fn_token.span(),
            "asupersync entry macros require an async function",
        ));
    }
    if sig.constness.is_some() {
        return Err(Error::new(
            sig.constness.span(),
            "asupersync entry macros do not support const functions",
        ));
    }
    if sig.unsafety.is_some() {
        return Err(Error::new(
            sig.unsafety.span(),
            "asupersync entry macros do not support unsafe entry functions",
        ));
    }
    if sig.abi.is_some() {
        return Err(Error::new(
            sig.abi.span(),
            "asupersync entry macros do not support extern entry functions",
        ));
    }
    if !sig.generics.params.is_empty() {
        return Err(Error::new(
            sig.generics.span(),
            "asupersync entry macros do not support generic entry functions",
        ));
    }
    validate_return_type(&sig.output)?;

    match kind {
        EntryKind::Main if sig.ident != "main" => Err(Error::new(
            sig.ident.span(),
            "#[asupersync::main] must be applied to `async fn main`",
        )),
        _ => Ok(()),
    }
}

fn validate_return_type(output: &ReturnType) -> Result<()> {
    match output {
        ReturnType::Default => Ok(()),
        ReturnType::Type(_, ty) if is_unit_result(ty) => Ok(()),
        ReturnType::Type(_, ty) => Err(Error::new(
            ty.span(),
            "asupersync entry macros support only `()` or `Result<(), E>` return types",
        )),
    }
}

fn is_unit_result(ty: &Type) -> bool {
    let Type::Path(path) = ty else {
        return false;
    };
    let Some(segment) = path.path.segments.last() else {
        return false;
    };
    if segment.ident != "Result" {
        return false;
    }
    let PathArguments::AngleBracketed(args) = &segment.arguments else {
        return false;
    };
    let Some(GenericArgument::Type(Type::Tuple(ok_type))) = args.args.first() else {
        return false;
    };
    ok_type.elems.is_empty()
}

fn take_optional_cx_arg(function: &mut ItemFn) -> Result<Option<Ident>> {
    match function.sig.inputs.len() {
        0 => Ok(None),
        1 => {
            let Some(arg) = function.sig.inputs.first() else {
                return Ok(None);
            };
            let FnArg::Typed(pat_type) = arg else {
                return Err(Error::new(
                    arg.span(),
                    "asupersync entry macros support at most one `cx: &Cx` argument",
                ));
            };
            let Pat::Ident(pat_ident) = pat_type.pat.as_ref() else {
                return Err(Error::new(
                    pat_type.pat.span(),
                    "asupersync entry macro Cx argument must use an identifier pattern",
                ));
            };
            if pat_ident.by_ref.is_some() || pat_ident.mutability.is_some() {
                return Err(Error::new(
                    pat_ident.span(),
                    "asupersync entry macro Cx argument must be written as `cx: &Cx`",
                ));
            }
            if !is_cx_reference(&pat_type.ty) {
                return Err(Error::new(
                    pat_type.ty.span(),
                    "asupersync entry macro argument must be `&Cx`",
                ));
            }
            let ident = pat_ident.ident.clone();
            function.sig.inputs.clear();
            Ok(Some(ident))
        }
        _ => Err(Error::new(
            function.sig.inputs.span(),
            "asupersync entry macros support only `()` or `(cx: &Cx)` parameters",
        )),
    }
}

fn is_cx_reference(ty: &Type) -> bool {
    let Type::Reference(reference) = ty else {
        return false;
    };
    if reference.mutability.is_some() {
        return false;
    }
    let Type::Path(path) = reference.elem.as_ref() else {
        return false;
    };
    path.path.segments.last().is_some_and(|segment| {
        segment.ident == "Cx" && matches!(segment.arguments, PathArguments::None)
    })
}

fn builder_tokens(args: &EntryArgs) -> TokenStream2 {
    let base = match args.flavor {
        RuntimeFlavor::CurrentThread => {
            quote!(::asupersync::runtime::RuntimeBuilder::current_thread())
        }
        RuntimeFlavor::MultiThread => quote!(::asupersync::runtime::RuntimeBuilder::multi_thread()),
    };
    let worker_step = args.workers.map(|workers| {
        let literal = Literal::usize_unsuffixed(workers);
        quote!(.worker_threads(#literal))
    });
    let budget_step = args.poll_budget.map(|budget| {
        let literal = Literal::u32_unsuffixed(budget);
        quote!(.poll_budget(#literal))
    });

    quote!(#base #worker_step #budget_step)
}

fn unsupported_entry_arg(key: &Ident) -> Error {
    let key_name = key.to_string();
    let suggestion = match key_name.as_str() {
        "flavour" | "runtime" => Some("flavor"),
        "worker" | "worker_threads" => Some("workers"),
        "poll_budget" | "task_budget" => Some("budget"),
        _ => None,
    };
    let mut message = format!(
        "unsupported asupersync entry argument `{key_name}`; valid arguments are `flavor`, `workers`, and `budget`"
    );
    if let Some(suggestion) = suggestion {
        message.push_str("; did you mean `");
        message.push_str(suggestion);
        message.push_str("`?");
    }
    Error::new(key.span(), message)
}

fn parse_flavor(input: ParseStream<'_>) -> Result<RuntimeFlavor> {
    let (value, span) = if input.peek(LitStr) {
        let lit: LitStr = input.parse()?;
        (lit.value(), lit.span())
    } else {
        let ident: Ident = input.parse()?;
        (ident.to_string(), ident.span())
    };

    match value.as_str() {
        "current_thread" => Ok(RuntimeFlavor::CurrentThread),
        "multi_thread" => Ok(RuntimeFlavor::MultiThread),
        _ => Err(Error::new(
            span,
            "flavor must be `current_thread` or `multi_thread`",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    #[test]
    fn main_expansion_builds_current_thread_runtime_by_default() {
        let input: ItemFn = syn::parse2(quote! {
            async fn main() {}
        })
        .unwrap();
        let tokens = expand_entry(&EntryArgs::default(), input, EntryKind::Main)
            .unwrap()
            .to_string();
        assert!(tokens.contains("RuntimeBuilder :: current_thread"));
        assert!(tokens.contains("block_on"));
    }

    #[test]
    fn test_expansion_installs_test_attribute_and_cx_binding() {
        let input: ItemFn = syn::parse2(quote! {
            async fn works(cx: &asupersync::Cx) {
                let _ = cx.task_id();
            }
        })
        .unwrap();
        let tokens = expand_entry(&EntryArgs::default(), input, EntryKind::Test)
            .unwrap()
            .to_string();
        assert!(tokens.contains("# [test]"));
        assert!(tokens.contains("Cx :: current"));
        assert!(!tokens.contains("async fn works"));
    }

    #[test]
    fn rejects_non_async_entry() {
        let input: ItemFn = syn::parse2(quote! {
            fn main() {}
        })
        .unwrap();
        let err = expand_entry(&EntryArgs::default(), input, EntryKind::Main).unwrap_err();
        assert!(
            err.to_string()
                .contains("entry macros require an async function")
        );
    }

    #[test]
    fn rejects_non_unit_non_result_return_type() {
        let input: ItemFn = syn::parse2(quote! {
            async fn main() -> u8 {
                1
            }
        })
        .unwrap();
        let err = expand_entry(&EntryArgs::default(), input, EntryKind::Main).unwrap_err();
        assert!(
            err.to_string()
                .contains("support only `()` or `Result<(), E>` return types")
        );
    }
}
