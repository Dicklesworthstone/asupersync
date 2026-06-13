use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{
    Attribute, Error, FnArg, Ident, ItemFn, LitInt, Pat, PatIdent, Result, Token, Type,
    parse_macro_input,
};

#[derive(Debug, Clone, Copy)]
struct LabTestArgs {
    seed_start: u64,
    seed_end: u64,
    chaos: bool,
}

#[derive(Debug, Clone, Copy)]
struct ExploreSeedsArgs {
    base_seed: u64,
    count: usize,
    worker_count: usize,
    max_steps: u64,
    chaos: bool,
}

impl Default for LabTestArgs {
    fn default() -> Self {
        Self {
            seed_start: 0,
            seed_end: 1,
            chaos: false,
        }
    }
}

impl Default for ExploreSeedsArgs {
    fn default() -> Self {
        Self {
            base_seed: 0,
            count: 16,
            worker_count: 1,
            max_steps: 100_000,
            chaos: false,
        }
    }
}

impl Parse for LabTestArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut args = Self::default();
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            match key.to_string().as_str() {
                "chaos" => args.chaos = true,
                "seeds" => {
                    input.parse::<Token![=]>()?;
                    let start: LitInt = input.parse()?;
                    if input.peek(Token![..=]) {
                        return Err(input.error(
                            "lab_test seeds expects an exclusive `start..end` range, not `..=`",
                        ));
                    }
                    input.parse::<Token![..]>()?;
                    let end: LitInt = input.parse()?;
                    args.seed_start = start.base10_parse()?;
                    args.seed_end = end.base10_parse()?;
                    if args.seed_start >= args.seed_end {
                        return Err(Error::new(
                            start.span(),
                            "lab_test seeds range must contain at least one seed",
                        ));
                    }
                }
                other => {
                    return Err(Error::new(
                        key.span(),
                        format!("unknown lab_test argument `{other}`"),
                    ));
                }
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else if !input.is_empty() {
                return Err(input.error("expected `,` between lab_test arguments"));
            }
        }
        Ok(args)
    }
}

impl Parse for ExploreSeedsArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut args = Self::default();
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            match key.to_string().as_str() {
                "chaos" => args.chaos = true,
                "base" | "base_seed" => {
                    input.parse::<Token![=]>()?;
                    let value: LitInt = input.parse()?;
                    args.base_seed = value.base10_parse()?;
                }
                "count" => {
                    input.parse::<Token![=]>()?;
                    let value: LitInt = input.parse()?;
                    args.count = value.base10_parse()?;
                    if args.count == 0 {
                        return Err(Error::new(
                            value.span(),
                            "explore_seeds count must be at least 1",
                        ));
                    }
                }
                "workers" | "worker_count" => {
                    input.parse::<Token![=]>()?;
                    let value: LitInt = input.parse()?;
                    args.worker_count = value.base10_parse()?;
                    if args.worker_count == 0 {
                        return Err(Error::new(
                            value.span(),
                            "explore_seeds worker count must be at least 1",
                        ));
                    }
                }
                "max_steps" => {
                    input.parse::<Token![=]>()?;
                    let value: LitInt = input.parse()?;
                    args.max_steps = value.base10_parse()?;
                }
                "seeds" => {
                    input.parse::<Token![=]>()?;
                    let start: LitInt = input.parse()?;
                    if input.peek(Token![..=]) {
                        return Err(input.error(
                            "explore_seeds seeds expects an exclusive `start..end` range, not `..=`",
                        ));
                    }
                    input.parse::<Token![..]>()?;
                    let end: LitInt = input.parse()?;
                    let seed_start = start.base10_parse()?;
                    let seed_end: u64 = end.base10_parse()?;
                    if seed_start >= seed_end {
                        return Err(Error::new(
                            start.span(),
                            "explore_seeds seeds range must contain at least one seed",
                        ));
                    }
                    let span = end.span();
                    args.base_seed = seed_start;
                    args.count = usize::try_from(seed_end - seed_start)
                        .map_err(|_| Error::new(span, "explore_seeds seeds range is too large"))?;
                }
                other => {
                    return Err(Error::new(
                        key.span(),
                        format!("unknown explore_seeds argument `{other}`"),
                    ));
                }
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else if !input.is_empty() {
                return Err(input.error("expected `,` between explore_seeds arguments"));
            }
        }
        Ok(args)
    }
}

enum LabSignature {
    Runtime { arg: Ident },
    AsyncCx { arg: Ident },
}

pub fn lab_test_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as LabTestArgs);
    let input = parse_macro_input!(item as ItemFn);
    expand_lab_test(args, input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

pub fn explore_seeds_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as ExploreSeedsArgs);
    let input = parse_macro_input!(item as ItemFn);
    expand_explore_seeds(args, input)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

fn expand_lab_test(args: LabTestArgs, mut item: ItemFn) -> Result<proc_macro2::TokenStream> {
    if !item.sig.generics.params.is_empty() || item.sig.generics.where_clause.is_some() {
        return Err(Error::new_spanned(
            &item.sig.generics,
            "lab_test functions cannot be generic",
        ));
    }
    if item.sig.variadic.is_some() {
        return Err(Error::new_spanned(
            &item.sig,
            "lab_test functions cannot be variadic",
        ));
    }

    let signature = classify_signature(&item)?;
    let test_name = item.sig.ident.clone();
    let inner_name = format_ident!("__asupersync_lab_test_{test_name}");
    item.sig.ident = inner_name.clone();

    let wrapper_attrs = wrapper_attrs(&item.attrs);
    item.attrs.clear();

    let start = LitInt::new(&args.seed_start.to_string(), Span::call_site());
    let end = LitInt::new(&args.seed_end.to_string(), Span::call_site());
    let chaos = args.chaos;
    let test_name_text = test_name.to_string();
    let runner = lab_runner_tokens(signature, &inner_name);
    let support_fns = lab_support_tokens();

    Ok(quote! {
        #(#wrapper_attrs)*
        #[test]
        fn #test_name() {
            ::asupersync::test_utils::init_test_logging();
            let __asupersync_test_name = concat!(module_path!(), "::", #test_name_text);
            let __asupersync_chaos = #chaos;

            for __asupersync_seed in #start..#end {
                let __asupersync_seed: u64 = __asupersync_seed;
                let __asupersync_phase = format!(
                    "lab_test_seed:{__asupersync_test_name}:{__asupersync_seed}"
                );
                ::asupersync::tracing_compat::info!(
                    phase = %__asupersync_phase,
                    test = __asupersync_test_name,
                    seed = __asupersync_seed,
                    chaos = __asupersync_chaos,
                    "lab_test seed start"
                );

                #runner
            }

            ::asupersync::tracing_compat::info!(
                kind = "lab_test_matrix",
                outcome = "ok",
                test = __asupersync_test_name,
                seed_start = #start,
                seed_end = #end,
                chaos = __asupersync_chaos,
                "lab_test matrix completed"
            );

            #support_fns
        }

        #item
    })
}

#[allow(clippy::too_many_lines)]
fn expand_explore_seeds(
    args: ExploreSeedsArgs,
    mut item: ItemFn,
) -> Result<proc_macro2::TokenStream> {
    if !item.sig.generics.params.is_empty() || item.sig.generics.where_clause.is_some() {
        return Err(Error::new_spanned(
            &item.sig.generics,
            "explore_seeds functions cannot be generic",
        ));
    }
    if item.sig.variadic.is_some() {
        return Err(Error::new_spanned(
            &item.sig,
            "explore_seeds functions cannot be variadic",
        ));
    }

    let arg = classify_explore_seeds_signature(&item)?;
    let test_name = item.sig.ident.clone();
    let inner_name = format_ident!("__asupersync_explore_seeds_{test_name}");
    item.sig.ident = inner_name.clone();

    let wrapper_attrs = wrapper_attrs(&item.attrs);
    item.attrs.clear();

    let base_seed = LitInt::new(&format!("{}u64", args.base_seed), Span::call_site());
    let count = LitInt::new(&format!("{}usize", args.count), Span::call_site());
    let worker_count = LitInt::new(&format!("{}usize", args.worker_count), Span::call_site());
    let max_steps = LitInt::new(&format!("{}u64", args.max_steps), Span::call_site());
    let chaos = args.chaos;
    let test_name_text = test_name.to_string();
    let support_fns = explore_seeds_support_tokens();

    Ok(quote! {
        #(#wrapper_attrs)*
        #[test]
        fn #test_name() {
            ::asupersync::test_utils::init_test_logging();
            let __asupersync_test_name = concat!(module_path!(), "::", #test_name_text);
            let __asupersync_base_seed: u64 = #base_seed;
            let __asupersync_count: usize = #count;
            let __asupersync_worker_count: usize = #worker_count;
            let __asupersync_max_steps: u64 = #max_steps;
            let __asupersync_chaos: bool = #chaos;
            let mut __asupersync_class_counts =
                ::std::collections::BTreeMap::<u64, usize>::new();
            let mut __asupersync_certificates =
                ::std::collections::BTreeMap::<u64, (u64, u64)>::new();
            let mut __asupersync_failures = ::std::vec::Vec::<String>::new();
            let mut __asupersync_divergences = ::std::vec::Vec::<String>::new();
            let mut __asupersync_total_runs: usize = 0;
            let mut __asupersync_new_classes: usize = 0;
            let mut __asupersync_total_races: usize = 0;

            for __asupersync_idx in 0..__asupersync_count {
                let __asupersync_seed =
                    __asupersync_base_seed.wrapping_add(__asupersync_idx as u64);
                let mut #arg = ::asupersync::lab::LabRuntime::new(
                    __asupersync_explore_config(
                        __asupersync_seed,
                        __asupersync_worker_count,
                        __asupersync_max_steps,
                        __asupersync_chaos,
                    )
                );

                let __asupersync_body_result = std::panic::catch_unwind(
                    std::panic::AssertUnwindSafe(|| {
                        #inner_name(&mut #arg);
                    })
                );

                let __asupersync_report = if __asupersync_body_result.is_ok() {
                    #arg.run_until_quiescent_with_report()
                } else {
                    #arg.report()
                };
                let __asupersync_trace_events = #arg.trace().snapshot();
                let __asupersync_fingerprint = if __asupersync_trace_events.is_empty() {
                    __asupersync_seed
                } else {
                    ::asupersync::trace::trace_fingerprint(&__asupersync_trace_events)
                };
                __asupersync_total_races += if __asupersync_trace_events.is_empty() {
                    0
                } else {
                    ::asupersync::trace::detect_races(&__asupersync_trace_events).race_count()
                };
                let __asupersync_class_run_count = __asupersync_class_counts
                    .entry(__asupersync_fingerprint)
                    .or_insert(0);
                if *__asupersync_class_run_count == 0 {
                    __asupersync_new_classes += 1;
                }
                *__asupersync_class_run_count += 1;
                __asupersync_total_runs += 1;

                let __asupersync_certificate_hash = #arg.certificate().hash();
                if let Some((__asupersync_first_seed, __asupersync_first_hash)) =
                    __asupersync_certificates.get(&__asupersync_fingerprint)
                {
                    if *__asupersync_first_hash != __asupersync_certificate_hash {
                        __asupersync_divergences.push(format!(
                            "fingerprint {} diverged between seeds {} (certificate {}) \
                             and {} (certificate {})",
                            __asupersync_fingerprint,
                            __asupersync_first_seed,
                            __asupersync_first_hash,
                            __asupersync_seed,
                            __asupersync_certificate_hash,
                        ));
                    }
                } else {
                    __asupersync_certificates.insert(
                        __asupersync_fingerprint,
                        (__asupersync_seed, __asupersync_certificate_hash),
                    );
                }

                if let Err(__asupersync_payload) = __asupersync_body_result {
                    let __asupersync_cause =
                        __asupersync_panic_cause(__asupersync_payload.as_ref());
                    let __asupersync_artifact = #arg.write_auto_crashpack_for_panic(
                        __asupersync_test_name,
                        &__asupersync_report,
                        &__asupersync_cause,
                    );
                    __asupersync_failures.push(__asupersync_explore_seed_failure(
                        __asupersync_test_name,
                        __asupersync_seed,
                        &format!("panic: {__asupersync_cause}"),
                        __asupersync_artifact,
                    ));
                    continue;
                }

                if !__asupersync_report.lab_test_passed() {
                    let __asupersync_cause = format!(
                        "quiescent={}; oracle_passed={}; invariant_violations={:?}; \
                         trace_fingerprint={}",
                        __asupersync_report.quiescent,
                        __asupersync_report.oracle_report.all_passed(),
                        __asupersync_report.invariant_violations,
                        __asupersync_report.trace_fingerprint
                    );
                    let __asupersync_artifact =
                        #arg.write_auto_crashpack_for_report(
                            __asupersync_test_name,
                            &__asupersync_report,
                        );
                    __asupersync_failures.push(__asupersync_explore_seed_failure(
                        __asupersync_test_name,
                        __asupersync_seed,
                        &__asupersync_cause,
                        __asupersync_artifact,
                    ));
                }
            }

            if !__asupersync_failures.is_empty() || !__asupersync_divergences.is_empty() {
                panic!(
                    "{}",
                    __asupersync_explore_failure_message(
                        __asupersync_test_name,
                        __asupersync_total_runs,
                        __asupersync_new_classes,
                        __asupersync_total_races,
                        &__asupersync_class_counts,
                        &__asupersync_failures,
                        &__asupersync_divergences,
                    )
                );
            }

            #support_fns
        }

        #item
    })
}

fn lab_runner_tokens(signature: LabSignature, inner_name: &Ident) -> proc_macro2::TokenStream {
    match signature {
        LabSignature::Runtime { arg } => quote! {
            let mut #arg = ::asupersync::lab::LabRuntime::new(
                __asupersync_lab_config(__asupersync_seed, __asupersync_chaos)
            );
            let __asupersync_body_result = std::panic::catch_unwind(
                std::panic::AssertUnwindSafe(|| {
                    #inner_name(&mut #arg);
                })
            );
            if let Err(__asupersync_payload) = __asupersync_body_result {
                let __asupersync_report = #arg.report();
                let __asupersync_cause =
                    __asupersync_panic_cause(__asupersync_payload.as_ref());
                let __asupersync_artifact = #arg.write_auto_crashpack_for_panic(
                    __asupersync_test_name,
                    &__asupersync_report,
                    &__asupersync_cause,
                );
                panic!(
                    "{}",
                    __asupersync_lab_failure_message(
                        __asupersync_test_name,
                        __asupersync_seed,
                        &__asupersync_cause,
                        __asupersync_artifact,
                    )
                );
            }

            let __asupersync_report = #arg.run_until_quiescent_with_report();
            __asupersync_assert_lab_report(
                &#arg,
                &__asupersync_report,
                __asupersync_seed,
                __asupersync_test_name,
            );
        },
        LabSignature::AsyncCx { arg } => quote! {
            let (_, __asupersync_report) =
                ::asupersync::lab::run_async_lab_test_with_config(
                    __asupersync_lab_config(__asupersync_seed, __asupersync_chaos),
                    __asupersync_test_name,
                    |#arg| async move {
                        #inner_name(&#arg).await
                    },
            );
            let _ = __asupersync_report;
        },
    }
}

fn explore_seeds_support_tokens() -> proc_macro2::TokenStream {
    quote! {
        fn __asupersync_explore_config(
            seed: u64,
            worker_count: usize,
            max_steps: u64,
            chaos: bool,
        ) -> ::asupersync::lab::LabConfig {
            let config = ::asupersync::lab::LabConfig::new(seed)
                .worker_count(worker_count)
                .max_steps(max_steps)
                .with_default_replay_recording();
            if chaos {
                config.with_light_chaos()
            } else {
                config
            }
        }

        fn __asupersync_explore_seed_failure(
            test_name: &str,
            seed: u64,
            cause: &str,
            artifact: Result<
                Option<::asupersync::lab::LabAutoCrashpack>,
                ::asupersync::lab::LabAutoCrashpackError,
            >,
        ) -> String {
            let mut message = format!(
                "seed {seed}; rerun: ASUPERSYNC_LAB_TEST_SEED={seed} \
                 cargo test {test_name} -- --nocapture; cause: {cause}"
            );
            match artifact {
                Ok(Some(artifact)) => {
                    message.push_str(&format!(
                        "\n  crashpack: {}\n  replay: {}",
                        artifact.path,
                        artifact.replay.command_line,
                    ));
                }
                Ok(None) => {}
                Err(error) => {
                    message.push_str(&format!("\n  crashpack_error: {error}"));
                }
            }
            message
        }

        fn __asupersync_explore_failure_message(
            test_name: &str,
            total_runs: usize,
            new_classes: usize,
            total_races: usize,
            class_counts: &::std::collections::BTreeMap<u64, usize>,
            failures: &[String],
            divergences: &[String],
        ) -> String {
            let mut message = format!(
                "explore_seeds failed for {test_name}\ncoverage: total_runs={total_runs}; \
                 unique_classes={}; new_class_discoveries={new_classes}; \
                 races_found={total_races}; class_run_counts={:?}",
                class_counts.len(),
                class_counts,
            );
            if !failures.is_empty() {
                message.push_str("\nfailures:");
                for failure in failures {
                    message.push_str("\n- ");
                    message.push_str(failure);
                }
            }
            if !divergences.is_empty() {
                message.push_str("\ncertificate_divergences:");
                for divergence in divergences {
                    message.push_str("\n- ");
                    message.push_str(divergence);
                }
            }
            message
        }

        fn __asupersync_panic_cause(
            payload: &(dyn std::any::Any + Send),
        ) -> String {
            payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string())
        }
    }
}

fn lab_support_tokens() -> proc_macro2::TokenStream {
    quote! {
        fn __asupersync_lab_config(
            seed: u64,
            chaos: bool,
        ) -> ::asupersync::lab::LabConfig {
            let config = ::asupersync::lab::LabConfig::new(seed);
            if chaos {
                config.with_light_chaos()
            } else {
                config
            }
        }

        fn __asupersync_assert_lab_report(
            lab: &::asupersync::lab::LabRuntime,
            report: &::asupersync::lab::LabRunReport,
            seed: u64,
            test_name: &str,
        ) {
            if report.lab_test_passed() {
                return;
            }

            let __asupersync_cause = format!(
                "quiescent={}; oracle_passed={}; invariant_violations={:?}; \
                 trace_fingerprint={}",
                report.quiescent,
                report.oracle_report.all_passed(),
                report.invariant_violations,
                report.trace_fingerprint
            );
            let __asupersync_artifact =
                lab.write_auto_crashpack_for_report(test_name, report);
            panic!(
                "{}",
                __asupersync_lab_failure_message(
                    test_name,
                    seed,
                    &__asupersync_cause,
                    __asupersync_artifact,
                )
            );
        }

        fn __asupersync_panic_cause(
            payload: &(dyn std::any::Any + Send),
        ) -> String {
            payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".to_string())
        }

        fn __asupersync_lab_failure_message(
            test_name: &str,
            seed: u64,
            cause: &str,
            artifact: Result<
                Option<::asupersync::lab::LabAutoCrashpack>,
                ::asupersync::lab::LabAutoCrashpackError,
            >,
        ) -> String {
            let mut message = format!(
                "lab_test failed for {test_name} seed {seed}; rerun: \
                 ASUPERSYNC_LAB_TEST_SEED={seed} cargo test {test_name} -- --nocapture; \
                 cause: {cause}"
            );
            match artifact {
                Ok(Some(artifact)) => {
                    message.push_str(&format!(
                        "\ncrashpack: {}\nreplay: {}",
                        artifact.path,
                        artifact.replay.command_line,
                    ));
                }
                Ok(None) => {}
                Err(error) => {
                    message.push_str(&format!("\ncrashpack_error: {error}"));
                }
            }
            message
        }
    }
}

fn classify_explore_seeds_signature(item: &ItemFn) -> Result<Ident> {
    if item.sig.inputs.len() != 1 {
        return Err(Error::new_spanned(
            &item.sig.inputs,
            "explore_seeds expects exactly one argument: `&mut LabRuntime`",
        ));
    }
    if item.sig.asyncness.is_some() {
        return Err(Error::new_spanned(
            item.sig.asyncness,
            "explore_seeds functions must be synchronous and take `&mut LabRuntime`",
        ));
    }

    let arg = match item.sig.inputs.first().expect("length checked") {
        FnArg::Typed(arg) => arg,
        FnArg::Receiver(receiver) => {
            return Err(Error::new_spanned(
                receiver,
                "explore_seeds cannot be applied to methods",
            ));
        }
    };
    let ident = match arg.pat.as_ref() {
        Pat::Ident(PatIdent { ident, .. }) => ident.clone(),
        other => {
            return Err(Error::new_spanned(
                other,
                "explore_seeds argument must be a simple identifier",
            ));
        }
    };

    if is_ref_to(&arg.ty, true, "LabRuntime") {
        Ok(ident)
    } else {
        Err(Error::new_spanned(
            &arg.ty,
            "explore_seeds functions must take `&mut LabRuntime`",
        ))
    }
}

fn wrapper_attrs(attrs: &[Attribute]) -> Vec<Attribute> {
    attrs
        .iter()
        .filter(|attr| !attr.path().is_ident("test"))
        .cloned()
        .collect()
}

fn classify_signature(item: &ItemFn) -> Result<LabSignature> {
    if item.sig.inputs.len() != 1 {
        return Err(Error::new_spanned(
            &item.sig.inputs,
            "lab_test expects exactly one argument: `&mut LabRuntime` or `&Cx`",
        ));
    }
    let arg = match item.sig.inputs.first().expect("length checked") {
        FnArg::Typed(arg) => arg,
        FnArg::Receiver(receiver) => {
            return Err(Error::new_spanned(
                receiver,
                "lab_test cannot be applied to methods",
            ));
        }
    };
    let ident = match arg.pat.as_ref() {
        Pat::Ident(PatIdent { ident, .. }) => ident.clone(),
        other => {
            return Err(Error::new_spanned(
                other,
                "lab_test argument must be a simple identifier",
            ));
        }
    };

    if item.sig.asyncness.is_some() {
        if is_ref_to(&arg.ty, false, "Cx") {
            Ok(LabSignature::AsyncCx { arg: ident })
        } else {
            Err(Error::new_spanned(
                &arg.ty,
                "async lab_test functions must take `&Cx`",
            ))
        }
    } else if is_ref_to(&arg.ty, true, "LabRuntime") {
        Ok(LabSignature::Runtime { arg: ident })
    } else {
        Err(Error::new_spanned(
            &arg.ty,
            "non-async lab_test functions must take `&mut LabRuntime`",
        ))
    }
}

fn is_ref_to(ty: &Type, mutable: bool, last_segment: &str) -> bool {
    let Type::Reference(reference) = ty else {
        return false;
    };
    if reference.mutability.is_some() != mutable {
        return false;
    }
    let Type::Path(path) = reference.elem.as_ref() else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == last_segment)
}

#[cfg(test)]
mod tests {
    use super::{ExploreSeedsArgs, LabTestArgs, expand_explore_seeds, expand_lab_test};
    use quote::quote;
    use syn::{ItemFn, parse_quote};

    #[test]
    fn empty_args_default_to_seed_zero_only() {
        let args: LabTestArgs = syn::parse_quote!();
        assert_eq!(args.seed_start, 0);
        assert_eq!(args.seed_end, 1);
        assert!(!args.chaos);
    }

    #[test]
    fn parses_seed_range_and_chaos() {
        let args: LabTestArgs = syn::parse_quote!(seeds = 2..5, chaos);
        assert_eq!(args.seed_start, 2);
        assert_eq!(args.seed_end, 5);
        assert!(args.chaos);
    }

    #[test]
    fn explore_seeds_defaults_to_sixteen_runs() {
        let args: ExploreSeedsArgs = syn::parse_quote!();
        assert_eq!(args.base_seed, 0);
        assert_eq!(args.count, 16);
        assert_eq!(args.worker_count, 1);
        assert_eq!(args.max_steps, 100_000);
        assert!(!args.chaos);
    }

    #[test]
    fn explore_seeds_parses_range_and_controls() {
        let args: ExploreSeedsArgs =
            syn::parse_quote!(seeds = 3..7, workers = 2, max_steps = 99, chaos);
        assert_eq!(args.base_seed, 3);
        assert_eq!(args.count, 4);
        assert_eq!(args.worker_count, 2);
        assert_eq!(args.max_steps, 99);
        assert!(args.chaos);
    }

    #[test]
    fn rejects_missing_argument() {
        let item: ItemFn = parse_quote! {
            fn no_args() {}
        };
        let error = expand_lab_test(LabTestArgs::default(), item).unwrap_err();
        assert!(error.to_string().contains("exactly one argument"));
    }

    #[test]
    fn expands_runtime_form() {
        let item: ItemFn = parse_quote! {
            fn runtime_form(lab: &mut ::asupersync::lab::LabRuntime) {
                let _ = lab.now();
            }
        };
        let expanded = expand_lab_test(LabTestArgs::default(), item).unwrap();
        let expanded = quote!(#expanded).to_string();
        assert!(expanded.contains("run_until_quiescent_with_report"));
    }

    #[test]
    fn expands_explore_seeds_form() {
        let item: ItemFn = parse_quote! {
            fn runtime_form(lab: &mut ::asupersync::lab::LabRuntime) {
                let _ = lab.now();
            }
        };
        let args: ExploreSeedsArgs = syn::parse_quote!(base = 4, count = 3, workers = 2);
        let expanded = expand_explore_seeds(args, item).unwrap();
        let expanded = quote!(#expanded).to_string();
        assert!(expanded.contains("trace_fingerprint"));
        assert!(expanded.contains("coverage"));
    }
}
