//! Implementation of the `session_protocol!` macro.
//!
//! Generates typestate-encoded session types from a protocol DSL,
//! producing paired channel constructors with compile-time protocol safety.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    braced,
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    Ident, Token, Type,
};

// ============================================================================
// AST
// ============================================================================

struct ProtocolDef {
    name: Ident,
    type_params: Vec<Ident>,
    obligation: ObligationSpec,
    messages: Vec<MessageDef>,
    body: SessionBody,
}

/// How the obligation kind is specified.
enum ObligationSpec {
    /// Fixed variant: `for SendPermit` → `ObligationKind::SendPermit`.
    Fixed(Ident),
    /// Parameterized: `(kind: ObligationKind)` → constructor takes `kind` param.
    Param(Ident, Box<Type>),
}

struct MessageDef {
    name: Ident,
    fields: Vec<FieldDef>,
}

struct FieldDef {
    name: Ident,
    ty: Type,
}

enum SessionBody {
    End,
    Continue,
    Send(Type, Box<Self>),
    Recv(Type, Box<Self>),
    Select(Box<Self>, Box<Self>),
    Offer(Box<Self>, Box<Self>),
    Loop(Box<Self>),
}

// ============================================================================
// Parser
// ============================================================================

impl Parse for ProtocolDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name: Ident = input.parse()?;

        let type_params = if input.peek(Token![<]) {
            let _: Token![<] = input.parse()?;
            let params: Punctuated<Ident, Token![,]> = Punctuated::parse_separated_nonempty(input)?;
            let _: Token![>] = input.parse()?;
            params.into_iter().collect()
        } else {
            Vec::new()
        };

        // Parse obligation spec: either `for Variant` or `(param: Type)`
        let obligation = if input.peek(Token![for]) {
            let _: Token![for] = input.parse()?;
            let variant: Ident = input.parse()?;
            ObligationSpec::Fixed(variant)
        } else if input.peek(syn::token::Paren) {
            let paren_content;
            syn::parenthesized!(paren_content in input);
            let param_name: Ident = paren_content.parse()?;
            let _: Token![:] = paren_content.parse()?;
            let param_type: Type = paren_content.parse()?;
            ObligationSpec::Param(param_name, Box::new(param_type))
        } else {
            return Err(syn::Error::new(
                input.span(),
                "expected `for ObligationKind` or `(param: Type)` after protocol name",
            ));
        };

        let content;
        braced!(content in input);

        let mut messages = Vec::new();
        while !content.is_empty() {
            if content.peek(Ident) {
                let fork = content.fork();
                if let Ok(ident) = fork.parse::<Ident>() {
                    if ident == "msg" {
                        let _: Ident = content.parse()?;
                        let msg = parse_message_def(&content)?;
                        messages.push(msg);
                        continue;
                    }
                }
            }
            break;
        }

        let body = parse_session_body(&content)?;

        validate_body(&body, false).map_err(|msg| syn::Error::new(name.span(), msg))?;

        Ok(Self {
            name,
            type_params,
            obligation,
            messages,
            body,
        })
    }
}

fn parse_message_def(input: ParseStream) -> syn::Result<MessageDef> {
    let name: Ident = input.parse()?;

    let fields = if input.peek(syn::token::Brace) {
        let fields_content;
        braced!(fields_content in input);
        let mut fields = Vec::new();
        while !fields_content.is_empty() {
            let fname: Ident = fields_content.parse()?;
            let _: Token![:] = fields_content.parse()?;
            let fty: Type = fields_content.parse()?;
            fields.push(FieldDef {
                name: fname,
                ty: fty,
            });
            if fields_content.peek(Token![,]) {
                let _: Token![,] = fields_content.parse()?;
            }
        }
        fields
    } else {
        Vec::new()
    };

    let _: Token![;] = input
        .parse()
        .map_err(|_| syn::Error::new(name.span(), "expected `;` after message definition"))?;

    Ok(MessageDef { name, fields })
}

fn parse_session_body(input: ParseStream) -> syn::Result<SessionBody> {
    if input.peek(Token![loop]) {
        let _: Token![loop] = input.parse()?;
        let content;
        braced!(content in input);
        let body = parse_session_body(&content)?;
        return Ok(SessionBody::Loop(Box::new(body)));
    }

    if input.peek(Token![continue]) {
        let _: Token![continue] = input.parse()?;
        return Ok(SessionBody::Continue);
    }

    let kw: Ident = input.parse().map_err(|_| {
        syn::Error::new(
            input.span(),
            "expected session action: send, recv, select, offer, end, loop, or continue",
        )
    })?;

    match kw.to_string().as_str() {
        "end" => Ok(SessionBody::End),
        "send" => {
            let ty: Type = input.parse()?;
            let _: Token![=>] = input
                .parse()
                .map_err(|_| syn::Error::new(kw.span(), "expected `=>` after send type"))?;
            let cont = parse_session_body(input)?;
            Ok(SessionBody::Send(ty, Box::new(cont)))
        }
        "recv" => {
            let ty: Type = input.parse()?;
            let _: Token![=>] = input
                .parse()
                .map_err(|_| syn::Error::new(kw.span(), "expected `=>` after recv type"))?;
            let cont = parse_session_body(input)?;
            Ok(SessionBody::Recv(ty, Box::new(cont)))
        }
        "select" => {
            let content;
            braced!(content in input);
            let left = parse_session_body(&content)?;
            let _: Token![,] = content.parse().map_err(|_| {
                syn::Error::new(kw.span(), "select requires two branches separated by `,`")
            })?;
            let right = parse_session_body(&content)?;
            if content.peek(Token![,]) {
                let _: Token![,] = content.parse()?;
            }
            Ok(SessionBody::Select(Box::new(left), Box::new(right)))
        }
        "offer" => {
            let content;
            braced!(content in input);
            let left = parse_session_body(&content)?;
            let _: Token![,] = content.parse().map_err(|_| {
                syn::Error::new(kw.span(), "offer requires two branches separated by `,`")
            })?;
            let right = parse_session_body(&content)?;
            if content.peek(Token![,]) {
                let _: Token![,] = content.parse()?;
            }
            Ok(SessionBody::Offer(Box::new(left), Box::new(right)))
        }
        other => Err(syn::Error::new(
            kw.span(),
            format!(
                "unknown session action `{other}`, expected: send, recv, select, offer, end, loop, continue"
            ),
        )),
    }
}

// ============================================================================
// Validation
// ============================================================================

fn validate_body(body: &SessionBody, in_loop: bool) -> Result<(), String> {
    match body {
        SessionBody::End => Ok(()),
        SessionBody::Continue => {
            if in_loop {
                Ok(())
            } else {
                Err("`continue` used outside of `loop` block".to_string())
            }
        }
        SessionBody::Send(_, cont) | SessionBody::Recv(_, cont) => validate_body(cont, in_loop),
        SessionBody::Select(a, b) | SessionBody::Offer(a, b) => {
            validate_body(a, in_loop)?;
            validate_body(b, in_loop)
        }
        SessionBody::Loop(inner) => {
            if in_loop {
                Err("nested `loop` blocks are not supported".to_string())
            } else {
                validate_body(inner, true)
            }
        }
    }
}

fn extract_loop_body(body: &SessionBody) -> Option<&SessionBody> {
    match body {
        SessionBody::Loop(inner) => Some(inner),
        SessionBody::Send(_, c) | SessionBody::Recv(_, c) => extract_loop_body(c),
        SessionBody::Select(a, b) | SessionBody::Offer(a, b) => {
            extract_loop_body(a).or_else(|| extract_loop_body(b))
        }
        SessionBody::End | SessionBody::Continue => None,
    }
}

// ============================================================================
// Type generation
// ============================================================================

/// Generate initiator's session type (direct encoding).
fn gen_init(body: &SessionBody, tp: &[Ident]) -> TokenStream2 {
    match body {
        SessionBody::End | SessionBody::Continue => quote! { End },
        SessionBody::Send(ty, c) => {
            let c = gen_init(c, tp);
            quote! { Send<#ty, #c> }
        }
        SessionBody::Recv(ty, c) => {
            let c = gen_init(c, tp);
            quote! { Recv<#ty, #c> }
        }
        SessionBody::Select(a, b) => {
            let a = gen_init(a, tp);
            let b = gen_init(b, tp);
            quote! { Select<#a, #b> }
        }
        SessionBody::Offer(a, b) => {
            let a = gen_init(a, tp);
            let b = gen_init(b, tp);
            quote! { Offer<#a, #b> }
        }
        SessionBody::Loop(_) => {
            if tp.is_empty() {
                quote! { InitiatorLoop }
            } else {
                quote! { InitiatorLoop<#(#tp),*> }
            }
        }
    }
}

/// Generate responder's session type (dual: Send↔Recv, Select↔Offer).
fn gen_resp(body: &SessionBody, tp: &[Ident]) -> TokenStream2 {
    match body {
        SessionBody::End | SessionBody::Continue => quote! { End },
        SessionBody::Send(ty, c) => {
            let c = gen_resp(c, tp);
            quote! { Recv<#ty, #c> }
        }
        SessionBody::Recv(ty, c) => {
            let c = gen_resp(c, tp);
            quote! { Send<#ty, #c> }
        }
        SessionBody::Select(a, b) => {
            let a = gen_resp(a, tp);
            let b = gen_resp(b, tp);
            quote! { Offer<#a, #b> }
        }
        SessionBody::Offer(a, b) => {
            let a = gen_resp(a, tp);
            let b = gen_resp(b, tp);
            quote! { Select<#a, #b> }
        }
        SessionBody::Loop(_) => {
            if tp.is_empty() {
                quote! { ResponderLoop }
            } else {
                quote! { ResponderLoop<#(#tp),*> }
            }
        }
    }
}

/// Generate loop body type for initiator.
fn gen_init_loop(body: &SessionBody) -> TokenStream2 {
    match body {
        SessionBody::End | SessionBody::Continue => quote! { End },
        SessionBody::Send(ty, c) => {
            let c = gen_init_loop(c);
            quote! { Send<#ty, #c> }
        }
        SessionBody::Recv(ty, c) => {
            let c = gen_init_loop(c);
            quote! { Recv<#ty, #c> }
        }
        SessionBody::Select(a, b) => {
            let a = gen_init_loop(a);
            let b = gen_init_loop(b);
            quote! { Select<#a, #b> }
        }
        SessionBody::Offer(a, b) => {
            let a = gen_init_loop(a);
            let b = gen_init_loop(b);
            quote! { Offer<#a, #b> }
        }
        SessionBody::Loop(_) => quote! { compile_error!("nested loop") },
    }
}

/// Generate loop body type for responder (dual).
fn gen_resp_loop(body: &SessionBody) -> TokenStream2 {
    match body {
        SessionBody::End | SessionBody::Continue => quote! { End },
        SessionBody::Send(ty, c) => {
            let c = gen_resp_loop(c);
            quote! { Recv<#ty, #c> }
        }
        SessionBody::Recv(ty, c) => {
            let c = gen_resp_loop(c);
            quote! { Send<#ty, #c> }
        }
        SessionBody::Select(a, b) => {
            let a = gen_resp_loop(a);
            let b = gen_resp_loop(b);
            quote! { Offer<#a, #b> }
        }
        SessionBody::Offer(a, b) => {
            let a = gen_resp_loop(a);
            let b = gen_resp_loop(b);
            quote! { Select<#a, #b> }
        }
        SessionBody::Loop(_) => quote! { compile_error!("nested loop") },
    }
}

// ============================================================================
// Module generation
// ============================================================================

fn generate_protocol(def: &ProtocolDef) -> TokenStream2 {
    let mod_name = &def.name;
    let tp = &def.type_params;

    let tp_clause = if tp.is_empty() {
        quote! {}
    } else {
        quote! { <#(#tp),*> }
    };

    // Obligation kind expression used in Chan::new_raw calls.
    let (ob_expr, ob_extra_param) = match &def.obligation {
        ObligationSpec::Fixed(variant) => (quote! { ObligationKind::#variant }, quote! {}),
        ObligationSpec::Param(name, ty) => (quote! { #name }, quote! { #name: #ty, }),
    };

    let msg_structs: Vec<TokenStream2> = def
        .messages
        .iter()
        .map(|msg| {
            let n = &msg.name;
            if msg.fields.is_empty() {
                quote! {
                    #[derive(Debug, Clone, Copy)]
                    pub struct #n;
                }
            } else {
                let fields: Vec<TokenStream2> = msg
                    .fields
                    .iter()
                    .map(|f| {
                        let fname = &f.name;
                        let fty = &f.ty;
                        quote! { pub #fname: #fty }
                    })
                    .collect();
                quote! {
                    #[derive(Debug, Clone)]
                    pub struct #n {
                        #(#fields,)*
                    }
                }
            }
        })
        .collect();

    let initiator_type = gen_init(&def.body, tp);
    let responder_type = gen_resp(&def.body, tp);

    let loop_code = extract_loop_body(&def.body).map_or_else(
        || quote! {},
        |loop_body| {
            let il = gen_init_loop(loop_body);
            let rl = gen_resp_loop(loop_body);

            quote! {
                /// One iteration of the protocol loop (initiator side).
                pub type InitiatorLoop #tp_clause = #il;

                /// One iteration of the protocol loop (responder side).
                pub type ResponderLoop #tp_clause = #rl;

                /// Create a fresh loop iteration (μ-unfolding).
                pub fn renew_loop #tp_clause (
                    channel_id: u64,
                    #ob_extra_param
                ) -> (
                    Chan<Initiator, InitiatorLoop #tp_clause>,
                    Chan<Responder, ResponderLoop #tp_clause>,
                ) {
                    (
                        Chan::new_raw(channel_id, #ob_expr),
                        Chan::new_raw(channel_id, #ob_expr),
                    )
                }
            }
        },
    );

    quote! {
        #[allow(unused_imports, missing_docs)]
        #[allow(clippy::type_complexity)]
        pub mod #mod_name {
            use super::{Chan, End, Initiator, Offer, Recv, Responder, Select, Send};
            use crate::record::ObligationKind;

            #(#msg_structs)*

            #loop_code

            /// Initiator's session type.
            pub type InitiatorSession #tp_clause = #initiator_type;

            /// Responder's session type.
            pub type ResponderSession #tp_clause = #responder_type;

            /// Create a paired initiator/responder session.
            pub fn new_session #tp_clause (
                channel_id: u64,
                #ob_extra_param
            ) -> (
                Chan<Initiator, InitiatorSession #tp_clause>,
                Chan<Responder, ResponderSession #tp_clause>,
            ) {
                (
                    Chan::new_raw(channel_id, #ob_expr),
                    Chan::new_raw(channel_id, #ob_expr),
                )
            }
        }
    }
}

/// Entry point for the `session_protocol!` proc-macro.
pub fn session_protocol_impl(input: TokenStream) -> TokenStream {
    let def = parse_macro_input!(input as ProtocolDef);
    TokenStream::from(generate_protocol(&def))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(input: proc_macro2::TokenStream) -> ProtocolDef {
        syn::parse2::<ProtocolDef>(input).expect("should parse")
    }

    fn parse_err(input: proc_macro2::TokenStream) -> String {
        match syn::parse2::<ProtocolDef>(input) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected parse error but succeeded"),
        }
    }

    // -- Parsing --

    #[test]
    fn parse_simple_protocol() {
        let def = parse_ok(quote! {
            test_proto for SendPermit {
                msg Foo;
                send Foo => end
            }
        });
        assert_eq!(def.name, "test_proto");
        assert!(def.type_params.is_empty());
        assert!(matches!(&def.obligation, ObligationSpec::Fixed(v) if v == "SendPermit"));
        assert_eq!(def.messages.len(), 1);
        assert_eq!(def.messages[0].name, "Foo");
        assert!(def.messages[0].fields.is_empty());
    }

    #[test]
    fn parse_protocol_with_generics() {
        let def = parse_ok(quote! {
            proto<T> for SendPermit {
                send T => end
            }
        });
        assert_eq!(def.type_params.len(), 1);
        assert_eq!(def.type_params[0], "T");
    }

    #[test]
    fn parse_protocol_with_select() {
        let def = parse_ok(quote! {
            proto for SendPermit {
                msg Reserve;
                msg Abort;
                send Reserve => select {
                    send Reserve => end,
                    send Abort => end,
                }
            }
        });
        assert_eq!(def.messages.len(), 2);
        assert!(matches!(def.body, SessionBody::Send(_, _)));
    }

    #[test]
    fn parse_protocol_with_loop() {
        let def = parse_ok(quote! {
            proto for Lease {
                msg Acquire;
                msg Renew;
                msg Release;
                send Acquire => loop {
                    select {
                        send Renew => continue,
                        send Release => end,
                    }
                }
            }
        });
        assert_eq!(def.messages.len(), 3);
        // Body is Send(Acquire, Loop(Select(...)))
        match &def.body {
            SessionBody::Send(_, cont) => assert!(matches!(**cont, SessionBody::Loop(_))),
            _ => panic!("expected Send"),
        }
    }

    #[test]
    fn parse_message_with_fields() {
        let def = parse_ok(quote! {
            proto for IoOp {
                msg Reserve { kind: ObligationKind };
                msg Abort { reason: String };
                send Reserve => end
            }
        });
        assert_eq!(def.messages.len(), 2);
        assert_eq!(def.messages[0].fields.len(), 1);
        assert_eq!(def.messages[0].fields[0].name, "kind");
        assert_eq!(def.messages[1].fields.len(), 1);
        assert_eq!(def.messages[1].fields[0].name, "reason");
    }

    #[test]
    fn parse_protocol_with_offer() {
        parse_ok(quote! {
            proto for SendPermit {
                recv Foo => offer {
                    recv Bar => end,
                    recv Baz => end,
                }
            }
        });
    }

    #[test]
    fn parse_parameterized_obligation() {
        let def = parse_ok(quote! {
            proto(kind: ObligationKind) {
                send Foo => end
            }
        });
        assert!(matches!(&def.obligation, ObligationSpec::Param(n, _) if n == "kind"));
    }

    #[test]
    fn parse_error_continue_outside_loop() {
        let err = parse_err(quote! {
            proto for SendPermit {
                send Foo => continue
            }
        });
        assert!(err.contains("continue"), "error: {err}");
    }

    #[test]
    fn parse_error_nested_loop() {
        let err = parse_err(quote! {
            proto for SendPermit {
                loop { loop { end } }
            }
        });
        assert!(err.contains("nested"), "error: {err}");
    }

    #[test]
    fn parse_error_unknown_keyword() {
        let err = parse_err(quote! {
            proto for SendPermit {
                unknown Foo => end
            }
        });
        assert!(err.contains("unknown"), "error: {err}");
    }

    #[test]
    fn parse_error_missing_for() {
        let err = parse_err(quote! {
            proto { end }
        });
        assert!(err.contains("for"), "error: {err}");
    }

    #[test]
    fn parse_trailing_comma_in_select() {
        parse_ok(quote! {
            proto for SendPermit {
                select {
                    end,
                    end,
                }
            }
        });
    }

    // -- Code generation --

    #[test]
    fn gen_simple_produces_module() {
        let def = parse_ok(quote! {
            test_mod for SendPermit {
                msg Foo;
                send Foo => end
            }
        });
        let code = generate_protocol(&def).to_string();
        assert!(code.contains("pub mod test_mod"), "missing module: {code}");
        assert!(code.contains("InitiatorSession"), "missing type: {code}");
        assert!(code.contains("ResponderSession"), "missing type: {code}");
        assert!(code.contains("new_session"), "missing constructor: {code}");
        assert!(code.contains("pub struct Foo"), "missing message: {code}");
    }

    #[test]
    fn gen_dual_send_becomes_recv() {
        let def = parse_ok(quote! {
            proto for SendPermit {
                send Foo => end
            }
        });
        let code = generate_protocol(&def).to_string();
        // Initiator: Send<Foo, End>
        assert!(
            code.contains("Send < Foo"),
            "initiator missing Send: {code}"
        );
        // Responder: Recv<Foo, End> (dual)
        assert!(
            code.contains("Recv < Foo"),
            "responder missing Recv: {code}"
        );
    }

    #[test]
    fn gen_dual_select_becomes_offer() {
        let def = parse_ok(quote! {
            proto for SendPermit {
                select { end, end }
            }
        });
        let code = generate_protocol(&def).to_string();
        assert!(code.contains("Select"), "initiator missing Select: {code}");
        assert!(code.contains("Offer"), "responder missing Offer: {code}");
    }

    #[test]
    fn gen_loop_produces_renew() {
        let def = parse_ok(quote! {
            proto for Lease {
                loop {
                    select {
                        send Renew => continue,
                        send Release => end,
                    }
                }
            }
        });
        let code = generate_protocol(&def).to_string();
        assert!(code.contains("InitiatorLoop"), "missing loop type: {code}");
        assert!(code.contains("ResponderLoop"), "missing loop type: {code}");
        assert!(code.contains("renew_loop"), "missing renew fn: {code}");
    }

    #[test]
    fn gen_no_loop_skips_renew() {
        let def = parse_ok(quote! {
            proto for SendPermit {
                send Foo => end
            }
        });
        let code = generate_protocol(&def).to_string();
        assert!(
            !code.contains("renew_loop"),
            "should not have renew: {code}"
        );
        assert!(
            !code.contains("InitiatorLoop"),
            "should not have loop type: {code}"
        );
    }

    #[test]
    fn gen_generic_protocol() {
        let def = parse_ok(quote! {
            proto<T> for SendPermit {
                msg Reserve;
                send Reserve => select {
                    send T => end,
                    send Reserve => end,
                }
            }
        });
        let code = generate_protocol(&def).to_string();
        assert!(
            code.contains("InitiatorSession < T >"),
            "missing generic session type: {code}"
        );
        assert!(
            code.contains("new_session < T >"),
            "missing generic constructor: {code}"
        );
    }

    #[test]
    fn gen_message_with_fields_not_copy() {
        let def = parse_ok(quote! {
            proto for IoOp {
                msg Abort { reason: String };
                send Abort => end
            }
        });
        let code = generate_protocol(&def).to_string();
        // Struct with fields should derive Debug, Clone but NOT Copy
        assert!(code.contains("Debug , Clone"), "missing derives: {code}");
        // Check it's not deriving Copy (the word Copy should not appear
        // near the struct definition for field-bearing messages)
        let abort_section = code.split("pub struct Abort").nth(1).unwrap_or("");
        // The derive for this struct should NOT include Copy
        assert!(
            !abort_section.starts_with(" ;"), // has fields, not unit
            "should have fields: {code}"
        );
    }

    #[test]
    fn gen_unit_message_is_copy() {
        let def = parse_ok(quote! {
            proto for SendPermit {
                msg Foo;
                send Foo => end
            }
        });
        let code = generate_protocol(&def).to_string();
        assert!(
            code.contains("Debug , Clone , Copy"),
            "unit struct should be Copy: {code}"
        );
    }

    #[test]
    fn gen_obligation_kind_in_constructor() {
        let def = parse_ok(quote! {
            proto for Lease {
                send Foo => end
            }
        });
        let code = generate_protocol(&def).to_string();
        assert!(
            code.contains("ObligationKind :: Lease"),
            "wrong obligation: {code}"
        );
    }

    #[test]
    fn gen_parameterized_obligation_in_constructor() {
        let def = parse_ok(quote! {
            proto(kind: ObligationKind) {
                send Foo => end
            }
        });
        let code = generate_protocol(&def).to_string();
        // Constructor should take `kind` parameter
        assert!(
            code.contains("kind : ObligationKind"),
            "missing param: {code}"
        );
        // Should use `kind` directly, not `ObligationKind::kind`
        assert!(
            !code.contains("ObligationKind :: kind"),
            "should use param directly: {code}"
        );
    }
}
