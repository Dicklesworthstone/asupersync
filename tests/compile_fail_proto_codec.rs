//! Compile-fail contracts for the owned protobuf authoring boundary.
//!
//! Bead: asupersync-5z2scg.1.2 (Protobuf A2)
//!
//! `tests/grpc_owned_proto_codec_downstream_contract.rs` proves the
//! compile-*pass* half: a downstream crate can define its own messages against
//! `ProtoMessage` with no derive, no registry, and no `prost`. These cases prove
//! the other half — that the boundary *rejects* the three mistakes a
//! hand-authoring user is most likely to make, and rejects them at the
//! definition site with a diagnostic that points at the real problem.
//!
//! This matters more than usual here because the derive is still future work
//! (`asupersync-5z2scg.1.6`). Until it lands, every message is written by hand,
//! so the quality of these errors *is* the authoring experience.

#[test]
#[ignore = "cold trybuild compile-fail lane; run explicitly with `cargo test --test compile_fail_proto_codec -- --ignored`"]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    // Using the codec requires ProtoMessage on both directions, even though
    // naming the type parameters does not.
    t.compile_fail("tests/compile_fail/proto_codec_requires_proto_message.rs");
    // Decoding is a merge onto Default, so a message with no default is
    // refused where it is defined.
    t.compile_fail("tests/compile_fail/proto_message_requires_default.rs");
    // Streaming call sites move messages across worker threads, so Send is
    // enforced at the impl rather than at the eventual call site.
    t.compile_fail("tests/compile_fail/proto_message_requires_send.rs");
}
