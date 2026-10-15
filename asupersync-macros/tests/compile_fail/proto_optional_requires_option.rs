use asupersync_macros::ProtoMessage;

#[derive(Default, ProtoMessage)]
struct OptionalRequiresOption {
    #[proto(uint32, optional, tag = 1)]
    value: u32,
}

fn main() {}
