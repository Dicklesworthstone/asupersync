use asupersync_macros::ProtoMessage;

#[derive(Default, ProtoMessage)]
struct ReservedTag {
    #[proto(string, tag = 19000)]
    value: String,
}

fn main() {}
