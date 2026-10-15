use asupersync_macros::ProtoMessage;

#[derive(Default, ProtoMessage)]
struct PackedString {
    #[proto(string, repeated, packed, tag = 1)]
    values: Vec<String>,
}

fn main() {}
