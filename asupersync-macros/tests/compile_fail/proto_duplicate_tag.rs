use asupersync_macros::ProtoMessage;

#[derive(Default, ProtoMessage)]
struct DuplicateTag {
    #[proto(string, tag = 1)]
    first: String,
    #[proto(uint64, tag = 1)]
    second: u64,
}

fn main() {}
