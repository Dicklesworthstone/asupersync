// Private wire shapes shared by grpc.reflection.v1 and v1alpha. Field numbers
// follow grpc/grpc-proto's reflection.proto; the public in-process registry's
// Rust request and descriptor types retain their existing representation.

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct WireRequest {
    #[prost(string, tag = "1")]
    pub host: String,
    #[prost(oneof = "Query", tags = "3, 4, 5, 6, 7")]
    pub query: Option<Query>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub(super) enum Query {
    #[prost(string, tag = "3")]
    FileByName(String),
    #[prost(string, tag = "4")]
    FileContainingSymbol(String),
    #[prost(message, tag = "5")]
    FileContainingExtension(ExtensionRequest),
    #[prost(string, tag = "6")]
    AllExtensionNumbers(String),
    #[prost(string, tag = "7")]
    ListServices(String),
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct ExtensionRequest {
    #[prost(string, tag = "1")]
    pub containing_type: String,
    #[prost(int32, tag = "2")]
    pub number: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct WireResponse {
    #[prost(string, tag = "1")]
    pub valid_host: String,
    #[prost(message, optional, tag = "2")]
    pub original_request: Option<WireRequest>,
    #[prost(oneof = "Reply", tags = "4, 5, 6, 7")]
    pub reply: Option<Reply>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub(super) enum Reply {
    #[prost(message, tag = "4")]
    Files(Files),
    #[prost(message, tag = "5")]
    Extensions(ExtensionNumbers),
    #[prost(message, tag = "6")]
    Services(Services),
    #[prost(message, tag = "7")]
    Error(ErrorReply),
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Files {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub files: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct ExtensionNumbers {
    #[prost(string, tag = "1")]
    pub base_type_name: String,
    #[prost(int32, repeated, tag = "2")]
    pub numbers: Vec<i32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Services {
    #[prost(message, repeated, tag = "1")]
    pub services: Vec<Service>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Service {
    #[prost(string, tag = "1")]
    pub name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct ErrorReply {
    #[prost(int32, tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: String,
}
