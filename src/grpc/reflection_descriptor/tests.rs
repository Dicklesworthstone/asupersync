use super::*;
use crate::grpc::Code;

// Fixture emitted and independently loaded by google.protobuf descriptor_pb2/DescriptorPool.
const FIXTURE: &[u8] = &[
    10, 123, 10, 10, 101, 99, 104, 111, 46, 112, 114, 111, 116, 111, 18, 4,
    100, 101, 109, 111, 26, 11, 116, 121, 112, 101, 115, 46, 112, 114, 111, 116,
    111, 50, 82, 10, 4, 69, 99, 104, 111, 18, 34, 10, 4, 80, 105, 110,
    103, 18, 12, 46, 100, 101, 109, 111, 46, 82, 101, 99, 111, 114, 100, 26,
    12, 46, 100, 101, 109, 111, 46, 82, 101, 99, 111, 114, 100, 18, 38, 10,
    4, 67, 104, 97, 116, 18, 12, 46, 100, 101, 109, 111, 46, 82, 101, 99,
    111, 114, 100, 26, 12, 46, 100, 101, 109, 111, 46, 82, 101, 99, 111, 114,
    100, 40, 1, 48, 1, 98, 6, 112, 114, 111, 116, 111, 50, 10, 110, 10,
    9, 101, 120, 116, 46, 112, 114, 111, 116, 111, 18, 4, 100, 101, 109, 111,
    26, 11, 116, 121, 112, 101, 115, 46, 112, 114, 111, 116, 111, 34, 42, 10,
    5, 79, 117, 116, 101, 114, 50, 33, 10, 11, 110, 101, 115, 116, 101, 100,
    95, 110, 111, 116, 101, 18, 12, 46, 100, 101, 109, 111, 46, 82, 101, 99,
    111, 114, 100, 24, 101, 32, 1, 40, 9, 58, 26, 10, 4, 110, 111, 116,
    101, 18, 12, 46, 100, 101, 109, 111, 46, 82, 101, 99, 111, 114, 100, 24,
    100, 32, 1, 40, 9, 98, 6, 112, 114, 111, 116, 111, 50, 10, 205, 1,
    10, 11, 116, 121, 112, 101, 115, 46, 112, 114, 111, 116, 111, 18, 4, 100,
    101, 109, 111, 34, 110, 10, 6, 82, 101, 99, 111, 114, 100, 18, 10, 10,
    2, 105, 100, 24, 1, 32, 1, 40, 9, 18, 14, 10, 4, 116, 101, 120,
    116, 24, 2, 32, 1, 40, 9, 72, 0, 26, 22, 10, 5, 67, 104, 105,
    108, 100, 18, 13, 10, 5, 118, 97, 108, 117, 101, 24, 1, 32, 1, 40,
    9, 34, 31, 10, 5, 83, 116, 97, 116, 101, 18, 11, 10, 7, 85, 78,
    75, 78, 79, 87, 78, 16, 0, 18, 9, 10, 5, 82, 69, 65, 68, 89,
    16, 1, 42, 5, 8, 100, 16, 200, 1, 66, 8, 10, 6, 99, 104, 111,
    105, 99, 101, 66, 14, 10, 12, 107, 101, 112, 116, 46, 111, 112, 116, 105,
    111, 110, 115, 74, 44, 10, 42, 10, 2, 4, 0, 26, 36, 84, 104, 105,
    115, 32, 115, 111, 117, 114, 99, 101, 32, 97, 110, 110, 111, 116, 97, 116,
    105, 111, 110, 32, 109, 117, 115, 116, 32, 115, 117, 114, 118, 105, 118, 101,
    46, 98, 6, 112, 114, 111, 116, 111, 50, 128, 181, 24, 7,
];

fn catalog() -> ReflectionDescriptorSet {
    ReflectionDescriptorSet::decode(FIXTURE).unwrap()
}

fn mutate_file(index: usize, mutate: impl FnOnce(&mut FileInfo)) -> Vec<u8> {
    let mut set = WireSet::decode(FIXTURE).unwrap();
    let mut file = FileInfo::decode(set.files[index].as_slice()).unwrap();
    mutate(&mut file);
    set.files[index] = file.encode_to_vec();
    set.encode_to_vec()
}

#[test]
fn reads_protobuf_compiler_wire_and_keeps_exact_descriptor_bytes() {
    let catalog = catalog();
    let raw = WireSet::decode(FIXTURE).unwrap().files;
    assert_eq!(catalog.file_names().collect::<Vec<_>>(), ["echo.proto", "ext.proto", "types.proto"]);
    assert_eq!(catalog.service_names().collect::<Vec<_>>(), ["demo.Echo"]);
    let files = catalog.file_by_name("echo.proto").unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].as_ref(), raw[0]);
    assert_eq!(files[1].as_ref(), raw[2]);
    assert!(files[1].as_ref().ends_with(&[0x80, 0xb5, 0x18, 0x07]));
}

#[test]
fn indexes_services_methods_nested_types_fields_enums_and_oneofs() {
    let catalog = catalog();
    for name in ["demo.Echo", "demo.Echo.Ping", "demo.Echo.Chat"] {
        assert_eq!(catalog.file_containing_symbol(name).unwrap(), catalog.file_by_name("echo.proto").unwrap());
    }
    for name in ["demo.Record", ".demo.Record", "demo.Record.id", "demo.Record.Child",
        "demo.Record.Child.value", "demo.Record.State", "demo.Record.READY", "demo.Record.choice"] {
        assert_eq!(catalog.file_containing_symbol(name).unwrap(), catalog.file_by_name("types.proto").unwrap());
    }
    // Enum values are siblings of the enum type, not children of it.
    assert_eq!(catalog.file_containing_symbol("demo.Record.State.READY").unwrap_err().code(), Code::NotFound);
}

#[test]
fn indexes_top_level_and_nested_extensions_by_name_and_number() {
    let catalog = catalog();
    assert_eq!(catalog.extension_numbers("demo.Record").unwrap(), [100, 101]);
    assert_eq!(catalog.extension_numbers("demo.Record.Child").unwrap(), Vec::<i32>::new());
    let expected = catalog.file_by_name("ext.proto").unwrap();
    for (name, number) in [("demo.note", 100), ("demo.Outer.nested_note", 101)] {
        assert_eq!(catalog.file_containing_symbol(name).unwrap(), expected);
        assert_eq!(catalog.file_containing_extension(".demo.Record", number).unwrap(), expected);
    }
    assert_eq!(catalog.extension_numbers("demo.Unknown").unwrap_err().code(), Code::NotFound);
    assert_eq!(catalog.file_containing_extension("demo.Record", 102).unwrap_err().code(), Code::NotFound);
}

#[test]
fn missing_lookups_fail_without_fabricated_schema() {
    let catalog = catalog();
    assert_eq!(catalog.file_by_name("missing.proto").unwrap_err().code(), Code::NotFound);
    assert_eq!(catalog.file_containing_symbol("..demo.Record").unwrap_err().code(), Code::NotFound);
    assert_eq!(catalog.file_containing_extension("demo.Record", -1).unwrap_err().code(), Code::NotFound);
}

#[test]
fn duplicate_files_are_refused_even_with_identical_bytes() {
    let mut set = WireSet::decode(FIXTURE).unwrap();
    set.files.push(set.files[0].clone());
    assert_eq!(ReflectionDescriptorSet::decode(&set.encode_to_vec()).unwrap_err().code(), Code::InvalidArgument);
}

#[test]
fn duplicate_symbols_in_distinct_files_are_refused() {
    let mut set = WireSet::decode(FIXTURE).unwrap();
    let mut file = FileInfo::decode(set.files[0].as_slice()).unwrap();
    file.name = Some("other.proto".to_string());
    set.files.push(file.encode_to_vec());
    assert_eq!(ReflectionDescriptorSet::decode(&set.encode_to_vec()).unwrap_err().code(), Code::InvalidArgument);
}

#[test]
fn missing_imports_duplicate_imports_and_cycles_are_refused() {
    for imports in [vec!["missing.proto"], vec!["types.proto", "types.proto"], vec!["echo.proto"]] {
        let invalid = mutate_file(0, |file| file.imports = imports.into_iter().map(str::to_owned).collect());
        assert_eq!(ReflectionDescriptorSet::decode(&invalid).unwrap_err().code(), Code::InvalidArgument);
    }
    let cycle = mutate_file(2, |file| file.imports.push("echo.proto".to_string()));
    assert_eq!(ReflectionDescriptorSet::decode(&cycle).unwrap_err().code(), Code::InvalidArgument);
}

#[test]
fn shared_transitive_import_is_returned_only_once() {
    let encoded = mutate_file(0, |file| file.imports.push("ext.proto".to_string()));
    let catalog = ReflectionDescriptorSet::decode(&encoded).unwrap();
    let files = catalog.file_by_name("echo.proto").unwrap();
    let names: Vec<_> = files.iter().map(|file| FileInfo::decode(file.as_ref()).unwrap().name.unwrap()).collect();
    assert_eq!(names, ["echo.proto", "types.proto", "ext.proto"]);
}

#[test]
fn duplicate_or_invalid_extension_targets_and_numbers_are_refused() {
    let duplicate = mutate_file(1, |file| file.messages[0].extensions[0].number = Some(100));
    assert_eq!(ReflectionDescriptorSet::decode(&duplicate).unwrap_err().code(), Code::InvalidArgument);
    for target in ["demo.Record", ".demo.Missing", ".demo.Echo"] {
        let invalid = mutate_file(1, |file| file.extensions[0].extendee = Some(target.to_string()));
        assert_eq!(ReflectionDescriptorSet::decode(&invalid).unwrap_err().code(), Code::InvalidArgument);
    }
    for number in [0, -1, 19_000, 536_870_912] {
        let invalid = mutate_file(1, |file| file.extensions[0].number = Some(number));
        assert_eq!(ReflectionDescriptorSet::decode(&invalid).unwrap_err().code(), Code::InvalidArgument);
    }
}

#[test]
fn malformed_wire_invalid_names_and_admission_limits_are_refused() {
    assert_eq!(ReflectionDescriptorSet::decode(&[0x0a, 0xff]).unwrap_err().code(), Code::InvalidArgument);
    let invalid = mutate_file(0, |file| file.services[0].name = Some("bad.name".to_string()));
    assert_eq!(ReflectionDescriptorSet::decode(&invalid).unwrap_err().code(), Code::InvalidArgument);
    let invalid = mutate_file(0, |file| file.name = Some(String::new()));
    assert_eq!(ReflectionDescriptorSet::decode(&invalid).unwrap_err().code(), Code::InvalidArgument);
    let oversized = vec![0; MAX_REFLECTION_DESCRIPTOR_BYTES + 1];
    assert_eq!(ReflectionDescriptorSet::decode(&oversized).unwrap_err().code(), Code::ResourceExhausted);
    let too_many = WireSet { files: vec![Vec::new(); MAX_FILES + 1] }.encode_to_vec();
    assert_eq!(ReflectionDescriptorSet::decode(&too_many).unwrap_err().code(), Code::ResourceExhausted);
}

#[test]
fn empty_catalog_is_valid_and_does_not_invent_services() {
    let empty = ReflectionDescriptorSet::decode(&[]).unwrap();
    assert_eq!(empty.file_names().count(), 0);
    assert_eq!(empty.service_names().count(), 0);
    assert_eq!(empty.file_by_name("empty.proto").unwrap_err().code(), Code::NotFound);
}
