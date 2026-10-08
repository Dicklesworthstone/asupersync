use super::*;
use crate::grpc::Code;

// Fixture emitted and independently loaded by google.protobuf descriptor_pb2/DescriptorPool.
const FIXTURE: &[u8] = include_bytes!("fixture.bin");

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
