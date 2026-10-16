    use super::*;

    fn person() -> SchemaDescriptor {
        SchemaDescriptor::structure(
            "Person",
            vec![
                ("id", u64::schema()),
                ("name", String::schema()),
                ("tags", <Vec<String>>::schema()),
            ],
        )
    }

    #[test]
    fn fingerprint_is_deterministic_and_distinct() {
        // AC3: stable across recomputation; distinct for distinct structure.
        assert_eq!(person().fingerprint(), person().fingerprint());
        assert_eq!(u64::schema_fingerprint(), u64::schema_fingerprint());
        assert_ne!(u64::schema_fingerprint(), u32::schema_fingerprint());
        assert_ne!(
            <Vec<u8>>::schema_fingerprint(),
            <Vec<u16>>::schema_fingerprint()
        );
        assert_ne!(
            <Option<u64>>::schema_fingerprint(),
            u64::schema_fingerprint()
        );
    }

    #[test]
    fn fingerprint_not_type_id_based() {
        // Two independently-constructed-but-identical descriptors agree.
        let a = SchemaDescriptor::structure("P", vec![("x", u8::schema())]);
        let b = SchemaDescriptor::structure("P", vec![("x", u8::schema())]);
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn diff_detects_type_change() {
        let expected = person();
        let actual = SchemaDescriptor::structure(
            "Person",
            vec![
                ("id", u32::schema()), // changed u64 -> u32
                ("name", String::schema()),
                ("tags", <Vec<String>>::schema()),
            ],
        );
        let mismatch = SchemaDescriptor::diff(&expected, &actual).expect("should differ");
        assert_eq!(mismatch.path, "$.id");
        assert!(matches!(
            mismatch.kind,
            SchemaMismatchKind::PrimitiveChanged {
                expected: "u64",
                actual: "u32"
            }
        ));
    }

    #[test]
    fn diff_detects_missing_field() {
        let expected = person();
        let actual = SchemaDescriptor::structure(
            "Person",
            vec![("id", u64::schema()), ("name", String::schema())], // dropped "tags"
        );
        let mismatch = SchemaDescriptor::diff(&expected, &actual).expect("should differ");
        assert!(matches!(
            mismatch.kind,
            SchemaMismatchKind::FieldMissing { ref field } if field == "tags"
        ));
    }

    #[test]
    fn diff_detects_extra_field() {
        let expected = SchemaDescriptor::structure("P", vec![("a", u8::schema())]);
        let actual =
            SchemaDescriptor::structure("P", vec![("a", u8::schema()), ("b", u8::schema())]);
        let mismatch = SchemaDescriptor::diff(&expected, &actual).expect("should differ");
        assert!(matches!(
            mismatch.kind,
            SchemaMismatchKind::FieldExtra { ref field } if field == "b"
        ));
    }

    #[test]
    fn diff_detects_rename() {
        let expected = SchemaDescriptor::structure("Old", vec![("a", u8::schema())]);
        let actual = SchemaDescriptor::structure("New", vec![("a", u8::schema())]);
        let mismatch = SchemaDescriptor::diff(&expected, &actual).expect("should differ");
        assert!(matches!(
            mismatch.kind,
            SchemaMismatchKind::NameChanged { .. }
        ));
    }

    #[test]
    fn identical_schema_has_no_diff() {
        assert!(SchemaDescriptor::diff(&person(), &person()).is_none());
    }

    #[test]
    fn mismatch_messages_name_the_difference() {
        // AC2: messages are agent-readable and name the difference.
        let expected = person();
        let actual = SchemaDescriptor::structure(
            "Person",
            vec![
                ("id", u32::schema()),
                ("name", String::schema()),
                ("tags", <Vec<String>>::schema()),
            ],
        );
        let mismatch = SchemaDescriptor::diff(&expected, &actual).expect("should differ");
        let rendered = mismatch.to_string();
        assert!(rendered.contains("$.id"), "rendered: {rendered}");
        assert!(rendered.contains("u64"), "rendered: {rendered}");
        assert!(rendered.contains("u32"), "rendered: {rendered}");
    }

    #[test]
    fn computation_registry_enumerates_entries_in_name_order() {
        let mut registry = ComputationSchemaRegistry::new();
        registry
            .register_typed::<u64, String>("zeta.encode")
            .unwrap();
        registry
            .register_typed::<(u64, String), Vec<u8>>("alpha.decode")
            .unwrap();

        assert_eq!(registry.len(), 2);
        assert!(registry.contains("alpha.decode"));

        let names: Vec<&str> = registry
            .iter()
            .map(RegisteredComputationSchema::name)
            .collect();
        assert_eq!(names, vec!["alpha.decode", "zeta.encode"]);

        let alpha = registry.get("alpha.decode").unwrap();
        assert_eq!(
            alpha.input_fingerprint(),
            <(u64, String)>::schema_fingerprint()
        );
        assert_eq!(alpha.output_fingerprint(), <Vec<u8>>::schema_fingerprint());
    }

    #[test]
    fn computation_registry_rejects_duplicate_names() {
        let mut registry = ComputationSchemaRegistry::new();
        registry.register_typed::<u64, u64>("work").unwrap();
        let err = registry
            .register_typed::<String, String>("work")
            .expect_err("duplicate computation names must fail closed");

        assert!(matches!(
            err,
            ComputationSchemaRegistryError::DuplicateName { ref name } if name == "work"
        ));
        assert_eq!(registry.len(), 1);
        let work = registry.get("work").unwrap();
        assert_eq!(work.input_fingerprint(), u64::schema_fingerprint());
        assert_eq!(work.output_fingerprint(), u64::schema_fingerprint());
    }

    #[test]
    fn computation_registry_fingerprint_is_order_independent_and_fail_closed() {
        let mut first = ComputationSchemaRegistry::new();
        first.register_typed::<u64, String>("zeta.encode").unwrap();
        first
            .register_typed::<(u64, String), Vec<u8>>("alpha.decode")
            .unwrap();

        let mut second = ComputationSchemaRegistry::new();
        second
            .register_typed::<(u64, String), Vec<u8>>("alpha.decode")
            .unwrap();
        second.register_typed::<u64, String>("zeta.encode").unwrap();

        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(
            ComputationRegistryFingerprint::from_bytes(first.fingerprint().into_bytes()),
            first.fingerprint()
        );

        let mut changed_schema = ComputationSchemaRegistry::new();
        changed_schema
            .register_typed::<(u32, String), Vec<u8>>("alpha.decode")
            .unwrap();
        changed_schema
            .register_typed::<u64, String>("zeta.encode")
            .unwrap();
        assert_ne!(first.fingerprint(), changed_schema.fingerprint());

        let mut missing_entry = ComputationSchemaRegistry::new();
        missing_entry
            .register_typed::<(u64, String), Vec<u8>>("alpha.decode")
            .unwrap();
        assert_ne!(first.fingerprint(), missing_entry.fingerprint());
    }
