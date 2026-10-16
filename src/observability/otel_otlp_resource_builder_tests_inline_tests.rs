    use std::collections::{BTreeMap, HashMap};
    use std::env;
    use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

    use super::OtlpResourceBuilder;

    const RESOURCE_ENV_VARS: &[&str] = &["HOSTNAME", "COMPUTERNAME", "OTEL_RESOURCE_ATTRIBUTES"];

    fn resource_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct ResourceEnvGuard {
        _guard: MutexGuard<'static, ()>,
        previous: BTreeMap<&'static str, Option<String>>,
    }

    impl ResourceEnvGuard {
        #[allow(unsafe_code)]
        fn with(updates: &[(&'static str, Option<&str>)]) -> Self {
            let guard = resource_env_lock()
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let previous = RESOURCE_ENV_VARS
                .iter()
                .map(|var| (*var, env::var(var).ok()))
                .collect();

            for var in RESOURCE_ENV_VARS {
                unsafe {
                    env::remove_var(var);
                }
            }

            for (key, value) in updates {
                unsafe {
                    match value {
                        Some(value) => env::set_var(key, value),
                        None => env::remove_var(key),
                    }
                }
            }

            Self {
                _guard: guard,
                previous,
            }
        }
    }

    impl Drop for ResourceEnvGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            for (key, value) in &self.previous {
                unsafe {
                    match value {
                        Some(value) => env::set_var(key, value),
                        None => env::remove_var(key),
                    }
                }
            }
        }
    }

    #[test]
    fn detected_host_name_uses_trimmed_hostname_env() {
        let _guard = ResourceEnvGuard::with(&[("HOSTNAME", Some("  asupersync-host  "))]);

        let resource = OtlpResourceBuilder::new().with_detected_host_name().build();

        assert_eq!(
            resource.get("host.name"),
            Some(&"asupersync-host".to_string())
        );
    }

    #[test]
    fn detected_host_name_ignores_empty_host_values() {
        let _guard =
            ResourceEnvGuard::with(&[("HOSTNAME", Some("   ")), ("COMPUTERNAME", Some("\t\n"))]);

        let resource = OtlpResourceBuilder::new().with_detected_host_name().build();

        assert!(!resource.contains_key("host.name"));
    }

    #[test]
    fn detected_host_name_preserves_resource_precedence() {
        let _guard = ResourceEnvGuard::with(&[
            ("HOSTNAME", Some("detected-host")),
            ("OTEL_RESOURCE_ATTRIBUTES", Some("host.name=env-host")),
        ]);

        let env_resource = OtlpResourceBuilder::new()
            .with_detected_host_name()
            .with_env_resource_attributes()
            .build();

        assert_eq!(env_resource.get("host.name"), Some(&"env-host".to_string()));

        let mut attrs = HashMap::new();
        attrs.insert("host.name".to_string(), "programmatic-host".to_string());

        let programmatic_resource = OtlpResourceBuilder::new()
            .with_detected_host_name()
            .with_env_resource_attributes()
            .with_attributes(attrs)
            .build();

        assert_eq!(
            programmatic_resource.get("host.name"),
            Some(&"programmatic-host".to_string())
        );
    }
