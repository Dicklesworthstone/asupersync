#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::{RegistryFamily, Subject};
use asupersync::messaging::subject::{
    NamespaceComponent, NamespaceKernel, NamespaceKernelError,
};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

const MAX_COMPONENT_CHARS: usize = 32;
const MAX_RAW_COMPONENT_CHARS: usize = 64;

type PanicPayload = Box<dyn std::any::Any + Send>;
type ComponentParse = Result<NamespaceComponent, NamespaceKernelError>;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Raw(Vec<u8>),
    Structured(StructuredKernelInput),
}

#[derive(Arbitrary, Debug)]
struct StructuredKernelInput {
    tenant: Vec<u8>,
    service: Vec<u8>,
    mailbox: Vec<u8>,
    channel: Vec<u8>,
    feed: Vec<u8>,
    sibling_service: Vec<u8>,
    foreign_tenant: Vec<u8>,
    mutation: KernelMutation,
}

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq, Eq)]
enum KernelMutation {
    Valid,
    TenantWildcard,
    TenantEmpty,
    TenantMultiSegment,
    ServiceWildcard,
    ServiceEmpty,
    ServiceMultiSegment,
    MailboxWildcard,
    MailboxEmpty,
    MailboxMultiSegment,
    ChannelWildcard,
    ChannelEmpty,
    ChannelMultiSegment,
    FeedWildcard,
    FeedEmpty,
    FeedMultiSegment,
}

#[derive(Debug)]
struct StructuredExpectation {
    tenant: String,
    service: String,
    mailbox: String,
    channel: String,
    feed: String,
    sibling_service: String,
    foreign_tenant: String,
    tenant_valid: bool,
    service_valid: bool,
    kernel_valid: bool,
    mailbox_valid: bool,
    channel_valid: bool,
    feed_valid: bool,
}

impl StructuredKernelInput {
    fn materialize(&self) -> StructuredExpectation {
        let tenant = sanitize_component(&self.tenant, "tenant");
        let service = sanitize_component(&self.service, "service");
        let mailbox = sanitize_component(&self.mailbox, "mailbox");
        let channel = sanitize_component(&self.channel, "control");
        let feed = sanitize_component(&self.feed, "telemetry");
        let sibling_service = sanitize_component(&self.sibling_service, "billing");
        let foreign_tenant = sanitize_component(&self.foreign_tenant, "foreign");

        let mut expectation = StructuredExpectation {
            tenant,
            service,
            mailbox,
            channel,
            feed,
            sibling_service,
            foreign_tenant,
            tenant_valid: true,
            service_valid: true,
            kernel_valid: true,
            mailbox_valid: true,
            channel_valid: true,
            feed_valid: true,
        };

        match self.mutation {
            KernelMutation::Valid => {}
            KernelMutation::TenantWildcard => {
                expectation.tenant = "*".to_owned();
                expectation.tenant_valid = false;
                expectation.kernel_valid = false;
            }
            KernelMutation::TenantEmpty => {
                expectation.tenant.clear();
                expectation.tenant_valid = false;
                expectation.kernel_valid = false;
            }
            KernelMutation::TenantMultiSegment => {
                expectation.tenant = make_multi_segment(&expectation.tenant, "corp");
                expectation.tenant_valid = false;
                expectation.kernel_valid = false;
            }
            KernelMutation::ServiceWildcard => {
                expectation.service = ">".to_owned();
                expectation.service_valid = false;
                expectation.kernel_valid = false;
            }
            KernelMutation::ServiceEmpty => {
                expectation.service.clear();
                expectation.service_valid = false;
                expectation.kernel_valid = false;
            }
            KernelMutation::ServiceMultiSegment => {
                expectation.service = make_multi_segment(&expectation.service, "api");
                expectation.service_valid = false;
                expectation.kernel_valid = false;
            }
            KernelMutation::MailboxWildcard => {
                expectation.mailbox = "*".to_owned();
                expectation.mailbox_valid = false;
            }
            KernelMutation::MailboxEmpty => {
                expectation.mailbox.clear();
                expectation.mailbox_valid = false;
            }
            KernelMutation::MailboxMultiSegment => {
                expectation.mailbox = make_multi_segment(&expectation.mailbox, "worker");
                expectation.mailbox_valid = false;
            }
            KernelMutation::ChannelWildcard => {
                expectation.channel = ">".to_owned();
                expectation.channel_valid = false;
            }
            KernelMutation::ChannelEmpty => {
                expectation.channel.clear();
                expectation.channel_valid = false;
            }
            KernelMutation::ChannelMultiSegment => {
                expectation.channel = make_multi_segment(&expectation.channel, "rebalance");
                expectation.channel_valid = false;
            }
            KernelMutation::FeedWildcard => {
                expectation.feed = "*".to_owned();
                expectation.feed_valid = false;
            }
            KernelMutation::FeedEmpty => {
                expectation.feed.clear();
                expectation.feed_valid = false;
            }
            KernelMutation::FeedMultiSegment => {
                expectation.feed = make_multi_segment(&expectation.feed, "errors");
                expectation.feed_valid = false;
            }
        }

        expectation
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = arbitrary::Unstructured::new(data).arbitrary::<FuzzInput>() else {
        return;
    };

    match input {
        FuzzInput::Raw(raw) => fuzz_raw(&raw),
        FuzzInput::Structured(input) => fuzz_structured(&input),
    }
});

fn fuzz_raw(raw: &[u8]) {
    let parts = split_raw_fields(raw);
    let component_results = [
        capture_component_parse(&parts[0]),
        capture_component_parse(&parts[1]),
        capture_component_parse(&parts[2]),
        capture_component_parse(&parts[3]),
        capture_component_parse(&parts[4]),
    ];
    for result in component_results {
        match result {
            Ok(Ok(component)) => {
                assert!(
                    !component.as_str().is_empty(),
                    "namespace component canonical form must not be empty"
                );
                let reparsed =
                    NamespaceComponent::parse(component.as_str()).expect("canonical reparse");
                assert_eq!(reparsed.as_str(), component.as_str());
            }
            Ok(Err(_)) => {}
            Err(payload) => panic_with_input("NamespaceComponent::parse", &parts, payload),
        }
    }

    let kernel_result = catch_unwind(AssertUnwindSafe(|| {
        NamespaceKernel::new(&parts[0], &parts[1])
    }));
    match kernel_result {
        Ok(Ok(kernel)) => exercise_kernel(
            &kernel, &parts[2], &parts[3], &parts[4], &parts[2], &parts[0],
        ),
        Ok(Err(_)) => {}
        Err(payload) => panic_with_input("NamespaceKernel::new", &parts, payload),
    }
}

fn fuzz_structured(input: &StructuredKernelInput) {
    let expectation = input.materialize();

    let tenant_result = capture_component_parse(&expectation.tenant);
    match (expectation.tenant_valid, tenant_result) {
        (true, Ok(Ok(component))) => assert_eq!(component.as_str(), expectation.tenant),
        (false, Ok(Err(_))) => {}
        (false, Ok(Ok(component))) => panic!(
            "invalid kernel tenant unexpectedly parsed: {:?}",
            component.as_str()
        ),
        (_, Err(payload)) => {
            let parts = [
                expectation.tenant.as_str(),
                expectation.service.as_str(),
                expectation.mailbox.as_str(),
                expectation.channel.as_str(),
                expectation.feed.as_str(),
            ];
            panic_with_input("NamespaceComponent::parse", &parts, payload);
        }
        (true, Ok(Err(err))) => panic!("valid tenant rejected: {err:?}"),
    }

    let service_result = capture_component_parse(&expectation.service);
    match (expectation.service_valid, service_result) {
        (true, Ok(Ok(component))) => assert_eq!(component.as_str(), expectation.service),
        (false, Ok(Err(_))) => {}
        (false, Ok(Ok(component))) => panic!(
            "invalid kernel service unexpectedly parsed: {:?}",
            component.as_str()
        ),
        (_, Err(payload)) => {
            let parts = [
                expectation.tenant.as_str(),
                expectation.service.as_str(),
                expectation.mailbox.as_str(),
                expectation.channel.as_str(),
                expectation.feed.as_str(),
            ];
            panic_with_input("NamespaceComponent::parse", &parts, payload);
        }
        (true, Ok(Err(err))) => panic!("valid service rejected: {err:?}"),
    }

    let kernel_result = catch_unwind(AssertUnwindSafe(|| {
        NamespaceKernel::new(&expectation.tenant, &expectation.service)
    }));

    match (expectation.kernel_valid, kernel_result) {
        (true, Ok(Ok(kernel))) => {
            assert_eq!(kernel.tenant().as_str(), expectation.tenant);
            assert_eq!(kernel.service().as_str(), expectation.service);
            assert_eq!(
                kernel.tenant_pattern().as_str(),
                format!("tenant.{}.>", expectation.tenant)
            );
            assert_eq!(
                kernel.service_pattern().as_str(),
                format!(
                    "tenant.{}.service.{}.>",
                    expectation.tenant, expectation.service
                )
            );
            assert_eq!(
                kernel.mailbox_pattern().as_str(),
                format!(
                    "tenant.{}.service.{}.mailbox.>",
                    expectation.tenant, expectation.service
                )
            );
            assert_eq!(
                kernel.control_channel_pattern().as_str(),
                format!(
                    "tenant.{}.service.{}.control.>",
                    expectation.tenant, expectation.service
                )
            );
            assert_eq!(
                kernel.durable_capture_pattern().as_str(),
                format!(
                    "tenant.{}.capture.{}.>",
                    expectation.tenant, expectation.service
                )
            );
            assert_eq!(
                kernel.observability_pattern().as_str(),
                format!(
                    "tenant.{}.service.{}.telemetry.>",
                    expectation.tenant, expectation.service
                )
            );
            assert_eq!(
                kernel.service_discovery_subject().as_str(),
                format!(
                    "tenant.{}.service.{}.discover",
                    expectation.tenant, expectation.service
                )
            );
            assert_eq!(
                kernel.trust_boundary_pattern().as_str(),
                kernel.service_pattern().as_str()
            );

            let mailbox_subject = if expectation.mailbox_valid {
                let mailbox_subject = kernel
                    .mailbox_subject(&expectation.mailbox)
                    .expect("valid mailbox subject");
                assert_eq!(
                    mailbox_subject.as_str(),
                    format!(
                        "tenant.{}.service.{}.mailbox.{}",
                        expectation.tenant, expectation.service, expectation.mailbox
                    )
                );
                assert!(kernel.mailbox_pattern().matches(&mailbox_subject));
                assert!(kernel.owns_subject(&mailbox_subject));
                Some(mailbox_subject)
            } else {
                assert!(kernel.mailbox_subject(&expectation.mailbox).is_err());
                None
            };

            let control_subject = if expectation.channel_valid {
                let control_subject = kernel
                    .control_channel_subject(&expectation.channel)
                    .expect("valid control subject");
                assert_eq!(
                    control_subject.as_str(),
                    format!(
                        "tenant.{}.service.{}.control.{}",
                        expectation.tenant, expectation.service, expectation.channel
                    )
                );
                assert!(kernel.control_channel_pattern().matches(&control_subject));
                assert!(kernel.owns_subject(&control_subject));
                Some(control_subject)
            } else {
                assert!(
                    kernel
                        .control_channel_subject(&expectation.channel)
                        .is_err()
                );
                None
            };

            let observability_subject = if expectation.feed_valid {
                let observability_subject = kernel
                    .observability_subject(&expectation.feed)
                    .expect("valid telemetry subject");
                assert_eq!(
                    observability_subject.as_str(),
                    format!(
                        "tenant.{}.service.{}.telemetry.{}",
                        expectation.tenant, expectation.service, expectation.feed
                    )
                );
                assert!(
                    kernel
                        .observability_pattern()
                        .matches(&observability_subject)
                );
                assert!(kernel.owns_subject(&observability_subject));
                Some(observability_subject)
            } else {
                assert!(kernel.observability_subject(&expectation.feed).is_err());
                None
            };

            assert!(kernel.owns_subject(&kernel.service_discovery_subject()));
            let capture_subject = Subject::new(format!(
                "tenant.{}.capture.{}.snapshot",
                expectation.tenant, expectation.service
            ));
            assert!(kernel.owns_subject(&capture_subject));
            let foreign_subject = Subject::new(format!(
                "tenant.{}.service.{}.mailbox.{}",
                expectation.foreign_tenant, expectation.service, "foreign-worker"
            ));
            assert!(!kernel.owns_subject(&foreign_subject));

            let same_tenant_kernel =
                NamespaceKernel::new(&expectation.tenant, &expectation.sibling_service)
                    .expect("sibling kernel");
            let foreign_kernel =
                NamespaceKernel::new(&expectation.foreign_tenant, &expectation.service)
                    .expect("foreign kernel");
            assert!(kernel.same_tenant(&same_tenant_kernel));
            assert!(!kernel.same_tenant(&foreign_kernel));

            let registry_entries = kernel.registry_entries();
            assert_eq!(registry_entries.len(), 5);
            assert_eq!(registry_entries[0].family, RegistryFamily::Command);
            assert_eq!(
                registry_entries[0].pattern.as_str(),
                kernel.mailbox_pattern().as_str()
            );
            assert_eq!(registry_entries[1].family, RegistryFamily::DerivedView);
            assert_eq!(
                registry_entries[1].pattern.as_str(),
                kernel.service_discovery_subject().as_str()
            );
            assert_eq!(registry_entries[2].family, RegistryFamily::Command);
            assert_eq!(
                registry_entries[2].pattern.as_str(),
                kernel.control_channel_pattern().as_str()
            );
            assert_eq!(registry_entries[3].family, RegistryFamily::Event);
            assert_eq!(
                registry_entries[3].pattern.as_str(),
                kernel.observability_pattern().as_str()
            );
            assert_eq!(registry_entries[4].family, RegistryFamily::CaptureSelector);
            assert_eq!(
                registry_entries[4].pattern.as_str(),
                kernel.durable_capture_pattern().as_str()
            );
            for entry in &registry_entries {
                assert!(
                    entry.description.contains(kernel.tenant().as_str()),
                    "registry description should name tenant: {:?}",
                    entry.description
                );
                assert!(
                    entry.description.contains(kernel.service().as_str()),
                    "registry description should name service: {:?}",
                    entry.description
                );
            }

            if let Some(subject) = mailbox_subject {
                assert!(kernel.service_pattern().matches(&subject));
            }
            if let Some(subject) = control_subject {
                assert!(kernel.service_pattern().matches(&subject));
            }
            if let Some(subject) = observability_subject {
                assert!(kernel.service_pattern().matches(&subject));
            }
        }
        (false, Ok(Err(_))) => {}
        (false, Ok(Ok(kernel))) => panic!(
            "invalid namespace kernel unexpectedly constructed: tenant={} service={} kernel={kernel:?}",
            expectation.tenant, expectation.service
        ),
        (_, Err(payload)) => {
            let parts = [
                expectation.tenant.as_str(),
                expectation.service.as_str(),
                expectation.mailbox.as_str(),
                expectation.channel.as_str(),
                expectation.feed.as_str(),
            ];
            panic_with_input("NamespaceKernel::new", &parts, payload);
        }
        (true, Ok(Err(err))) => panic!("valid namespace kernel rejected: {err:?}"),
    }
}

fn exercise_kernel(
    kernel: &NamespaceKernel,
    mailbox: &str,
    channel: &str,
    feed: &str,
    sibling_service: &str,
    foreign_tenant: &str,
) {
    let service_pattern = kernel.service_pattern();
    let trust_boundary_pattern = kernel.trust_boundary_pattern();
    assert_eq!(service_pattern.as_str(), trust_boundary_pattern.as_str());

    if let Ok(mailbox_subject) = kernel.mailbox_subject(mailbox) {
        assert!(kernel.mailbox_pattern().matches(&mailbox_subject));
        assert!(service_pattern.matches(&mailbox_subject));
        assert!(kernel.owns_subject(&mailbox_subject));
    }

    if let Ok(control_subject) = kernel.control_channel_subject(channel) {
        assert!(kernel.control_channel_pattern().matches(&control_subject));
        assert!(service_pattern.matches(&control_subject));
        assert!(kernel.owns_subject(&control_subject));
    }

    if let Ok(observability_subject) = kernel.observability_subject(feed) {
        assert!(
            kernel
                .observability_pattern()
                .matches(&observability_subject)
        );
        assert!(service_pattern.matches(&observability_subject));
        assert!(kernel.owns_subject(&observability_subject));
    }

    let service_discovery_subject = kernel.service_discovery_subject();
    assert!(service_pattern.matches(&service_discovery_subject));
    assert!(kernel.owns_subject(&service_discovery_subject));
    assert_eq!(kernel.registry_entries().len(), 5);

    if let (Ok(sibling), Ok(foreign)) = (
        NamespaceKernel::new(kernel.tenant().as_str(), sibling_service),
        NamespaceKernel::new(foreign_tenant, kernel.service().as_str()),
    ) {
        assert!(kernel.same_tenant(&sibling));
        assert!(!kernel.same_tenant(&foreign));
    }
}

fn capture_component_parse(component: &str) -> Result<ComponentParse, PanicPayload> {
    catch_unwind(AssertUnwindSafe(|| NamespaceComponent::parse(component)))
}

fn split_raw_fields(raw: &[u8]) -> [String; 5] {
    let mut fields = std::array::from_fn(|_| String::new());
    for (index, chunk) in raw.split(|byte| *byte == 0).take(5).enumerate() {
        fields[index] = sanitize_raw_component(chunk);
    }
    fields
}

fn sanitize_component(bytes: &[u8], fallback: &str) -> String {
    let sanitized: String = String::from_utf8_lossy(bytes)
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        .take(MAX_COMPONENT_CHARS)
        .collect();
    if sanitized.is_empty() {
        fallback.to_owned()
    } else {
        sanitized
    }
}

fn sanitize_raw_component(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_RAW_COMPONENT_CHARS)
        .collect()
}

fn make_multi_segment(base: &str, suffix: &str) -> String {
    format!("{base}.{suffix}")
}

fn panic_with_input(operation: &str, parts: &[impl AsRef<str>], payload: PanicPayload) -> ! {
    let fields = parts
        .iter()
        .map(|part| part.as_ref())
        .collect::<Vec<_>>()
        .join(" | ");
    let panic_text = panic_message(payload);
    panic!("{operation} panicked for input [{fields}]: {panic_text}");
}

fn panic_message(payload: PanicPayload) -> String {
    let payload_ref = payload.as_ref();
    if let Some(message) = payload_ref.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload_ref.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}
