//! Explicit caller-owned resources for managed AppSpec work units.
//!
//! These bindings pass real typed handles to code. They do not create pools,
//! grant runtime drivers, install global state, or manage an external handle's
//! shutdown protocol. Cloned handles may outlive the application that received
//! them, just as other caller-supplied Rust capabilities can.

use super::{AppCxCapabilityV1, AppResourceKindV1, AppResourceSpecV1};
use std::any::{Any, TypeId, type_name};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

/// One explicit typed implementation of a manifest resource declaration.
///
/// The declaration must exactly match the manifest, including its kind,
/// capability and optional feature. The value is a caller-owned capability,
/// such as a channel sender, actor address, or database pool handle. Declaring
/// a resource never grants an absent `Cx` I/O, spawn, time or remote driver.
///
/// Bindings retain the value through `Arc`; resource-aware work receives only
/// the handles named by its declaration. Retained routers, factories and cloned
/// handles can extend that ownership beyond application join. Shutdown and
/// revocation of external resources remain the caller's responsibility.
pub struct ManagedAppResourceBinding {
    declaration: AppResourceSpecV1,
    value: Arc<dyn Any + Send + Sync>,
    value_type: &'static str,
}

impl ManagedAppResourceBinding {
    /// Bind a real handle to its exact manifest declaration.
    #[must_use]
    pub fn new<T: Any + Send + Sync>(declaration: AppResourceSpecV1, value: T) -> Self {
        Self {
            declaration,
            value: Arc::new(value),
            value_type: type_name::<T>(),
        }
    }
}

impl fmt::Debug for ManagedAppResourceBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedAppResourceBinding")
            .field("declaration", &self.declaration)
            .field("value_type", &self.value_type)
            .finish_non_exhaustive()
    }
}

/// A work unit's expected Rust type for one named resource.
///
/// Resource-aware factories must list exactly the resources visible to that
/// work unit: the union of service-level and entry-point resource names. This
/// makes a missing or incorrectly typed binding fail before any factory runs.
#[derive(Clone, Debug)]
pub struct ManagedAppResourceRequirement {
    name: String,
    value_type: TypeId,
    value_type_name: &'static str,
}

impl ManagedAppResourceRequirement {
    /// Require `T`, which must be the value type passed to the binding's `new`.
    #[must_use]
    pub fn of<T: Any + Send + Sync>(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value_type: TypeId::of::<T>(),
            value_type_name: type_name::<T>(),
        }
    }
}

/// A resource declaration, typed binding, or work-unit access was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManagedAppResourceError {
    /// More than one handle was supplied for a resource name.
    DuplicateBinding(String),
    /// A declared resource has no supplied handle.
    MissingBinding(String),
    /// A supplied handle names no declared resource.
    UnexpectedBinding(String),
    /// A binding's kind, capability, or feature differs from the manifest.
    DeclarationMismatch(String),
    /// An external capability family has an incompatible resource kind.
    KindCapabilityMismatch(String),
    /// A Pure entry point inherited an effectful named handle from its service.
    PureWorkHasResources(String),
    /// A work unit did not declare the type of a resource it can access.
    MissingRequirement { unit: String, resource: String },
    /// A factory requested a resource outside its manifest allowlist.
    UnexpectedRequirement { unit: String, resource: String },
    /// A factory supplied a type requirement twice.
    DuplicateRequirement { unit: String, resource: String },
    /// A resource's gate is absent from the work unit's declared capabilities.
    MissingCapability { unit: String, resource: String },
    /// A typed requirement or access disagrees with the supplied value type.
    TypeMismatch {
        resource: String,
        expected: &'static str,
        supplied: &'static str,
    },
    /// The resource is not present in this work unit's physical view.
    Undeclared(String),
}

impl fmt::Display for ManagedAppResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AppSpec resource binding/access rejected: {self:?}")
    }
}

impl std::error::Error for ManagedAppResourceError {}

#[derive(Clone)]
struct ResourceValue {
    capability: AppCxCapabilityV1,
    value: Arc<dyn Any + Send + Sync>,
    value_type: &'static str,
}

/// A physically restricted set of real handles for one managed work unit.
///
/// This view contains only the union of its service's and entry point's named
/// resources; it does not retain an application-wide catalog behind a filter.
/// A declared resource's capability must also be explicitly present in the
/// entry point's `cx_capabilities`. Service inheritance therefore shares named
/// handles without silently broadening a factory's runtime authority.
///
/// `get` returns an `Arc<T>` to the exact supplied value. If `T` itself is an
/// `Arc<U>`, the result is `Arc<Arc<U>>`. A caller may clone and retain handles;
/// this interface is explicit dependency injection, not revocation or a Rust
/// sandbox. Its contents remain private.
#[derive(Clone, Default)]
pub struct ManagedAppResources {
    values: Arc<BTreeMap<String, ResourceValue>>,
}

impl fmt::Debug for ManagedAppResources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedAppResources")
            .field("names", &self.values.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl ManagedAppResources {
    /// Get the handle only if this work unit declared its name and Rust type.
    pub fn get<T: Any + Send + Sync>(
        &self,
        name: &str,
    ) -> Result<Arc<T>, ManagedAppResourceError> {
        let value = self
            .values
            .get(name)
            .ok_or_else(|| ManagedAppResourceError::Undeclared(name.to_string()))?;
        Arc::clone(&value.value)
            .downcast::<T>()
            .map_err(|_| ManagedAppResourceError::TypeMismatch {
                resource: name.to_string(),
                expected: type_name::<T>(),
                supplied: value.value_type,
            })
    }

    /// Names actually held by this view, in deterministic order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.values.keys().map(String::as_str)
    }

    pub(super) fn capabilities(&self) -> Vec<AppCxCapabilityV1> {
        let mut capabilities = Vec::new();
        for value in self.values.values() {
            if !capabilities.contains(&value.capability) {
                capabilities.push(value.capability.clone());
            }
        }
        capabilities
    }
}

pub(super) struct ResourceCatalog {
    bindings: BTreeMap<String, ManagedAppResourceBinding>,
}

impl ResourceCatalog {
    pub(super) fn bind(
        declarations: &[AppResourceSpecV1],
        bindings: Vec<ManagedAppResourceBinding>,
    ) -> Result<Self, ManagedAppResourceError> {
        let mut supplied = BTreeMap::new();
        for binding in bindings {
            let name = binding.declaration.name.clone();
            if supplied.insert(name.clone(), binding).is_some() {
                return Err(ManagedAppResourceError::DuplicateBinding(name));
            }
        }
        for declaration in declarations {
            let binding = supplied.get(&declaration.name).ok_or_else(|| {
                ManagedAppResourceError::MissingBinding(declaration.name.clone())
            })?;
            if binding.declaration != *declaration {
                return Err(ManagedAppResourceError::DeclarationMismatch(
                    declaration.name.clone(),
                ));
            }
            let compatible = match declaration.capability {
                AppCxCapabilityV1::Database => declaration.kind == AppResourceKindV1::Database,
                AppCxCapabilityV1::Messaging => declaration.kind == AppResourceKindV1::MessageBus,
                AppCxCapabilityV1::Tls | AppCxCapabilityV1::Quic => {
                    declaration.kind == AppResourceKindV1::Socket
                }
                AppCxCapabilityV1::BrowserHost => {
                    declaration.kind == AppResourceKindV1::BrowserHost
                }
                _ => true,
            };
            if !compatible {
                return Err(ManagedAppResourceError::KindCapabilityMismatch(
                    declaration.name.clone(),
                ));
            }
        }
        let declared: BTreeSet<_> = declarations.iter().map(|d| d.name.as_str()).collect();
        if let Some(name) = supplied.keys().find(|name| !declared.contains(name.as_str())) {
            return Err(ManagedAppResourceError::UnexpectedBinding(name.clone()));
        }
        Ok(Self { bindings: supplied })
    }

    pub(super) fn for_work(
        &self,
        unit: &str,
        names: &BTreeSet<String>,
        requirements: &[ManagedAppResourceRequirement],
        capabilities: &[AppCxCapabilityV1],
    ) -> Result<ManagedAppResources, ManagedAppResourceError> {
        // The compiler checks Pure against entry-point resources. Service
        // inheritance is resolved here, so enforce that invariant again on
        // the effective view, even if a supplied declaration labels a handle
        // itself as Pure.
        if !names.is_empty() && capabilities.contains(&AppCxCapabilityV1::Pure) {
            return Err(ManagedAppResourceError::PureWorkHasResources(unit.to_string()));
        }
        let mut requested = BTreeMap::new();
        for requirement in requirements {
            if !names.contains(&requirement.name) {
                return Err(ManagedAppResourceError::UnexpectedRequirement {
                    unit: unit.to_string(),
                    resource: requirement.name.clone(),
                });
            }
            if requested.insert(requirement.name.clone(), requirement).is_some() {
                return Err(ManagedAppResourceError::DuplicateRequirement {
                    unit: unit.to_string(),
                    resource: requirement.name.clone(),
                });
            }
        }
        let mut values = BTreeMap::new();
        for name in names {
            let requirement = requested.get(name).ok_or_else(|| {
                ManagedAppResourceError::MissingRequirement {
                    unit: unit.to_string(),
                    resource: name.clone(),
                }
            })?;
            let binding = self.bindings.get(name).ok_or_else(|| {
                ManagedAppResourceError::MissingBinding(name.clone())
            })?;
            if !capabilities.contains(&binding.declaration.capability) {
                return Err(ManagedAppResourceError::MissingCapability {
                    unit: unit.to_string(),
                    resource: name.clone(),
                });
            }
            if binding.value.as_ref().type_id() != requirement.value_type {
                return Err(ManagedAppResourceError::TypeMismatch {
                    resource: name.clone(),
                    expected: requirement.value_type_name,
                    supplied: binding.value_type,
                });
            }
            values.insert(name.clone(), ResourceValue {
                capability: binding.declaration.capability.clone(),
                value: Arc::clone(&binding.value),
                value_type: binding.value_type,
            });
        }
        Ok(ManagedAppResources { values: Arc::new(values) })
    }
}
