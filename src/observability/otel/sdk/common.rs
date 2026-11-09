//! Shared bounded SDK value mapping. Callers validate a complete borrowed
//! collection before constructing any owned OTLP values.

use crate::observability::otlp_proto::common_and_resource::{
    AnyValue, AnyValueValue, ArrayValue, KeyValue, KeyValueList, Resource,
};
use opentelemetry::logs::AnyValue as LogValue;
use opentelemetry::{Array, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ATTRIBUTES: usize = 128;
const MAX_ARRAY_ITEMS: usize = 128;
const MAX_VALUES: usize = 65_536;
const MAX_LOG_VALUE_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SdkValueError {
    LimitExceeded,
    InvalidAttributes,
    InvalidNumericValue,
    InvalidTimestamp,
}

pub(super) struct ValueBudget {
    max_bytes: usize,
    bytes: usize,
    values: usize,
}

impl ValueBudget {
    pub(super) fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            bytes: 0,
            values: 0,
        }
    }

    pub(super) fn byte_count(&self) -> usize {
        self.bytes
    }

    pub(super) fn node_count(&self) -> usize {
        self.values
    }

    pub(super) fn bytes(&mut self, amount: usize) -> Result<(), SdkValueError> {
        self.bytes = self
            .bytes
            .checked_add(amount)
            .filter(|bytes| *bytes <= self.max_bytes)
            .ok_or(SdkValueError::LimitExceeded)?;
        Ok(())
    }

    pub(super) fn reserve_owned(
        &mut self,
        bytes: usize,
        values: usize,
    ) -> Result<(), SdkValueError> {
        self.bytes(bytes)?;
        self.values = self
            .values
            .checked_add(values)
            .filter(|count| *count <= MAX_VALUES)
            .ok_or(SdkValueError::LimitExceeded)?;
        Ok(())
    }

    pub(super) fn text(&mut self, text: &str, limit: usize) -> Result<(), SdkValueError> {
        if text.len() > limit {
            return Err(SdkValueError::LimitExceeded);
        }
        self.bytes(text.len())
    }

    pub(super) fn attributes<'a>(
        &mut self,
        attributes: impl Iterator<Item = (&'a str, &'a Value)>,
    ) -> Result<(), SdkValueError> {
        self.attribute_list_inner(attributes, true)
    }

    /// SDK trace setters append updates rather than replacing earlier keys.
    /// Account and validate every raw entry before selecting the last value.
    pub(super) fn attribute_list<'a>(
        &mut self,
        attributes: impl Iterator<Item = (&'a str, &'a Value)>,
    ) -> Result<(), SdkValueError> {
        self.attribute_list_inner(attributes, false)
    }

    fn attribute_list_inner<'a>(
        &mut self,
        attributes: impl Iterator<Item = (&'a str, &'a Value)>,
        unique: bool,
    ) -> Result<(), SdkValueError> {
        let mut keys = BTreeSet::new();
        for (index, (key, value)) in attributes.enumerate() {
            if index == MAX_ATTRIBUTES
                || key.is_empty()
                || key.len() > 1024
                || (unique && !keys.insert(key))
            {
                return Err(SdkValueError::InvalidAttributes);
            }
            self.bytes(std::mem::size_of::<KeyValue>())?;
            self.text(key, 1024)?;
            self.value(value)?;
        }
        Ok(())
    }

    fn value_node(&mut self) -> Result<(), SdkValueError> {
        self.values = self
            .values
            .checked_add(1)
            .filter(|count| *count <= MAX_VALUES)
            .ok_or(SdkValueError::LimitExceeded)?;
        self.bytes(std::mem::size_of::<AnyValue>())
    }

    fn value(&mut self, value: &Value) -> Result<(), SdkValueError> {
        self.value_node()?;
        match value {
            Value::Bool(_) | Value::I64(_) => Ok(()),
            Value::F64(value) => finite(*value).map(|_| ()),
            Value::String(value) => self.text(value.as_str(), 4096),
            Value::Array(array) => match array {
                Array::Bool(values) => self.scalar_array(values.len()),
                Array::I64(values) => self.scalar_array(values.len()),
                Array::F64(values) => {
                    self.scalar_array(values.len())?;
                    for value in values {
                        finite(*value)?;
                    }
                    Ok(())
                }
                Array::String(values) => {
                    self.scalar_array(values.len())?;
                    for value in values {
                        self.text(value.as_str(), 4096)?;
                    }
                    Ok(())
                }
                _ => Err(SdkValueError::InvalidAttributes),
            },
            _ => Err(SdkValueError::InvalidAttributes),
        }
    }

    fn scalar_array(&mut self, len: usize) -> Result<(), SdkValueError> {
        if len > MAX_ARRAY_ITEMS {
            return Err(SdkValueError::LimitExceeded);
        }
        for _ in 0..len {
            self.value_node()?;
        }
        Ok(())
    }

    /// Admit every raw SDK log attribute, including overwritten updates.
    pub(super) fn log_attributes<'a>(
        &mut self,
        attributes: impl Iterator<Item = (&'a str, &'a LogValue)>,
    ) -> Result<(), SdkValueError> {
        for (index, (key, value)) in attributes.enumerate() {
            if index == MAX_ATTRIBUTES || key.is_empty() || key.len() > 1024 {
                return Err(SdkValueError::InvalidAttributes);
            }
            self.bytes(std::mem::size_of::<KeyValue>())?;
            self.text(key, 1024)?;
            self.log_value(value, 1)?;
        }
        Ok(())
    }

    /// Bound recursive SDK log values before copying strings, bytes, or maps.
    pub(super) fn log_value(
        &mut self,
        value: &LogValue,
        depth: usize,
    ) -> Result<(), SdkValueError> {
        if depth == 0 || depth > MAX_LOG_VALUE_DEPTH {
            return Err(SdkValueError::LimitExceeded);
        }
        self.value_node()?;
        match value {
            LogValue::Int(_) | LogValue::Boolean(_) => Ok(()),
            LogValue::Double(value) => finite(*value).map(|_| ()),
            LogValue::String(value) => self.text(value.as_str(), 4096),
            LogValue::Bytes(value) => {
                if value.len() > 4096 {
                    return Err(SdkValueError::LimitExceeded);
                }
                self.bytes(value.len())
            }
            LogValue::ListAny(values) => {
                if values.len() > MAX_ARRAY_ITEMS {
                    return Err(SdkValueError::LimitExceeded);
                }
                for value in values.iter() {
                    self.log_value(value, depth + 1)?;
                }
                Ok(())
            }
            LogValue::Map(values) => {
                if values.len() > MAX_ARRAY_ITEMS {
                    return Err(SdkValueError::LimitExceeded);
                }
                // HashMap iteration scans capacity, including empty buckets.
                // Admit that finite source envelope before its first scan.
                self.bytes(
                    values
                        .capacity()
                        .saturating_mul(std::mem::size_of::<(opentelemetry::Key, LogValue)>()),
                )?;
                for (key, value) in values.iter() {
                    if key.as_str().is_empty() || key.as_str().len() > 1024 {
                        return Err(SdkValueError::InvalidAttributes);
                    }
                    self.bytes(std::mem::size_of::<KeyValue>())?;
                    self.text(key.as_str(), 1024)?;
                    self.log_value(value, depth + 1)?;
                }
                Ok(())
            }
            _ => Err(SdkValueError::InvalidAttributes),
        }
    }
}

/// Compact, prevalidated SDK resource shared by the log and span bridges.
pub(super) struct SdkResource {
    pub(super) resource: Resource,
    pub(super) schema_url: String,
    pub(super) input_bytes: usize,
    pub(super) value_nodes: usize,
}

impl SdkResource {
    pub(super) fn empty() -> Self {
        Self {
            resource: Resource::default(),
            schema_url: String::new(),
            input_bytes: std::mem::size_of::<Self>(),
            value_nodes: 0,
        }
    }

    pub(super) fn prepare(
        input: &opentelemetry_sdk::Resource,
        max_bytes: usize,
    ) -> Result<Self, SdkValueError> {
        let mut budget = ValueBudget::new(max_bytes);
        budget.bytes(std::mem::size_of::<Self>())?;
        budget.attributes(input.iter().map(|(key, value)| (key.as_str(), value)))?;
        budget.text(input.schema_url().unwrap_or_default(), 2048)?;
        Ok(Self {
            resource: Resource {
                attributes: owned_attributes(
                    input.iter().map(|(key, value)| (key.as_str(), value)),
                )?,
                ..Resource::default()
            },
            schema_url: input.schema_url().unwrap_or_default().to_owned(),
            input_bytes: budget.byte_count(),
            value_nodes: budget.node_count(),
        })
    }
}

pub(super) fn finite(value: f64) -> Result<f64, SdkValueError> {
    if value.is_finite() {
        Ok(value)
    } else {
        Err(SdkValueError::InvalidNumericValue)
    }
}

pub(super) fn nanos(time: SystemTime, zero_allowed: bool) -> Result<u64, SdkValueError> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SdkValueError::InvalidTimestamp)?;
    let nanos = u64::try_from(duration.as_nanos()).map_err(|_| SdkValueError::InvalidTimestamp)?;
    if nanos == 0 && !zero_allowed {
        return Err(SdkValueError::InvalidTimestamp);
    }
    Ok(nanos)
}

fn owned_value(value: &Value) -> Result<AnyValue, SdkValueError> {
    let value = match value {
        Value::Bool(value) => AnyValueValue::Bool(*value),
        Value::I64(value) => AnyValueValue::Int(*value),
        Value::F64(value) => AnyValueValue::Double(*value),
        Value::String(value) => AnyValueValue::String(value.as_str().to_owned()),
        Value::Array(array) => {
            let scalar = |value| AnyValue {
                value: Some(value),
                ..AnyValue::default()
            };
            let values = match array {
                Array::Bool(values) => values
                    .iter()
                    .map(|value| scalar(AnyValueValue::Bool(*value)))
                    .collect(),
                Array::I64(values) => values
                    .iter()
                    .map(|value| scalar(AnyValueValue::Int(*value)))
                    .collect(),
                Array::F64(values) => values
                    .iter()
                    .map(|value| scalar(AnyValueValue::Double(*value)))
                    .collect(),
                Array::String(values) => values
                    .iter()
                    .map(|value| scalar(AnyValueValue::String(value.as_str().to_owned())))
                    .collect(),
                _ => return Err(SdkValueError::InvalidAttributes),
            };
            AnyValueValue::Array(ArrayValue {
                values,
                ..ArrayValue::default()
            })
        }
        _ => return Err(SdkValueError::InvalidAttributes),
    };
    Ok(AnyValue {
        value: Some(value),
        ..AnyValue::default()
    })
}

/// Copy only after a complete borrowed input has passed its value budget.
pub(super) fn owned_attributes<'a>(
    attributes: impl Iterator<Item = (&'a str, &'a Value)>,
) -> Result<Vec<KeyValue>, SdkValueError> {
    let mut attributes = attributes
        .map(|(key, value)| {
            Ok(KeyValue {
                key: key.to_owned(),
                value: Some(owned_value(value)?),
                ..KeyValue::default()
            })
        })
        .collect::<Result<Vec<_>, SdkValueError>>()?;
    attributes.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(attributes)
}

pub(super) fn owned_attributes_last_wins<'a>(
    attributes: impl Iterator<Item = (&'a str, &'a Value)>,
) -> Result<Vec<KeyValue>, SdkValueError> {
    let selected: BTreeMap<_, _> = attributes.collect();
    owned_attributes(selected.into_iter())
}

pub(super) fn value_nodes(value: &AnyValue) -> usize {
    match value.value.as_ref() {
        Some(AnyValueValue::Array(array)) => array.values.iter().fold(1usize, |count, value| {
            count.saturating_add(value_nodes(value))
        }),
        Some(AnyValueValue::KeyValueList(list)) => {
            1usize.saturating_add(attribute_nodes(&list.values))
        }
        _ => 1,
    }
}

/// Map a log value only after complete borrowed collection validation.
pub(super) fn owned_log_value(value: &LogValue) -> Result<AnyValue, SdkValueError> {
    let value = match value {
        LogValue::Int(value) => AnyValueValue::Int(*value),
        LogValue::Double(value) => AnyValueValue::Double(*value),
        LogValue::String(value) => AnyValueValue::String(value.as_str().to_owned()),
        LogValue::Boolean(value) => AnyValueValue::Bool(*value),
        LogValue::Bytes(value) => AnyValueValue::Bytes(value.as_slice().to_vec()),
        LogValue::ListAny(values) => AnyValueValue::Array(ArrayValue {
            values: values
                .iter()
                .map(owned_log_value)
                .collect::<Result<Vec<_>, _>>()?,
            ..ArrayValue::default()
        }),
        LogValue::Map(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));
            AnyValueValue::KeyValueList(KeyValueList {
                values: entries
                    .into_iter()
                    .map(|(key, value)| {
                        Ok(KeyValue {
                            key: key.as_str().to_owned(),
                            value: Some(owned_log_value(value)?),
                            ..KeyValue::default()
                        })
                    })
                    .collect::<Result<Vec<_>, SdkValueError>>()?,
                ..KeyValueList::default()
            })
        }
        _ => return Err(SdkValueError::InvalidAttributes),
    };
    Ok(AnyValue {
        value: Some(value),
        ..AnyValue::default()
    })
}

pub(super) fn owned_log_attributes<'a>(
    attributes: impl Iterator<Item = (&'a str, &'a LogValue)>,
) -> Result<Vec<KeyValue>, SdkValueError> {
    let selected: BTreeMap<_, _> = attributes.collect();
    selected
        .into_iter()
        .map(|(key, value)| {
            Ok(KeyValue {
                key: key.to_owned(),
                value: Some(owned_log_value(value)?),
                ..KeyValue::default()
            })
        })
        .collect()
}

pub(super) fn attribute_nodes(attributes: &[KeyValue]) -> usize {
    attributes.iter().fold(0usize, |count, attribute| {
        count.saturating_add(attribute.value.as_ref().map_or(0, value_nodes))
    })
}
