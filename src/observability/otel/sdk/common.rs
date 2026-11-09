//! Shared bounded SDK value mapping. Callers validate a complete borrowed
//! collection before constructing any owned OTLP values.

use crate::observability::otlp_proto::common_and_resource::{
    AnyValue, AnyValueValue, ArrayValue, KeyValue,
};
use opentelemetry::{Array, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ATTRIBUTES: usize = 128;
const MAX_ARRAY_ITEMS: usize = 128;
const MAX_VALUES: usize = 65_536;

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

fn value_nodes(value: &AnyValue) -> usize {
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

pub(super) fn attribute_nodes(attributes: &[KeyValue]) -> usize {
    attributes.iter().fold(0usize, |count, attribute| {
        count.saturating_add(attribute.value.as_ref().map_or(0, value_nodes))
    })
}
