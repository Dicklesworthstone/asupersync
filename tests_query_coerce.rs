use std::collections::HashMap;
use serde::Deserialize;

fn coerce_json_scalar(raw: &str) -> serde_json::Value {
    if let Ok(boolean) = raw.parse::<bool>() {
        return serde_json::Value::Bool(boolean);
    }
    if let Ok(integer) = raw.parse::<i64>() {
        return serde_json::Value::Number(integer.into());
    }
    if let Ok(unsigned) = raw.parse::<u64>() {
        return serde_json::Value::Number(unsigned.into());
    }
    if let Ok(float) = raw.parse::<f64>() {
        if let Some(number) = serde_json::Number::from_f64(float) {
            return serde_json::Value::Number(number);
        }
    }
    serde_json::Value::String(raw.to_string())
}

fn deserialize_from_string_map<T: serde::de::DeserializeOwned>(
    values: &HashMap<String, String>,
) -> Result<T, String> {
    let as_strings = serde_json::Value::Object(
        values
            .iter()
            .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
            .collect(),
    );
    if let Ok(parsed) = serde_json::from_value::<T>(as_strings) {
        return Ok(parsed);
    }

    let as_coerced = serde_json::Value::Object(
        values
            .iter()
            .map(|(key, value)| (key.clone(), coerce_json_scalar(value)))
            .collect(),
    );
    serde_json::from_value::<T>(as_coerced).map_err(|e| e.to_string())
}

#[derive(Deserialize, Debug)]
struct Foo {
    name: String,
    age: u32,
}

fn main() {
    let mut map = HashMap::new();
    map.insert("name".to_string(), "true".to_string());
    map.insert("age".to_string(), "25".to_string());
    
    let res: Result<Foo, _> = deserialize_from_string_map(&map);
    println!("Result: {:?}", res);
}
