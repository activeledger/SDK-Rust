//! Canonical JSON: the exact bytes Activeledger signs.
//!
//! Signatures cover the bytes of `JSON.stringify($tx)` encoded as UTF-8 --
//! no hash prefix, no length prefix, no domain separator and **no key
//! sorting**. A signature over bytes that differ by a single escape is
//! invalid, and the ledger reports that as 1220 "Signature Incorrect",
//! which says nothing at all about serialisation.
//!
//! `serde_json` cannot produce these bytes. Its map is a `BTreeMap` that
//! sorts keys unless the crate-wide `preserve_order` feature is on -- and
//! turning that on from a library would silently change `serde_json`'s
//! behaviour for everything else in the consumer's binary. It also writes
//! `1.0` where JavaScript writes `1`. So this module owns the format.

use std::collections::HashMap;
use std::fmt::Write as _;

/// A JSON value that can be serialised canonically.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// An exact integer. Kept separate from `Number` so that stream ids and
    /// other large values do not lose precision on the way through an f64.
    Integer(i64),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(Object),
}

/// A JSON object that preserves insertion order.
///
/// Order is not a stylistic choice here. The ledger does not canonicalise
/// key order, so a signer has to reproduce the order the caller wrote.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Object {
    keys: Vec<String>,
    values: HashMap<String, Value>,
}

impl Object {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a key. A replaced key keeps its original position.
    pub fn set(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.insert(key, value);
        self
    }

    /// The same as [`Object::set`], for when chaining does not suit.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        let key = key.into();
        if !self.values.contains_key(&key) {
            self.keys.push(key.clone());
        }
        self.values.insert(key, value.into());
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.values.get(key)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    /// Keys in insertion order.
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn entries(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.keys.iter().map(move |k| (k, &self.values[k]))
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_owned())
    }
}
impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::String(v)
    }
}
impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Integer(v)
    }
}
impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Integer(v as i64)
    }
}
impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Value::Integer(v as i64)
    }
}
impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Number(v)
    }
}
impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}
impl From<Object> for Value {
    fn from(v: Object) -> Self {
        Value::Object(v)
    }
}
impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Value::Array(v.into_iter().map(Into::into).collect())
    }
}
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(inner) => inner.into(),
            None => Value::Null,
        }
    }
}

/// A value that cannot be represented in the bytes the ledger signs.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CanonicalError {
    /// `JSON.stringify` turns these into `null`, which would sign bytes the
    /// caller never intended. Refused instead.
    #[error("{0} cannot be signed")]
    NotFinite(&'static str),
}

/// Serialises to the exact string the ledger expects.
pub fn to_string(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

/// The exact bytes that get signed.
pub fn to_bytes(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    to_string(value).map(String::into_bytes)
}

fn write_value(out: &mut String, value: &Value) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Integer(i) => {
            let _ = write!(out, "{i}");
        }
        Value::Number(f) => write_number(out, *f)?,
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(obj) => {
            out.push('{');
            for (i, (key, val)) in obj.entries().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, val)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// JavaScript number formatting: one numeric type, shortest representation
/// that round-trips. `JSON.stringify(1.0)` is `1`.
fn write_number(out: &mut String, value: f64) -> Result<(), CanonicalError> {
    if value.is_nan() {
        return Err(CanonicalError::NotFinite("NaN"));
    }
    if value.is_infinite() {
        return Err(CanonicalError::NotFinite("Infinity"));
    }

    // Rust's Display for f64 is already shortest-round-trip and prints 1.0
    // as "1", which is what JavaScript does. It differs above 1e21, where
    // JavaScript switches to exponential notation and Rust does not.
    if value == value.trunc() && value.abs() < 1e21 {
        let _ = write!(out, "{}", value as i64);
    } else {
        let _ = write!(out, "{value}");
    }
    Ok(())
}

/// Escapes exactly what `JSON.stringify` escapes: the two characters JSON
/// requires plus control characters below 0x20. Everything else, including
/// all non-ASCII, passes through as raw UTF-8.
fn write_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
