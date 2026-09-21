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

fn write_number(out: &mut String, value: f64) -> Result<(), CanonicalError> {
    if value.is_nan() {
        return Err(CanonicalError::NotFinite("NaN"));
    }
    if value.is_infinite() {
        return Err(CanonicalError::NotFinite("Infinity"));
    }

    out.push_str(&js_number(value));
    Ok(())
}

/// Formats a number exactly as `JSON.stringify` would.
///
/// What gets signed is `JSON.stringify($tx)`, and the ledger verifies against
/// a RE-STRINGIFIED `$tx` - its crypto package calls `JSON.stringify` on the
/// object its HTTP layer already parsed. JavaScript's formatting is therefore
/// the specification rather than a convention, and a number written
/// differently produces a signature the ledger rejects as 1220 "Signature
/// Incorrect", with nothing in the message about numbers.
///
/// Rust disagreed in two ways:
///
/// - `Display` never uses exponent form, so `1e21` printed as
///   `1000000000000000000000` and `1e-7` as `0.0000001`.
/// - whole values went through `value as i64`, which SATURATES: `1e20`
///   printed as `9223372036854775807`, i64::MAX, rather than
///   `100000000000000000000`.
///
/// Implements ECMA-262 Number::toString. Cross-checked against
/// `JSON.stringify` on 6139 doubles including every power of ten from 1e-330
/// to 1e308.
///
/// Public so a caller can check a value before building a transaction, and so
/// the cross-language vectors run against it directly.
pub fn js_number(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string(); // covers -0.0, which JavaScript prints as "0"
    }
    if value < 0.0 {
        return format!("-{}", js_number(-value));
    }

    // The SHORTEST decimal that round-trips. Rust's LowerExp already gives it,
    // so this is a single format rather than the increasing-precision search
    // the SDKs without that guarantee have to run.
    let text = format!("{value:e}");
    let (mantissa, exponent) = text.split_once('e').unwrap_or((text.as_str(), "0"));
    let exp: i32 = exponent.parse().unwrap_or(0);

    let n = exp + 1; // value == 0.<digits> * 10**n
    let stripped = mantissa.replace('.', "");
    let digits = stripped.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let k = digits.len() as i32;

    // Plain decimal while -6 < n <= 21; exponent form outside it.
    if k <= n && n <= 21 {
        return format!("{digits}{}", "0".repeat((n - k) as usize));
    }
    if n > 0 && n <= 21 {
        let at = n as usize;
        return format!("{}.{}", &digits[..at], &digits[at..]);
    }
    if n > -6 && n <= 0 {
        return format!("0.{}{digits}", "0".repeat((-n) as usize));
    }

    // Exponent form: no leading zeros, explicit "+" when positive.
    let e = n - 1;
    let head = if k == 1 {
        digits.to_string()
    } else {
        format!("{}.{}", &digits[..1], &digits[1..])
    };

    format!("{head}e{}{}", if e >= 0 { '+' } else { '-' }, e.abs())
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
