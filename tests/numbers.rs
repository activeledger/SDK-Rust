//! Canonical number formatting, against the published vectors.
//!
//! What gets signed is `JSON.stringify($tx)` and the ledger verifies against a
//! re-stringified `$tx`, so JavaScript's number formatting is the
//! specification. A number written differently produces a signature the ledger
//! rejects as 1220, with nothing in the message about numbers.
//!
//! These exist because the `float` case in pq-vectors.json - 1, 0.1, -2.5, 0 -
//! sits entirely inside the range where every language already agrees.

use activeledger::canonical::{js_number, to_string, Object};

fn vectors() -> Vec<(String, f64, String)> {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/number-vectors.json"
    ))
    .expect("number-vectors.json");
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("number vector json");

    doc["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .map(|v| {
            (
                v["name"].as_str().unwrap().to_string(),
                v["value"].as_f64().unwrap(),
                v["expected"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn the_vector_file_is_not_empty() {
    assert!(
        !vectors().is_empty(),
        "the tests below would pass by not running"
    );
}

#[test]
fn js_number_matches_the_reference() {
    for (name, value, expected) in vectors() {
        assert_eq!(js_number(value), expected, "{name}");
    }
}

/// The formatter being right is not enough if the encoder does not call it.
#[test]
fn the_encoder_uses_it() {
    for (name, value, expected) in vectors() {
        let encoded = to_string(&Object::new().set("n", value).into()).expect("encode");
        assert_eq!(encoded, format!("{{\"n\":{expected}}}"), "{name}");
    }
}

#[test]
fn negative_zero_loses_its_sign() {
    assert_eq!(js_number(-0.0), "0");
}

/// Display never used exponent form, so these printed in full.
#[test]
fn exponent_form_is_used_outside_the_plain_range() {
    assert_eq!(js_number(1e21), "1e+21");
    assert_eq!(js_number(1e-7), "1e-7");
    assert_eq!(js_number(-1.5e-9), "-1.5e-9");
}

/// Both sides of both boundaries - where implementations part company.
#[test]
fn the_plain_exponent_boundaries() {
    assert_eq!(js_number(1e20), "100000000000000000000");
    assert_eq!(js_number(1e21), "1e+21");
    assert_eq!(js_number(1e-6), "0.000001");
    assert_eq!(js_number(1e-7), "1e-7");
}

/// `value as i64` SATURATES in Rust, so 1e20 used to print as i64::MAX.
#[test]
fn large_whole_values_no_longer_saturate_to_i64_max() {
    assert_ne!(js_number(1e20), "9223372036854775807");
    assert_ne!(js_number(1e19), "9223372036854775807");
    assert_eq!(js_number(1e19), "10000000000000000000");
}
