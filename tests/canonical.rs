//! Checked against the bytes the JavaScript reference produced and a real
//! ledger accepted. If this file and my reading of JSON.stringify ever
//! disagree, this file is right.

use activeledger::canonical::{self, CanonicalError};
use activeledger::{Object, Value};

mod common;

fn stringify(value: impl Into<Value>) -> String {
    canonical::to_string(&value.into()).expect("serialisable")
}

#[test]
fn ascii_baseline() {
    assert_eq!(
        common::reference("ascii"),
        stringify(Object::new().set("greeting", "hello"))
    );
}

/// `serde_json` does not escape these, but Go's encoder does and so does
/// .NET's. Both look fine until a payload contains an angle bracket.
#[test]
fn html_characters_are_not_escaped() {
    assert_eq!(
        common::reference("html"),
        stringify(
            Object::new()
                .set("expr", "a < b && c > d")
                .set("amp", "Tom & Jerry")
        )
    );
}

#[test]
fn non_ascii_is_raw() {
    let got =
        stringify(Object::new().set("greeting", "caf\u{e9} \u{65e5}\u{672c}\u{8a9e} \u{2615}"));
    assert_eq!(common::reference("non-ascii"), got);
    assert!(!got.contains("\\u00e9"));
}

/// The JavaScript number rule: one numeric type, so a whole float prints
/// without a fractional part. `serde_json` writes `1.0` here.
#[test]
fn whole_floats_print_as_integers() {
    assert_eq!(
        common::reference("float"),
        stringify(
            Object::new()
                .set("whole", 1.0)
                .set("third", 0.1)
                .set("negative", -2.5)
                .set("zero", 0)
        )
    );
}

/// The ledger does not canonicalise key order, so the signer reproduces
/// whatever order the caller built. These keys are not alphabetical, and a
/// `BTreeMap` would silently sort them.
#[test]
fn key_order_is_insertion_order_not_sorted() {
    assert_eq!(
        common::reference("ordering"),
        stringify(
            Object::new()
                .set("zebra", 1)
                .set("alpha", 2)
                .set("middle", 3)
        )
    );
}

/// Documents why this module exists rather than merely asserting behaviour:
/// if `serde_json` ever starts matching the JavaScript number rule, this
/// test says so.
#[test]
fn serde_json_still_gets_it_wrong() {
    let stdlib = serde_json::json!({ "whole": 1.0 }).to_string();
    assert_ne!(r#"{"whole":1}"#, stdlib);
    assert!(stdlib.contains("1.0"), "serde_json produced {stdlib}");
}

#[test]
fn onboard_shape_matches_reference() {
    let reference = common::reference("onboard");
    let parsed: serde_json::Value = serde_json::from_str(&reference).unwrap();
    let identity = &parsed["$i"]["identity"];

    let built = Object::new()
        .set("$namespace", "default")
        .set("$contract", "onboard")
        .set(
            "$i",
            Object::new().set(
                "identity",
                Object::new()
                    .set("type", identity["type"].as_str().unwrap())
                    .set("publicKey", identity["publicKey"].as_str().unwrap()),
            ),
        )
        .set("$o", Object::new());

    assert_eq!(reference, stringify(built));
}

#[test]
fn nested_structures_arrays_and_null() {
    let built = Object::new()
        .set(
            "a",
            Value::Array(vec![
                Value::Integer(1),
                Value::from("two"),
                Value::Bool(true),
                Value::Null,
            ]),
        )
        .set("b", Object::new().set("c", false));

    assert_eq!(
        r#"{"a":[1,"two",true,null],"b":{"c":false}}"#,
        stringify(built)
    );
}

#[test]
fn empty_containers() {
    assert_eq!("{}", stringify(Object::new()));
    assert_eq!("[]", canonical::to_string(&Value::Array(vec![])).unwrap());
}

#[test]
fn escapes_only_what_json_requires() {
    assert_eq!(
        r#"{"s":"a\"b\\c"}"#,
        stringify(Object::new().set("s", "a\"b\\c"))
    );
}

#[test]
fn control_characters() {
    // Both the input and the expected output are BUILT rather than written
    // as literals. A control character written as an escape sequence gets
    // helpfully converted into the character itself by an editor or a shell,
    // and the test then asserts the exact opposite of what it means - which
    // is how this test first passed against a serialiser that was correct.
    let ctrl = char::from_u32(1).unwrap();
    let built = Object::new().set("s", format!("\n\t{ctrl}"));

    let escaped = format!("\\u{:04x}", 1u32);
    let expected = format!("{{\"s\":\"\\n\\t{escaped}\"}}");

    assert_eq!(expected, stringify(built));
}

/// `JSON.stringify` emits `null` for these, which would sign bytes the
/// caller never intended.
#[test]
fn nan_and_infinity_refused() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let result = canonical::to_string(&Value::Object(Object::new().set("x", bad)));
        assert!(
            matches!(result, Err(CanonicalError::NotFinite(_))),
            "{bad} was accepted"
        );
    }
}

#[test]
fn replacing_a_key_keeps_its_position() {
    assert_eq!(
        r#"{"a":3,"b":2}"#,
        stringify(Object::new().set("a", 1).set("b", 2).set("a", 3))
    );
}

#[test]
fn bytes_are_utf8_of_the_string() {
    let built = Value::Object(Object::new().set("e", "\u{e9}"));
    assert_eq!(
        canonical::to_string(&built).unwrap().into_bytes(),
        canonical::to_bytes(&built).unwrap()
    );
    assert_eq!(10, canonical::to_bytes(&built).unwrap().len());
}

/// Large integers survive exactly. An f64-only number type would round
/// these, and a stream id that comes back subtly different is the kind of
/// bug that takes a day to find.
#[test]
fn large_integers_keep_their_precision() {
    let built = Object::new().set("big", 9_007_199_254_740_993_i64);
    assert_eq!(r#"{"big":9007199254740993}"#, stringify(built));
}
