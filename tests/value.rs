//! `Value` and `Object` as a caller meets them: the `From` conversions the
//! builder methods lean on, the `Object` accessors, and canonical output for
//! values the vector files do not reach.

use activeledger::canonical::{self, CanonicalError};
use activeledger::{Object, Value};

fn stringify(value: impl Into<Value>) -> String {
    canonical::to_string(&value.into()).expect("serialisable")
}

#[test]
fn scalar_conversions_pick_the_matching_variant() {
    assert_eq!(Value::String("a".into()), Value::from("a"));
    assert_eq!(Value::String("b".into()), Value::from(String::from("b")));
    assert_eq!(Value::Bool(true), Value::from(true));
    assert_eq!(Value::Number(2.5), Value::from(2.5_f64));
    assert_eq!(Value::Integer(-7), Value::from(-7_i64));
    assert_eq!(Value::Integer(-7), Value::from(-7_i32));
}

/// A u32 above i32::MAX must not wrap negative on its way to an i64.
#[test]
fn u32_widens_without_wrapping() {
    assert_eq!(Value::Integer(4_294_967_295), Value::from(u32::MAX));
    assert_eq!("4294967295", stringify(u32::MAX));
}

/// An integer stays an integer, a float stays a float: the variant decides
/// the formatting path, so `2.0` and `2` land on the same bytes only because
/// the number formatter says so.
#[test]
fn integers_and_whole_floats_print_alike_but_are_distinct_values() {
    assert_ne!(Value::from(2_i64), Value::from(2.0_f64));
    assert_eq!(stringify(2_i64), stringify(2.0_f64));
}

#[test]
fn option_converts_to_null_or_the_inner_value() {
    assert_eq!(Value::Null, Value::from(None::<i32>));
    assert_eq!(Value::Integer(3), Value::from(Some(3_i32)));
    assert_eq!("null", stringify(None::<String>));
    assert_eq!("\"x\"", stringify(Some("x")));
}

#[test]
fn vectors_convert_element_by_element_including_nested_ones() {
    assert_eq!(
        Value::Array(vec![Value::Integer(1), Value::Integer(2)]),
        Value::from(vec![1_i32, 2])
    );
    assert_eq!(
        "[[1,2],[],[3]]",
        stringify(vec![vec![1_i32, 2], vec![], vec![3]])
    );
    assert_eq!("[1,null,3]", stringify(vec![Some(1_i32), None, Some(3)]));
}

#[test]
fn an_object_converts_into_an_object_value() {
    let object = Object::new().set("k", 1);
    assert_eq!(Value::Object(object.clone()), Value::from(object));
}

#[test]
fn object_accessors_report_contents_in_insertion_order() {
    let mut object = Object::new();
    assert!(object.is_empty());
    assert_eq!(0, object.len());
    assert!(object.get("a").is_none());
    assert!(!object.contains_key("a"));

    object.insert("zebra", 1);
    object.insert("apple", "two");

    assert!(!object.is_empty());
    assert_eq!(2, object.len());
    assert_eq!(["zebra", "apple"], object.keys());
    assert!(object.contains_key("apple"));
    assert_eq!(Some(&Value::Integer(1)), object.get("zebra"));
    assert_eq!(Some(&Value::String("two".into())), object.get("apple"));
}

/// Replacing a key changes its value, not the count and not the key list.
#[test]
fn replacing_a_key_does_not_grow_the_object() {
    let object = Object::new().set("a", 1).set("b", 2).set("a", 9);

    assert_eq!(2, object.len());
    assert_eq!(["a", "b"], object.keys());
    assert_eq!(Some(&Value::Integer(9)), object.get("a"));
}

/// Objects compare by content including order, since order is what gets
/// signed.
#[test]
fn objects_with_the_same_pairs_in_a_different_order_are_unequal() {
    let ab = Object::new().set("a", 1).set("b", 2);
    let ba = Object::new().set("b", 2).set("a", 1);

    assert_ne!(ab, ba);
    assert_ne!(stringify(ab), stringify(ba));
}

#[test]
fn keys_are_escaped_like_strings() {
    let object = Object::new().set("a\"b\n", 1).set("", 2);
    assert_eq!(r#"{"a\"b\n":1,"":2}"#, stringify(object));
}

#[test]
fn integer_extremes_print_exactly() {
    assert_eq!("9223372036854775807", stringify(i64::MAX));
    assert_eq!("-9223372036854775808", stringify(i64::MIN));
}

#[test]
fn float_values_use_javascript_formatting_inside_values() {
    assert_eq!("0", stringify(-0.0_f64));
    assert_eq!("1e+21", stringify(1e21_f64));
    assert_eq!("1e-7", stringify(1e-7_f64));
    assert_eq!("100000000000000000000", stringify(1e20_f64));
}

/// JSON.stringify leaves DEL and the Unicode line separators alone, so the
/// bytes signed contain them raw.
#[test]
fn del_and_line_separators_pass_through_raw() {
    assert_eq!(
        "\"\u{7f}\u{2028}\u{2029}\"",
        stringify("\u{7f}\u{2028}\u{2029}")
    );
}

#[test]
fn the_last_control_character_is_escaped_in_lowercase_hex() {
    assert_eq!(r#""\u001f""#, stringify("\u{1f}"));
    assert_eq!(r#""\u0000""#, stringify("\u{0}"));
}

#[test]
fn a_non_finite_number_nested_anywhere_is_refused() {
    let nested = Object::new().set(
        "outer",
        vec![Value::Object(Object::new().set("n", f64::NAN))],
    );
    assert_eq!(
        Err(CanonicalError::NotFinite("NaN")),
        canonical::to_string(&nested.into())
    );

    let inside_array = Value::Array(vec![Value::Integer(1), Value::Number(f64::NEG_INFINITY)]);
    assert_eq!(
        Err(CanonicalError::NotFinite("Infinity")),
        canonical::to_bytes(&inside_array)
    );
}

#[test]
fn the_not_finite_error_names_the_offending_value() {
    let error = canonical::to_string(&Value::Number(f64::INFINITY)).unwrap_err();
    assert_eq!("Infinity cannot be signed", error.to_string());
}

#[test]
fn deep_nesting_serialises_without_losing_structure() {
    let mut value = Value::Integer(1);
    for _ in 0..200 {
        value = Value::Array(vec![value]);
    }
    let text = canonical::to_string(&value).expect("serialisable");

    assert_eq!(format!("{}1{}", "[".repeat(200), "]".repeat(200)), text);
}
