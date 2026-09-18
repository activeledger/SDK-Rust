//! The envelope shape, and the exact bytes covered by a signature.
//!
//! Everything here is checked by verifying with the public key rather than
//! by comparing signature bytes. Signing is hedged, so byte comparison would
//! fail against a correct implementation.

use base64::{engine::general_purpose::STANDARD, Engine};

use activeledger::transaction::TransactionError;
use activeledger::{KeyPair, Object, Transaction};

fn key() -> KeyPair {
    KeyPair::generate().expect("generate")
}

fn json(tx: &Transaction) -> serde_json::Value {
    serde_json::from_str(&tx.to_json().expect("serialise")).expect("valid json")
}

#[test]
fn onboard_carries_type_selfsign_and_label_keyed_sigs() {
    let key = key();
    let tx = Transaction::onboard(&key, "identity").expect("onboard");
    let doc = json(&tx);

    assert_eq!(Some(true), doc["$selfsign"].as_bool());

    let identity = &doc["$tx"]["$i"]["identity"];
    assert_eq!(Some("ml-dsa-65"), identity["type"].as_str());
    assert_eq!(
        Some(key.public_key().as_str()),
        identity["publicKey"].as_str()
    );

    // Keyed by the $i LABEL, not a stream id: there is no stream yet.
    assert!(doc["$sigs"]["identity"].is_string());
}

#[test]
fn onboard_signature_covers_the_tx_object_and_nothing_else() {
    let key = key();
    let tx = Transaction::onboard(&key, "identity").unwrap();

    let signature = STANDARD.decode(&tx.sigs()[0].1).unwrap();
    assert!(key.verify(&tx.signed_bytes().unwrap(), &signature));

    // signed_bytes is $tx alone. The envelope is strictly longer, and signing
    // IT is the single most common porting mistake.
    let envelope = tx.to_json().unwrap().into_bytes();
    assert!(envelope.len() > tx.signed_bytes().unwrap().len());
    assert!(!key.verify(&envelope, &signature));
}

#[test]
fn onboard_label_is_configurable() {
    let tx = Transaction::onboard(&key(), "owner").unwrap();
    assert_eq!("owner", tx.sigs()[0].0);
    assert!(json(&tx)["$tx"]["$i"]["owner"].is_object());
}

#[test]
fn built_transaction_has_no_selfsign_key_at_all() {
    let key = key();
    let tx = Transaction::builder()
        .namespace("default")
        .contract("transfer")
        .input("streamid", &key)
        .build()
        .unwrap();

    // Not "false" -- absent. $selfsign: false on a normal transaction changes
    // the signed bytes for no reason.
    assert!(json(&tx)["$selfsign"].is_null());
    assert!(!tx.is_self_signed());
}

#[test]
fn key_order_follows_insertion_not_alphabet() {
    let key = key();
    let tx = Transaction::builder()
        .namespace("zz")
        .contract("aa")
        .entry("mm")
        .input("sid", &key)
        .build()
        .unwrap();

    // $entry first, then $namespace, $contract, $i -- the order the JS SDK
    // writes, which is what the reference signs.
    let body = String::from_utf8(tx.signed_bytes().unwrap()).unwrap();
    assert!(
        body.starts_with(r#"{"$entry":"mm","$namespace":"zz","$contract":"aa","$i":"#),
        "{body}"
    );
}

#[test]
fn optional_sections_are_omitted_when_empty() {
    let key = key();
    let tx = Transaction::builder()
        .namespace("default")
        .contract("noop")
        .input("sid", &key)
        .build()
        .unwrap();

    let body = String::from_utf8(tx.signed_bytes().unwrap()).unwrap();
    assert!(!body.contains("$o"));
    assert!(!body.contains("$r"));
    assert!(!body.contains("$entry"));
}

#[test]
fn readonly_streams_land_in_dollar_r() {
    let key = key();
    let tx = Transaction::builder()
        .namespace("default")
        .contract("fetch")
        .input("sid", &key)
        .readonly("target", "otherstream")
        .build()
        .unwrap();

    assert_eq!(
        Some("otherstream"),
        json(&tx)["$tx"]["$r"]["target"].as_str()
    );
}

#[test]
fn every_signer_signs_the_same_bytes() {
    let a = key();
    let b = key();
    let tx = Transaction::builder()
        .namespace("default")
        .contract("multi")
        .input("streamA", &a)
        .input("streamB", &b)
        .output("streamC")
        .build()
        .unwrap();

    let message = tx.signed_bytes().unwrap();
    assert_eq!(2, tx.sigs().len());
    assert!(a.verify(&message, &STANDARD.decode(&tx.sigs()[0].1).unwrap()));
    assert!(b.verify(&message, &STANDARD.decode(&tx.sigs()[1].1).unwrap()));
}

#[test]
fn sigs_appear_in_the_order_inputs_were_added() {
    let a = key();
    let b = key();
    let tx = Transaction::builder()
        .namespace("default")
        .contract("multi")
        .input("zebra", &a)
        .input("alpha", &b)
        .build()
        .unwrap();

    assert_eq!("zebra", tx.sigs()[0].0);
    assert_eq!("alpha", tx.sigs()[1].0);

    let envelope = tx.to_json().unwrap();
    assert!(envelope.find("zebra\":\"").unwrap() < envelope.find("alpha\":\"").unwrap());
}

#[test]
fn re_adding_an_input_replaces_its_key_without_duplicating_the_signature() {
    let first = key();
    let replacement = key();
    let tx = Transaction::builder()
        .namespace("default")
        .contract("c")
        .input("sid", &first)
        .input("sid", &replacement)
        .build()
        .unwrap();

    assert_eq!(1, tx.sigs().len());
    let signature = STANDARD.decode(&tx.sigs()[0].1).unwrap();
    assert!(replacement.verify(&tx.signed_bytes().unwrap(), &signature));
    assert!(!first.verify(&tx.signed_bytes().unwrap(), &signature));
}

#[test]
fn input_payload_fields_survive_into_the_signed_body() {
    let key = key();
    let tx = Transaction::builder()
        .namespace("default")
        .contract("transfer")
        .input_with("sid", &key, Object::new().set("amount", 100))
        .build()
        .unwrap();

    let body = String::from_utf8(tx.signed_bytes().unwrap()).unwrap();
    assert!(body.contains(r#""amount":100"#), "{body}");
}

#[test]
fn build_refuses_a_transaction_with_no_namespace() {
    let key = key();
    let result = Transaction::builder()
        .contract("c")
        .input("sid", &key)
        .build();
    assert!(matches!(result, Err(TransactionError::MissingNamespace)));
}

#[test]
fn build_refuses_a_transaction_with_no_contract() {
    let key = key();
    let result = Transaction::builder()
        .namespace("default")
        .input("sid", &key)
        .build();
    assert!(matches!(result, Err(TransactionError::MissingContract)));
}

/// A transaction with no signer would serialise perfectly and be rejected by
/// the ledger with a message about signatures.
#[test]
fn build_refuses_a_transaction_with_no_input() {
    let result = Transaction::builder()
        .namespace("default")
        .contract("c")
        .build();
    assert!(matches!(result, Err(TransactionError::MissingInput)));
}

#[test]
fn envelope_is_rebuilt_identically_each_time() {
    let tx = Transaction::onboard(&key(), "identity").unwrap();
    assert_eq!(tx.to_json().unwrap(), tx.to_json().unwrap());
}
