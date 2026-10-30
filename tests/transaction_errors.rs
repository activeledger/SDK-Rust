//! How the builder reacts when a signer or a payload cannot be used.

use activeledger::canonical::CanonicalError;
use activeledger::keys::KeyError;
use activeledger::transaction::TransactionError;
use activeledger::{KeyPair, KeyType, Object, Signer, Transaction};

/// A signer that is not one of this crate's key types, as an HSM would be.
struct Fixed;

impl Signer for Fixed {
    fn key_type(&self) -> KeyType {
        KeyType::MlDsa65
    }
    fn public_key(&self) -> String {
        "pub".to_owned()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        // Echoes the message so a test can see exactly what was handed over.
        Ok(message.to_vec())
    }
}

#[test]
fn a_verify_only_key_cannot_build_a_transaction() {
    let full = KeyPair::generate().unwrap();
    let verify_only = KeyPair::from_public(&full.public_key()).unwrap();

    let result = Transaction::builder()
        .namespace("n")
        .contract("c")
        .input("s", &verify_only)
        .build();

    assert!(matches!(
        result,
        Err(TransactionError::Key(KeyError::VerifyOnly))
    ));
}

#[test]
fn a_verify_only_key_cannot_onboard() {
    let full = KeyPair::generate().unwrap();
    let verify_only = KeyPair::from_public(&full.public_key()).unwrap();

    assert!(matches!(
        Transaction::onboard(&verify_only, "identity"),
        Err(TransactionError::Key(KeyError::VerifyOnly))
    ));
}

#[test]
fn a_non_finite_payload_number_is_refused_rather_than_signed_as_null() {
    let key = KeyPair::generate().unwrap();

    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let result = Transaction::builder()
            .namespace("n")
            .contract("c")
            .input_with("s", &key, Object::new().set("v", bad))
            .build();

        assert!(
            matches!(
                result,
                Err(TransactionError::Canonical(CanonicalError::NotFinite(_)))
            ),
            "{bad}: {result:?}"
        );
    }
}

#[test]
fn a_custom_signer_receives_exactly_the_canonical_body_bytes() {
    let tx = Transaction::builder()
        .namespace("n")
        .contract("c")
        .input("stream", &Fixed)
        .build()
        .unwrap();

    // The echoing signer makes the signature the signed bytes themselves.
    use base64::{engine::general_purpose::STANDARD, Engine};
    let signed = STANDARD.decode(&tx.sigs()[0].1).unwrap();
    assert_eq!(tx.signed_bytes().unwrap(), signed);
    assert_eq!(
        r#"{"$namespace":"n","$contract":"c","$i":{"stream":{}}}"#,
        String::from_utf8(signed).unwrap()
    );
}

#[test]
fn onboard_with_a_custom_signer_uses_its_key_type_and_public_key() {
    let tx = Transaction::onboard(&Fixed, "identity").unwrap();
    let doc: serde_json::Value = serde_json::from_str(&tx.to_json().unwrap()).unwrap();

    assert_eq!(
        Some("ml-dsa-65"),
        doc["$tx"]["$i"]["identity"]["type"].as_str()
    );
    assert_eq!(
        Some("pub"),
        doc["$tx"]["$i"]["identity"]["publicKey"].as_str()
    );
}

#[test]
fn builder_errors_report_what_is_missing() {
    let key = KeyPair::generate().unwrap();
    let no_namespace = Transaction::builder()
        .contract("c")
        .input("s", &key)
        .build();
    let no_contract = Transaction::builder()
        .namespace("n")
        .input("s", &key)
        .build();
    let no_input = Transaction::builder().namespace("n").contract("c").build();

    assert_eq!(
        "namespace is required",
        no_namespace.unwrap_err().to_string()
    );
    assert_eq!("contract is required", no_contract.unwrap_err().to_string());
    assert_eq!(
        "at least one input with a signing key is required",
        no_input.unwrap_err().to_string()
    );
}
