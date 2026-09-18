//! Conformance against the vectors published by the ledger repository.
//!
//! This is what makes "done" an observation rather than an assertion: the
//! signatures here were produced by the reference implementation and
//! accepted by a real network, so agreeing with them is agreeing with the
//! thing that matters.
//!
//! Signing is not reproducible. The reference signs hedged -- fresh entropy
//! on every call -- so two signatures over one message differ, and this SDK
//! matches that. What must hold is that signatures cross in both directions.

use base64::{engine::general_purpose::STANDARD, Engine};

use activeledger::keys::{
    ML_DSA_65_PRIVATE_KEY_SIZE, ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE,
};
use activeledger::{KeyError, KeyPair, KeyType, Signer};

mod common;

fn decode(value: &str) -> Vec<u8> {
    STANDARD.decode(value).expect("base64")
}

/// A file that silently lost a scheme would let everything below pass while
/// covering half of what it claims.
#[test]
fn the_vector_file_has_both_schemes() {
    let all = common::all();
    assert!(all.iter().any(|v| v.key_type == "ml-dsa-65"));
    assert!(all.iter().any(|v| v.key_type == "falcon-512"));
    assert!(
        all.len() >= 12,
        "expected at least 12 vectors, found {}",
        all.len()
    );
    assert_eq!(6, common::ml_dsa().count());
}

#[test]
fn verifies_every_published_signature() {
    for v in common::ml_dsa() {
        let key = KeyPair::from_public(&v.public_key).expect("public key");
        assert!(
            key.verify(v.message.as_bytes(), &decode(&v.signature)),
            "failed to verify published ml-dsa-65/{}",
            v.message_name
        );
    }
}

#[test]
fn round_trips_published_keys_without_re_deriving() {
    for v in common::ml_dsa() {
        let key = KeyPair::from_keys(&v.public_key, &v.private_key).expect("key pair");
        assert_eq!(v.public_key, key.public_key());
        assert_eq!(Some(v.private_key.clone()), key.private_key());
    }
}

#[test]
fn signatures_made_here_verify_with_the_reference_public_key() {
    for v in common::ml_dsa() {
        let signer = KeyPair::from_keys(&v.public_key, &v.private_key).expect("key pair");
        let mine = signer.sign(v.message.as_bytes()).expect("sign");

        let verifier = KeyPair::from_public(&v.public_key).expect("public key");
        assert!(
            verifier.verify(v.message.as_bytes(), &mine),
            "reference key rejected a signature made here ({})",
            v.message_name
        );
    }
}

/// Deliberately NOT byte equality. The reference is hedged, so matching it
/// means being unable to reproduce it -- and a signer that DID reproduce it
/// would be deterministic, a different security posture adopted by accident.
#[test]
fn signing_is_hedged_so_two_signatures_differ() {
    for v in common::ml_dsa().take(3) {
        let key = KeyPair::from_keys(&v.public_key, &v.private_key).expect("key pair");
        let first = key.sign(v.message.as_bytes()).unwrap();
        let second = key.sign(v.message.as_bytes()).unwrap();
        assert_ne!(first, second);

        // Both must still verify: differing is only correct if both are valid.
        assert!(key.verify(v.message.as_bytes(), &first));
        assert!(key.verify(v.message.as_bytes(), &second));
    }
}

#[test]
fn signature_length_matches_the_scheme() {
    for v in common::ml_dsa() {
        let key = KeyPair::from_keys(&v.public_key, &v.private_key).unwrap();
        assert_eq!(
            ML_DSA_65_SIGNATURE_SIZE,
            key.sign(v.message.as_bytes()).unwrap().len()
        );
    }
}

#[test]
fn tampered_message_does_not_verify() {
    for v in common::ml_dsa() {
        let key = KeyPair::from_public(&v.public_key).unwrap();
        let mut tampered = v.message.clone().into_bytes();
        tampered.push(b' ');
        assert!(!key.verify(&tampered, &decode(&v.signature)));
    }
}

/// A caller checking a signature wants a yes or a no. A signature of the
/// wrong length is simply a no, not a panic.
#[test]
fn malformed_signature_returns_false_rather_than_panicking() {
    let v = common::ml_dsa().next().unwrap();
    let key = KeyPair::from_public(&v.public_key).unwrap();

    assert!(!key.verify(v.message.as_bytes(), &[]));
    assert!(!key.verify(v.message.as_bytes(), &[0u8; 10]));
    assert!(!key.verify(v.message.as_bytes(), &[0u8; ML_DSA_65_SIGNATURE_SIZE]));
    assert!(!key.verify(&[], &decode(&v.signature)));
}

/// A Falcon signature is a different length entirely, so this also checks
/// the length guard rather than the maths.
#[test]
fn a_falcon_signature_does_not_verify_as_ml_dsa() {
    let mldsa = common::ml_dsa().next().unwrap();
    let falcon = common::all()
        .iter()
        .find(|v| v.key_type == "falcon-512")
        .unwrap();

    let key = KeyPair::from_public(&mldsa.public_key).unwrap();
    assert!(!key.verify(mldsa.message.as_bytes(), &decode(&falcon.signature)));
}

#[test]
fn generated_keys_have_the_documented_lengths() {
    let key = KeyPair::generate().expect("generate");
    assert_eq!(ML_DSA_65_PUBLIC_KEY_SIZE, decode(&key.public_key()).len());
    assert_eq!(
        ML_DSA_65_PRIVATE_KEY_SIZE,
        decode(&key.private_key().unwrap()).len()
    );
}

#[test]
fn freshly_generated_keys_verify_their_own_signatures() {
    let key = KeyPair::generate().unwrap();
    let message = b"round trip";
    assert!(key.verify(message, &key.sign(message).unwrap()));
}

#[test]
fn verify_only_key_pair_refuses_to_sign() {
    let v = common::ml_dsa().next().unwrap();
    let key = KeyPair::from_public(&v.public_key).unwrap();

    assert!(!key.can_sign());
    assert!(key.private_key().is_none());
    assert!(matches!(key.sign(b"anything"), Err(KeyError::VerifyOnly)));
}

#[test]
fn wrong_length_key_is_rejected_at_construction_with_both_numbers() {
    let too_short = STANDARD.encode([0u8; 100]);
    let error = KeyPair::from_public(&too_short).unwrap_err();

    let message = error.to_string();
    assert!(message.contains("100"), "{message}");
    assert!(message.contains("1952"), "{message}");
}

#[test]
fn non_base64_key_says_so_rather_than_reporting_a_length() {
    let error = KeyPair::from_public("this is not base64!!").unwrap_err();
    assert!(matches!(error, KeyError::NotBase64 { .. }), "{error}");
}

/// Garbage of the RIGHT length is accepted, and that is not a defect to
/// fix here.
///
/// An ML-DSA-65 public key is a seed plus packed 10-bit coefficients, with
/// no checksum and no redundancy, so very nearly any 1952 bytes decode to
/// *some* key. There is nothing to validate against. The failure therefore
/// surfaces where it can be detected at all -- verification returns false --
/// rather than at construction.
///
/// Worth stating in a test, because the natural assumption is that a
/// constructor which accepts the bytes has checked them.
#[test]
fn right_length_garbage_is_accepted_and_fails_at_verification() {
    let bogus = STANDARD.encode([0xFFu8; ML_DSA_65_PUBLIC_KEY_SIZE]);
    let key = KeyPair::from_public(&bogus).expect("no redundancy to reject it");

    let real = common::ml_dsa().next().unwrap();
    assert!(!key.verify(real.message.as_bytes(), &decode(&real.signature)));
}

#[test]
fn key_type_wire_strings_are_exact() {
    assert_eq!("rsa", KeyType::Rsa.as_wire());
    assert_eq!("secp256k1", KeyType::Secp256k1.as_wire());
    assert_eq!("ml-dsa-65", KeyType::MlDsa65.as_wire());
    assert_eq!("falcon-512", KeyType::Falcon512.as_wire());

    assert_eq!(KeyType::MlDsa65, KeyType::from_wire("ml-dsa-65").unwrap());
    assert!(KeyType::from_wire("ML-DSA-65").is_err());

    assert!(KeyType::MlDsa65.is_post_quantum());
    assert!(KeyType::Falcon512.is_post_quantum());
    assert!(!KeyType::Rsa.is_post_quantum());
}

/// A KeyPair here is always ML-DSA-65. If that ever stops being true, the
/// transaction builder's `type` field silently starts lying.
#[test]
fn key_pair_reports_ml_dsa_as_its_type() {
    assert_eq!(KeyType::MlDsa65, KeyPair::generate().unwrap().key_type());
}

/// Debug output must never carry private key material: it ends up in logs.
#[test]
fn debug_output_does_not_leak_the_private_key() {
    let key = KeyPair::generate().unwrap();
    let rendered = format!("{key:?}");

    assert!(!rendered.contains(&key.private_key().unwrap()));
    assert!(!rendered.contains(&key.public_key()));
    assert_eq!("KeyPair(ml-dsa-65, public+private)", rendered);
}
