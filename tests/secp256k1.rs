//! secp256k1 conformance against the published cross-language vectors.
//!
//! Its encoding has nothing in common with the post-quantum schemes, and every
//! test here exists because reusing the base64 path produces material the
//! ledger rejects as 1220 "Signature Incorrect" while saying nothing else.

use base64::{engine::general_purpose::STANDARD, Engine};

use activeledger::keys::{KeyError, KeyType, Signer};
use activeledger::secp256k1::{self, Secp256k1KeyPair};

mod common;

fn decode(value: &str) -> Vec<u8> {
    STANDARD.decode(value).expect("base64")
}

#[test]
fn both_public_key_forms_are_present_in_the_vectors() {
    // The ledger accepts either, so a port that only ever sees one never
    // learns to read the other.
    let all: Vec<_> = common::secp256k1().collect();
    assert!(all.iter().any(|v| v.public_key_form == "compressed"));
    assert!(all.iter().any(|v| v.public_key_form == "uncompressed"));
    assert!(all.len() >= 12, "expected at least 12, found {}", all.len());
}

#[test]
fn verifies_every_published_signature() {
    for v in common::secp256k1() {
        let key = Secp256k1KeyPair::from_public(&v.public_key).expect("public key");
        assert!(
            key.verify(v.message.as_bytes(), &decode(&v.signature)),
            "failed to verify published secp256k1/{}/{}",
            v.message_name,
            v.public_key_form
        );
    }
}

/// High-S signatures must still verify.
///
/// `k256` REJECTS high-S by default, and measured against this very file the
/// unmodified path rejects 7 of 12 valid signatures. The ledger verifies
/// through OpenSSL, which neither normalises nor requires low-S, so it
/// produces high-S freely. Inheriting the library default here would reject
/// roughly half of everything the ledger makes -- and the half that succeeded
/// would make it look like an intermittent fault rather than a crypto one.
#[test]
fn high_s_signatures_from_elsewhere_still_verify() {
    let high: Vec<_> = common::secp256k1()
        .filter(|v| secp256k1::is_high_s_base64(&v.signature))
        .collect();

    assert!(
        !high.is_empty(),
        "the published vectors no longer contain a high-S signature, so this test proves nothing"
    );

    for v in high {
        let key = Secp256k1KeyPair::from_public(&v.public_key).unwrap();
        assert!(
            key.verify(v.message.as_bytes(), &decode(&v.signature)),
            "rejected a high-S signature ({}/{}) - low-S is being enforced on verify",
            v.message_name,
            v.public_key_form
        );
    }
}

/// The strongest test here: the exact bytes, not merely a valid signature.
///
/// These expected values come from @noble/curves, an entirely separate
/// implementation. Agreeing byte for byte means agreeing on RFC 6979's k, on
/// low-S normalisation and on DER encoding at once -- none of which a
/// verify-round-trip test can see. Only possible because ECDSA signing is
/// deterministic; the post-quantum schemes are hedged and never can be.
#[test]
fn signatures_are_byte_identical_to_the_reference_implementation() {
    for v in common::secp256k1() {
        let key = Secp256k1KeyPair::from_keys(&v.public_key, &v.private_key).expect("key pair");
        let mine = STANDARD.encode(key.sign(v.message.as_bytes()).unwrap());

        assert_eq!(
            v.deterministic_signature, mine,
            "{}/{}: signature differs from the reference. If r matches and only s differs, \
             low-S normalisation is the cause.",
            v.message_name, v.public_key_form
        );
    }
}

#[test]
fn signing_is_deterministic() {
    let v = common::secp256k1().next().unwrap();
    let key = Secp256k1KeyPair::from_keys(&v.public_key, &v.private_key).unwrap();

    assert_eq!(
        key.sign(v.message.as_bytes()).unwrap(),
        key.sign(v.message.as_bytes()).unwrap()
    );

    let other = common::secp256k1().nth(1).unwrap();
    assert_ne!(
        key.sign(v.message.as_bytes()).unwrap(),
        key.sign(other.message.as_bytes()).unwrap()
    );
}

#[test]
fn every_signature_emitted_is_low_s() {
    let key = Secp256k1KeyPair::generate();

    for i in 0..200 {
        let signature = key.sign(format!("message {i}").as_bytes()).unwrap();
        assert!(
            !secp256k1::is_high_s(&signature),
            "signature {i} was high-S"
        );
    }
}

#[test]
fn signatures_made_here_verify_with_the_reference_public_key() {
    for v in common::secp256k1() {
        let signer = Secp256k1KeyPair::from_keys(&v.public_key, &v.private_key).unwrap();
        let verifier = Secp256k1KeyPair::from_public(&v.public_key).unwrap();

        assert!(
            verifier.verify(
                v.message.as_bytes(),
                &signer.sign(v.message.as_bytes()).unwrap()
            ),
            "reference key rejected a signature made here ({}/{})",
            v.message_name,
            v.public_key_form
        );
    }
}

#[test]
fn round_trips_published_keys_exactly() {
    for v in common::secp256k1() {
        let key = Secp256k1KeyPair::from_keys(&v.public_key, &v.private_key).unwrap();
        assert_eq!(v.public_key, key.public_key());
        assert_eq!(Some(v.private_key.clone()), key.private_key());
    }
}

#[test]
fn tampered_message_does_not_verify() {
    for v in common::secp256k1() {
        let key = Secp256k1KeyPair::from_public(&v.public_key).unwrap();
        let mut tampered = v.message.clone().into_bytes();
        tampered.push(b' ');
        assert!(!key.verify(&tampered, &decode(&v.signature)));
    }
}

#[test]
fn generated_keys_use_the_ledgers_encoding() {
    let key = Secp256k1KeyPair::generate();

    assert!(key.public_key().starts_with("0x"));
    assert!(key.private_key().unwrap().starts_with("0x"));
    // Compressed by default: 33 bytes, so "0x" plus 66 hex characters.
    assert_eq!(68, key.public_key().len());
    assert_eq!(66, key.private_key().unwrap().len());
    assert!(matches!(&key.public_key()[2..4], "02" | "03"));
}

#[test]
fn uncompressed_generation_is_available() {
    let key = Secp256k1KeyPair::generate_with(false);

    assert_eq!(132, key.public_key().len());
    assert!(key.public_key().starts_with("0x04"));
    assert!(key.verify(b"x", &key.sign(b"x").unwrap()));
}

/// The private scalar must always be 32 bytes.
///
/// A leading zero byte occurs roughly once in 400 keys, and a value that
/// dropped it is a different scalar to anything reading it strictly.
#[test]
fn private_keys_are_always_left_padded_to_32_bytes() {
    for _ in 0..1500 {
        assert_eq!(
            66,
            Secp256k1KeyPair::generate().private_key().unwrap().len()
        );
    }
}

/// The 0x prefix is part of what the ledger stores, not decoration.
#[test]
fn a_key_without_the_hex_prefix_is_refused_with_an_explanation() {
    let valid = Secp256k1KeyPair::generate().public_key();

    let error = Secp256k1KeyPair::from_public(&valid[2..]).unwrap_err();
    assert!(
        matches!(error, KeyError::MissingHexPrefix { .. }),
        "{error}"
    );
    assert!(error.to_string().contains("0x"), "{error}");
}

#[test]
fn wrong_length_public_key_is_rejected_with_both_valid_lengths() {
    let error = Secp256k1KeyPair::from_public(&format!("0x{}", "aa".repeat(20))).unwrap_err();

    let message = error.to_string();
    assert!(message.contains("33"), "{message}");
    assert!(message.contains("65"), "{message}");
}

/// A length and a point prefix that disagree means the forms got mixed.
#[test]
fn a_prefix_that_contradicts_the_length_is_rejected() {
    let error = Secp256k1KeyPair::from_public(&format!("0x04{}", "aa".repeat(32))).unwrap_err();
    assert!(
        matches!(error, KeyError::PointPrefixMismatch { .. }),
        "{error}"
    );
}

#[test]
fn non_hex_is_rejected() {
    let error = Secp256k1KeyPair::from_public("0xzzzz").unwrap_err();
    assert!(matches!(error, KeyError::NotHex { .. }), "{error}");
}

#[test]
fn verify_only_key_pair_refuses_to_sign() {
    let v = common::secp256k1().next().unwrap();
    let key = Secp256k1KeyPair::from_public(&v.public_key).unwrap();

    assert!(!key.can_sign());
    assert!(key.private_key().is_none());
    assert!(matches!(key.sign(b"anything"), Err(KeyError::VerifyOnly)));
}

#[test]
fn malformed_signature_returns_false_rather_than_panicking() {
    let v = common::secp256k1().next().unwrap();
    let key = Secp256k1KeyPair::from_public(&v.public_key).unwrap();

    assert!(!key.verify(v.message.as_bytes(), &[]));
    assert!(!key.verify(v.message.as_bytes(), &[0u8; 10]));
    // A raw r||s pair rather than DER.
    assert!(!key.verify(v.message.as_bytes(), &[0u8; 64]));
}

/// The ledger routes `bitcoin` and `ethereum` to identical secp256k1
/// verification, so an existing identity may carry either.
#[test]
fn bitcoin_and_ethereum_parse_as_secp256k1_but_are_never_emitted() {
    assert_eq!(KeyType::Secp256k1, KeyType::from_wire("bitcoin").unwrap());
    assert_eq!(KeyType::Secp256k1, KeyType::from_wire("ethereum").unwrap());
    assert_eq!(
        "secp256k1",
        KeyType::from_wire("bitcoin").unwrap().as_wire()
    );
    assert_eq!(
        "secp256k1",
        KeyType::from_wire("ethereum").unwrap().as_wire()
    );
}

#[test]
fn the_key_pair_reports_secp256k1_as_its_type() {
    assert_eq!(KeyType::Secp256k1, Secp256k1KeyPair::generate().key_type());
}

/// Debug output must never carry private key material: it ends up in logs.
#[test]
fn debug_output_does_not_leak_the_private_key() {
    let key = Secp256k1KeyPair::generate();
    let rendered = format!("{key:?}");

    assert!(!rendered.contains(&key.private_key().unwrap()));
    assert!(!rendered.contains(&key.public_key()));
}
