//! Key loading and error reporting: what a caller sees when stored key
//! material is wrong, and that the messages say what is wrong.

use activeledger::keys::{
    ML_DSA_65_PRIVATE_KEY_SIZE, ML_DSA_65_PUBLIC_KEY_SIZE, ML_DSA_65_SIGNATURE_SIZE,
};
use activeledger::{KeyError, KeyPair, KeyType, Secp256k1KeyPair, Signer};
use base64::{engine::general_purpose::STANDARD, Engine};

fn b64_zeros(len: usize) -> String {
    STANDARD.encode(vec![0u8; len])
}

#[test]
fn wire_names_round_trip_for_every_key_type() {
    for key_type in [
        KeyType::Rsa,
        KeyType::Secp256k1,
        KeyType::MlDsa65,
        KeyType::Falcon512,
    ] {
        assert_eq!(
            key_type,
            KeyType::from_wire(key_type.as_wire()).expect("own wire name parses")
        );
    }
}

#[test]
fn wire_names_are_the_ledgers_strings() {
    assert_eq!("rsa", KeyType::Rsa.as_wire());
    assert_eq!("secp256k1", KeyType::Secp256k1.as_wire());
    assert_eq!("ml-dsa-65", KeyType::MlDsa65.as_wire());
    assert_eq!("falcon-512", KeyType::Falcon512.as_wire());
}

#[test]
fn an_unknown_wire_name_is_reported_with_the_text_given() {
    let error = KeyType::from_wire("").unwrap_err();
    assert!(matches!(&error, KeyError::UnknownKeyType(s) if s.is_empty()));

    let error = KeyType::from_wire(" rsa").unwrap_err();
    assert!(error.to_string().contains("' rsa'"), "{error}");
}

#[test]
fn only_the_lattice_schemes_are_post_quantum() {
    assert!(!KeyType::Rsa.is_post_quantum());
    assert!(!KeyType::Secp256k1.is_post_quantum());
    assert!(KeyType::MlDsa65.is_post_quantum());
    assert!(KeyType::Falcon512.is_post_quantum());
}

#[test]
fn ml_dsa_sizes_match_the_fixed_encodings() {
    let key = KeyPair::generate().expect("keygen");
    assert_eq!(
        ML_DSA_65_PUBLIC_KEY_SIZE,
        STANDARD.decode(key.public_key()).unwrap().len()
    );
    assert_eq!(
        ML_DSA_65_PRIVATE_KEY_SIZE,
        STANDARD
            .decode(key.private_key().expect("private"))
            .unwrap()
            .len()
    );
    assert_eq!(
        ML_DSA_65_SIGNATURE_SIZE,
        key.sign(b"m").expect("sign").len()
    );
}

#[test]
fn ml_dsa_from_public_rejects_the_wrong_length_and_says_which_key() {
    let error = KeyPair::from_public(&b64_zeros(10)).unwrap_err();
    assert!(
        matches!(
            error,
            KeyError::WrongLength {
                role: "public",
                actual: 10,
                expected: ML_DSA_65_PUBLIC_KEY_SIZE
            }
        ),
        "{error:?}"
    );
    assert_eq!("public key is 10 bytes, expected 1952", error.to_string());
}

#[test]
fn ml_dsa_from_public_rejects_text_that_is_not_base64() {
    let error = KeyPair::from_public("not base64 !!").unwrap_err();
    assert!(
        matches!(error, KeyError::NotBase64 { role: "public", .. }),
        "{error:?}"
    );
}

#[test]
fn ml_dsa_from_keys_checks_the_private_half_separately() {
    let key = KeyPair::generate().expect("keygen");
    let public = key.public_key();

    let short = KeyPair::from_keys(&public, &b64_zeros(5)).unwrap_err();
    assert!(
        matches!(
            short,
            KeyError::WrongLength {
                role: "private",
                actual: 5,
                expected: ML_DSA_65_PRIVATE_KEY_SIZE
            }
        ),
        "{short:?}"
    );

    let garbage = KeyPair::from_keys(&public, "***").unwrap_err();
    assert!(
        matches!(
            garbage,
            KeyError::NotBase64 {
                role: "private",
                ..
            }
        ),
        "{garbage:?}"
    );

    // A bad public key is reported as the public key, not the private one.
    let bad_public = KeyPair::from_keys(&b64_zeros(3), &key.private_key().unwrap()).unwrap_err();
    assert!(
        matches!(bad_public, KeyError::WrongLength { role: "public", .. }),
        "{bad_public:?}"
    );
}

#[test]
fn ml_dsa_from_keys_restores_a_pair_that_signs_for_the_original() {
    let original = KeyPair::generate().expect("keygen");
    let restored =
        KeyPair::from_keys(&original.public_key(), &original.private_key().unwrap()).unwrap();

    assert!(restored.can_sign());
    assert_eq!(original.public_key(), restored.public_key());
    let signature = restored.sign(b"message").expect("sign");
    assert!(original.verify(b"message", &signature));
}

#[test]
fn ml_dsa_verify_is_false_for_a_signature_of_the_wrong_length() {
    let key = KeyPair::generate().expect("keygen");
    let signature = key.sign(b"m").expect("sign");

    assert!(key.verify(b"m", &signature));
    assert!(!key.verify(b"m", &[]));
    assert!(!key.verify(b"m", &signature[..signature.len() - 1]));
    let mut longer = signature.clone();
    longer.push(0);
    assert!(!key.verify(b"m", &longer));
}

#[test]
fn ml_dsa_verify_rejects_a_flipped_bit_and_a_different_message() {
    let key = KeyPair::generate().expect("keygen");
    let mut signature = key.sign(b"m").expect("sign");

    assert!(!key.verify(b"n", &signature));
    signature[0] ^= 1;
    assert!(!key.verify(b"m", &signature));
}

#[test]
fn a_signature_does_not_verify_under_a_different_key() {
    let signer = KeyPair::generate().expect("keygen");
    let other = KeyPair::generate().expect("keygen");

    let signature = signer.sign(b"m").expect("sign");
    assert!(!other.verify(b"m", &signature));
}

#[test]
fn ml_dsa_signing_is_hedged_so_two_signatures_differ_but_both_verify() {
    let key = KeyPair::generate().expect("keygen");
    let first = key.sign(b"same").expect("sign");
    let second = key.sign(b"same").expect("sign");

    assert_ne!(first, second);
    assert!(key.verify(b"same", &first) && key.verify(b"same", &second));
}

#[test]
fn a_verify_only_pair_has_no_private_key_and_its_debug_says_so() {
    let key = KeyPair::generate().expect("keygen");
    let public_only = KeyPair::from_public(&key.public_key()).expect("public");

    assert!(!public_only.can_sign());
    assert_eq!(None, public_only.private_key());
    assert_eq!(
        "KeyPair(ml-dsa-65, public only)",
        format!("{public_only:?}")
    );
    assert_eq!("KeyPair(ml-dsa-65, public+private)", format!("{key:?}"));
}

#[test]
fn ml_dsa_debug_never_contains_key_material() {
    let key = KeyPair::generate().expect("keygen");
    let shown = format!("{key:?}");
    assert!(!shown.contains(&key.public_key()[..16]));
    assert!(!shown.contains(&key.private_key().unwrap()[..16]));
}

#[test]
fn ml_dsa_seeds_must_be_exactly_32_bytes() {
    for len in [0, 31, 33, 64] {
        let error = KeyPair::from_seed(&vec![1u8; len]).unwrap_err();
        assert!(
            matches!(
                error,
                KeyError::WrongSeedLength { key_type: "ml-dsa-65", actual, expected: 32 } if actual == len
            ),
            "{len}: {error:?}"
        );
    }
}

#[test]
fn the_same_seed_gives_the_same_ml_dsa_identity() {
    let a = KeyPair::from_seed(&[7u8; 32]).expect("seed");
    let b = KeyPair::from_seed(&[7u8; 32]).expect("seed");
    let c = KeyPair::from_seed(&[8u8; 32]).expect("seed");

    assert_eq!(a.public_key(), b.public_key());
    assert_eq!(a.private_key(), b.private_key());
    assert_ne!(a.public_key(), c.public_key());
}

// --- secp256k1 loading -----------------------------------------------------

fn secp_pair() -> Secp256k1KeyPair {
    Secp256k1KeyPair::from_seed(&[3u8; 32], true).expect("seed")
}

#[test]
fn secp256k1_from_keys_rejects_a_private_key_of_the_wrong_length() {
    let public = secp_pair().public_key();

    let error = Secp256k1KeyPair::from_keys(&public, "0xabcd").unwrap_err();
    assert!(
        matches!(
            error,
            KeyError::WrongLength {
                role: "private",
                actual: 2,
                expected: 32
            }
        ),
        "{error:?}"
    );
}

#[test]
fn secp256k1_from_keys_rejects_a_zero_scalar_as_malformed() {
    let public = secp_pair().public_key();
    let zero = format!("0x{}", "00".repeat(32));

    let error = Secp256k1KeyPair::from_keys(&public, &zero).unwrap_err();
    assert!(
        matches!(error, KeyError::Malformed { role: "private" }),
        "{error:?}"
    );
}

#[test]
fn secp256k1_from_keys_checks_prefix_and_hex_on_the_private_half() {
    let public = secp_pair().public_key();

    let unprefixed = Secp256k1KeyPair::from_keys(&public, &"11".repeat(32)).unwrap_err();
    assert!(
        matches!(unprefixed, KeyError::MissingHexPrefix { role: "private" }),
        "{unprefixed:?}"
    );

    let not_hex = Secp256k1KeyPair::from_keys(&public, "0xzz").unwrap_err();
    assert!(
        matches!(not_hex, KeyError::NotHex { role: "private" }),
        "{not_hex:?}"
    );
}

/// 0x02 followed by thirty-two 0xff bytes has the right length and prefix but
/// is not an x coordinate on the curve.
#[test]
fn secp256k1_from_public_rejects_a_point_that_is_not_on_the_curve() {
    let off_curve = format!("0x02{}", "ff".repeat(32));

    let error = Secp256k1KeyPair::from_public(&off_curve).unwrap_err();
    assert!(
        matches!(error, KeyError::Malformed { role: "public" }),
        "{error:?}"
    );
}

#[test]
fn secp256k1_from_public_reports_the_length_it_was_given() {
    let error = Secp256k1KeyPair::from_public("0x02").unwrap_err();
    assert!(
        matches!(error, KeyError::WrongPublicKeyLength { actual: 1 }),
        "{error:?}"
    );
    assert!(error.to_string().contains("1 bytes"), "{error}");
}

#[test]
fn secp256k1_seeds_must_be_32_bytes_and_a_valid_scalar() {
    let short = Secp256k1KeyPair::from_seed(&[1u8; 31], true).unwrap_err();
    assert!(
        matches!(
            short,
            KeyError::WrongSeedLength {
                key_type: "secp256k1",
                actual: 31,
                expected: 32
            }
        ),
        "{short:?}"
    );

    let zero = Secp256k1KeyPair::from_seed(&[0u8; 32], true).unwrap_err();
    assert!(matches!(zero, KeyError::InvalidScalar), "{zero:?}");

    // Above the group order n: refused rather than reduced.
    let above_order = Secp256k1KeyPair::from_seed(&[0xff; 32], true).unwrap_err();
    assert!(
        matches!(above_order, KeyError::InvalidScalar),
        "{above_order:?}"
    );
}

#[test]
fn a_seed_of_one_gives_the_generator_point() {
    let mut seed = [0u8; 32];
    seed[31] = 1;
    let key = Secp256k1KeyPair::from_seed(&seed, true).expect("scalar 1 is valid");

    assert_eq!(
        "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        key.public_key()
    );
}

#[test]
fn compressed_and_uncompressed_forms_of_one_seed_share_the_private_key() {
    let compressed = Secp256k1KeyPair::from_seed(&[5u8; 32], true).unwrap();
    let uncompressed = Secp256k1KeyPair::from_seed(&[5u8; 32], false).unwrap();

    assert_eq!(compressed.private_key(), uncompressed.private_key());
    assert_eq!(2 + 2 * 33, compressed.public_key().len());
    assert_eq!(2 + 2 * 65, uncompressed.public_key().len());
    assert!(uncompressed.public_key().starts_with("0x04"));

    let signature = compressed.sign(b"m").expect("sign");
    assert!(uncompressed.verify(b"m", &signature));
}

#[test]
fn secp256k1_verify_only_pair_reports_itself_in_debug_and_cannot_sign() {
    let verify_only = Secp256k1KeyPair::from_public(&secp_pair().public_key()).unwrap();

    assert!(!verify_only.can_sign());
    assert_eq!(None, verify_only.private_key());
    assert_eq!("Secp256k1KeyPair(public only)", format!("{verify_only:?}"));
    assert_eq!(
        "Secp256k1KeyPair(public+private)",
        format!("{:?}", secp_pair())
    );
}

#[test]
fn a_signature_by_one_secp256k1_key_fails_under_another() {
    let a = Secp256k1KeyPair::from_seed(&[1u8; 32], true).unwrap();
    let b = Secp256k1KeyPair::from_seed(&[2u8; 32], true).unwrap();

    let signature = a.sign(b"m").unwrap();
    assert!(a.verify(b"m", &signature));
    assert!(!b.verify(b"m", &signature));
}

#[test]
fn high_s_detection_treats_non_signatures_as_not_high() {
    use activeledger::secp256k1::{is_high_s, is_high_s_base64};

    assert!(!is_high_s(&[]));
    assert!(!is_high_s(&[0x30, 0x00]));
    assert!(!is_high_s_base64("not base64 !!"));
    assert!(!is_high_s_base64(""));

    // And a real, emitted signature is low-S.
    let signature = secp_pair().sign(b"m").unwrap();
    assert!(!is_high_s(&signature));
    assert!(!is_high_s_base64(&STANDARD.encode(&signature)));
}

#[test]
fn error_messages_name_the_remedy_not_just_the_failure() {
    let verify_only = KeyError::VerifyOnly.to_string();
    assert!(verify_only.contains("verification only"), "{verify_only}");

    let prefix = Secp256k1KeyPair::from_public("abcd")
        .unwrap_err()
        .to_string();
    assert!(prefix.contains("0x"), "{prefix}");
}
