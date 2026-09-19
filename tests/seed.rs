//! Seed and recovery-phrase derivation, against the published cross-language
//! vectors.
//!
//! Six other SDKs derive keys from the same seeds and phrases. A derivation
//! that drifts does not fail loudly -- it produces a perfectly valid key for
//! an identity that is not the caller's, and the only symptom arrives much
//! later as 1220 "Signature Incorrect" from somewhere else entirely.

use activeledger::keys::KeyError;
use activeledger::recovery;
use activeledger::secp256k1::Secp256k1KeyPair;
use activeledger::{KeyPair, KeyType, Signer};

fn doc() -> serde_json::Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/seed-vectors.json"
    ))
    .expect("seed-vectors.json");
    serde_json::from_str(&raw).expect("seed vector json")
}

fn hex_bytes(value: &str) -> Vec<u8> {
    hex::decode(value).expect("hex in vector")
}

fn seed_vectors(doc: &serde_json::Value, key_type: &str, valid: bool) -> Vec<serde_json::Value> {
    doc["seedVectors"]
        .as_array()
        .expect("seedVectors")
        .iter()
        .filter(|v| v["type"] == key_type && v["valid"].as_bool().unwrap_or(true) == valid)
        .cloned()
        .collect()
}

fn phrase_vectors(doc: &serde_json::Value, key_type: &str) -> Vec<serde_json::Value> {
    doc["phraseVectors"]
        .as_array()
        .expect("phraseVectors")
        .iter()
        .filter(|v| v["type"] == key_type)
        .cloned()
        .collect()
}

/// A file that silently lost a type would let everything below pass by simply
/// not running.
#[test]
fn the_vector_file_covers_what_this_sdk_supports() {
    let doc = doc();

    assert!(!seed_vectors(&doc, "ml-dsa-65", true).is_empty());
    assert!(!seed_vectors(&doc, "secp256k1", true).is_empty());
    assert!(seed_vectors(&doc, "secp256k1", false).len() >= 2);
    assert!(!phrase_vectors(&doc, "ml-dsa-65").is_empty());
    assert!(!phrase_vectors(&doc, "secp256k1").is_empty());
}

#[test]
fn ml_dsa_from_seed_matches_the_vectors() {
    for v in seed_vectors(&doc(), "ml-dsa-65", true) {
        let name = v["seedName"].as_str().unwrap();
        let pair = KeyPair::from_seed(&hex_bytes(v["seed"].as_str().unwrap()))
            .unwrap_or_else(|e| panic!("{name}: {e}"));

        assert_eq!(
            pair.public_key(),
            v["publicKey"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            pair.private_key().unwrap(),
            v["privateKey"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn secp256k1_from_seed_matches_the_vectors() {
    for v in seed_vectors(&doc(), "secp256k1", true) {
        let name = v["seedName"].as_str().unwrap();
        let form = v["publicKeyForm"].as_str().unwrap();
        let pair = Secp256k1KeyPair::from_seed(
            &hex_bytes(v["seed"].as_str().unwrap()),
            form == "compressed",
        )
        .unwrap_or_else(|e| panic!("{name}/{form}: {e}"));

        assert_eq!(
            pair.public_key(),
            v["publicKey"].as_str().unwrap(),
            "{name}/{form}"
        );
        assert_eq!(
            pair.private_key().unwrap(),
            v["privateKey"].as_str().unwrap(),
            "{name}/{form}"
        );
    }
}

/// An invalid scalar must be refused, never reduced. Reducing mod n produces
/// a perfectly functional key belonging to a different identity, and nothing
/// downstream ever reports a problem.
#[test]
fn an_invalid_scalar_is_refused_rather_than_reduced() {
    for v in seed_vectors(&doc(), "secp256k1", false) {
        let name = v["seedName"].as_str().unwrap();

        match Secp256k1KeyPair::from_seed(&hex_bytes(v["seed"].as_str().unwrap()), true) {
            Err(KeyError::InvalidScalar) => {}
            Err(other) => panic!("{name}: wrong error: {other}"),
            Ok(_) => panic!("{name}: accepted an invalid scalar"),
        }
    }
}

#[test]
fn phrase_recovery_matches_the_vectors() {
    let doc = doc();
    let mut checked = 0;

    for v in doc["phraseVectors"].as_array().unwrap() {
        let key_type = v["type"].as_str().unwrap();
        let phrase = v["phrase"].as_str().unwrap();
        let passphrase = v["passphrase"].as_str().unwrap();
        let scheme = v["scheme"].as_str().unwrap();
        let name = v["phraseName"].as_str().unwrap();

        let (public, private) = match key_type {
            "ml-dsa-65" => {
                let pair = KeyPair::from_phrase(phrase, passphrase)
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                (pair.public_key(), pair.private_key().unwrap())
            }
            "secp256k1" => {
                let compressed = v["publicKeyForm"] == "compressed";
                let pair = if scheme == "legacy" {
                    Secp256k1KeyPair::from_legacy_phrase(phrase, compressed)
                } else {
                    Secp256k1KeyPair::from_phrase(phrase, passphrase, compressed)
                }
                .unwrap_or_else(|e| panic!("{name}/{scheme}: {e}"));
                (pair.public_key(), pair.private_key().unwrap())
            }
            // falcon-512 is not supported by this SDK at all.
            _ => continue,
        };

        checked += 1;
        assert_eq!(
            public,
            v["publicKey"].as_str().unwrap(),
            "{key_type}/{name}/{scheme}"
        );
        assert_eq!(
            private,
            v["privateKey"].as_str().unwrap(),
            "{key_type}/{name}/{scheme}"
        );
    }

    assert!(checked > 0, "no phrase vectors ran");
}

/// Checked separately from the key so a failure says WHICH step drifted.
#[test]
fn the_derivation_matches_the_published_intermediates() {
    for v in doc()["phraseVectors"].as_array().unwrap() {
        if v["scheme"] != "v1" {
            continue;
        }

        let name = v["phraseName"].as_str().unwrap();
        let key_type = KeyType::from_wire(v["type"].as_str().unwrap()).unwrap();

        let bip39 = recovery::to_seed(
            v["phrase"].as_str().unwrap(),
            v["passphrase"].as_str().unwrap(),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));

        assert_eq!(
            hex::encode(&bip39),
            v["bip39Seed"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            hex::encode(recovery::derive_seed(key_type, &bip39).unwrap()),
            v["derivedSeed"].as_str().unwrap(),
            "{key_type:?}/{name}"
        );
    }
}

/// Domain separation. Without it one phrase gives an ml-dsa-65 seed equal to
/// the secp256k1 scalar, so two identities share entropy.
#[test]
fn each_key_type_derives_a_different_seed() {
    let doc = doc();
    let phrase = doc["phraseVectors"][0]["phrase"].as_str().unwrap();
    let bip39 = recovery::to_seed(phrase, "").unwrap();

    let seeds: Vec<Vec<u8>> = [KeyType::Secp256k1, KeyType::MlDsa65, KeyType::Falcon512]
        .iter()
        .map(|t| recovery::derive_seed(*t, &bip39).unwrap())
        .collect();

    assert_ne!(seeds[0], seeds[1]);
    assert_ne!(seeds[1], seeds[2]);
    assert_ne!(seeds[0], seeds[2]);
}

/// falcon-512 has no implementation here, but its SEED still derives, so a
/// phrase can back a Falcon identity created in another SDK.
#[test]
fn a_falcon_seed_derives_even_though_falcon_does_not() {
    let doc = doc();
    let bip39 = recovery::to_seed(doc["phraseVectors"][0]["phrase"].as_str().unwrap(), "").unwrap();

    assert_eq!(
        recovery::derive_seed(KeyType::Falcon512, &bip39)
            .unwrap()
            .len(),
        48
    );
}

#[test]
fn a_seed_of_the_wrong_length_is_refused_rather_than_padded() {
    // Padding would produce a valid key for a different identity - the same
    // failure as reducing a scalar, by another route.
    for length in [0usize, 31, 33, 48] {
        assert!(matches!(
            KeyPair::from_seed(&vec![1u8; length]),
            Err(KeyError::WrongSeedLength { .. })
        ));
        assert!(matches!(
            Secp256k1KeyPair::from_seed(&vec![1u8; length], true),
            Err(KeyError::WrongSeedLength { .. })
        ));
    }
}

#[test]
fn a_phrase_with_a_bad_checksum_is_rejected() {
    // An unchecked phrase is a silent failure: it derives a perfectly valid
    // key for an identity nobody owns.
    let phrase = "abandon ".repeat(11) + "abandon";

    assert!(matches!(
        recovery::to_seed(&phrase, ""),
        Err(KeyError::BadChecksum)
    ));
}

#[test]
fn a_word_outside_the_wordlist_is_named() {
    let phrase = "abandon ".repeat(11) + "zzzz";

    match recovery::to_seed(&phrase, "") {
        Err(KeyError::UnknownWord { position, word }) => {
            assert_eq!(position, 12);
            assert_eq!(word, "zzzz");
        }
        other => panic!("expected the word to be named, got {other:?}"),
    }
}

#[test]
fn a_wrong_word_count_is_rejected() {
    assert!(matches!(
        recovery::to_seed("abandon abandon abandon", ""),
        Err(KeyError::WrongWordCount { actual: 3 })
    ));
}

#[test]
fn a_passphrase_changes_the_identity() {
    let doc = doc();
    let phrase = doc["phraseVectors"][0]["phrase"].as_str().unwrap();

    assert_ne!(
        KeyPair::from_phrase(phrase, "").unwrap().public_key(),
        KeyPair::from_phrase(phrase, "TREZOR").unwrap().public_key()
    );
}

#[test]
fn a_seed_derived_key_signs_and_verifies() {
    let seed = vec![0x11u8; 32];

    let pq = KeyPair::from_seed(&seed).unwrap();
    let signature = pq.sign(b"payload").unwrap();
    assert!(pq.verify(b"payload", &signature));

    let ec = Secp256k1KeyPair::from_seed(&seed, true).unwrap();
    let signature = ec.sign(b"payload").unwrap();
    assert!(ec.verify(b"payload", &signature));
}

#[test]
fn the_same_seed_always_derives_the_same_key() {
    let seed = vec![0x5au8; 32];

    assert_eq!(
        KeyPair::from_seed(&seed).unwrap().public_key(),
        KeyPair::from_seed(&seed).unwrap().public_key()
    );
}
