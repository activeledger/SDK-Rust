//! Recovery-phrase validation and seed-size rules, checked against the
//! published BIP-39 test vectors rather than against this crate's own output.

use activeledger::keys::KeyError;
use activeledger::recovery::{self, BIP39_SEED_SIZE};
use activeledger::{KeyPair, KeyType};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// `count - 1` copies of "abandon" followed by `last`.
fn phrase(count: usize, last: &str) -> String {
    let mut words = vec!["abandon"; count - 1];
    words.push(last);
    words.join(" ")
}

#[test]
fn every_valid_phrase_length_is_accepted() {
    // Checksum words for all-zero entropy at each length, from the BIP-39
    // reference vectors.
    for (count, last) in [
        (12, "about"),
        (15, "address"),
        (18, "agent"),
        (21, "admit"),
        (24, "art"),
    ] {
        let p = phrase(count, last);
        assert_eq!(p, recovery::validate(&p).unwrap(), "{count} words");
    }
}

#[test]
fn validation_normalises_whitespace_and_to_seed_agrees() {
    let messy = format!("  {}\n", ABANDON.replace(' ', " \t "));

    assert_eq!(ABANDON, recovery::validate(&messy).unwrap());
    assert_eq!(
        recovery::to_seed(ABANDON, "").unwrap(),
        recovery::to_seed(&messy, "").unwrap()
    );
}

/// The first vector in the BIP-39 reference suite.
#[test]
fn the_bip39_seed_matches_the_published_trezor_vector() {
    let seed = recovery::to_seed(ABANDON, "TREZOR").unwrap();

    assert_eq!(BIP39_SEED_SIZE, seed.len());
    assert_eq!(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        hex::encode(seed)
    );
}

#[test]
fn the_wordlist_is_case_sensitive() {
    let upper = ABANDON.replacen("abandon", "Abandon", 1);

    match recovery::validate(&upper) {
        Err(KeyError::UnknownWord { position, word }) => {
            assert_eq!(1, position);
            assert_eq!("Abandon", word);
        }
        other => panic!("expected UnknownWord, got {other:?}"),
    }
}

#[test]
fn word_counts_between_valid_lengths_are_refused() {
    for count in [0usize, 1, 11, 13, 14, 16, 25, 27] {
        let phrase = vec!["abandon"; count].join(" ");
        match recovery::validate(&phrase) {
            Err(KeyError::WrongWordCount { actual }) => assert_eq!(count, actual),
            other => panic!("{count} words: expected WrongWordCount, got {other:?}"),
        }
    }
}

#[test]
fn a_swapped_pair_of_words_fails_the_checksum() {
    let swapped = format!("about {}", phrase(11, "abandon"));

    assert!(matches!(
        recovery::validate(&swapped),
        Err(KeyError::BadChecksum)
    ));
}

#[test]
fn seed_sizes_per_key_type() {
    assert_eq!(32, recovery::seed_size(KeyType::Secp256k1).unwrap());
    assert_eq!(32, recovery::seed_size(KeyType::MlDsa65).unwrap());
    assert_eq!(48, recovery::seed_size(KeyType::Falcon512).unwrap());
    assert!(matches!(
        recovery::seed_size(KeyType::Rsa),
        Err(KeyError::UnknownKeyType(_))
    ));
}

#[test]
fn derive_seed_refuses_a_bip39_seed_of_the_wrong_length() {
    for length in [0usize, 32, 63, 65] {
        match recovery::derive_seed(KeyType::MlDsa65, &vec![7u8; length]) {
            Err(KeyError::WrongBip39SeedLength { actual }) => assert_eq!(length, actual),
            other => panic!("{length} bytes: expected WrongBip39SeedLength, got {other:?}"),
        }
    }
}

#[test]
fn derived_seeds_have_the_length_the_key_type_takes() {
    let bip39 = [9u8; BIP39_SEED_SIZE];

    assert_eq!(
        32,
        recovery::derive_seed(KeyType::MlDsa65, &bip39)
            .unwrap()
            .len()
    );
    assert_eq!(
        32,
        recovery::derive_seed(KeyType::Secp256k1, &bip39)
            .unwrap()
            .len()
    );
    assert_eq!(
        48,
        recovery::derive_seed(KeyType::Falcon512, &bip39)
            .unwrap()
            .len()
    );
    assert!(recovery::derive_seed(KeyType::Rsa, &bip39).is_err());
}

#[test]
fn from_phrase_surfaces_validation_errors_instead_of_deriving() {
    let bad = ABANDON.replace("about", "abandon");

    assert!(matches!(
        KeyPair::from_phrase(&bad, ""),
        Err(KeyError::BadChecksum)
    ));
    assert!(matches!(
        KeyPair::from_phrase("one two three", ""),
        Err(KeyError::WrongWordCount { actual: 3 })
    ));
}
