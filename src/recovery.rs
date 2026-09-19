//! BIP-39 recovery phrases, and the seed each key type derives from one.
//!
//! Two layers, and conflating them is the mistake this module is arranged to
//! prevent. A phrase becomes a 64-byte BIP-39 seed; that seed becomes the
//! seed the chosen algorithm actually takes. They are different lengths and
//! different constructions, and [`derive_seed`] is the step between them.
//!
//! The derivation:
//!
//! ```text
//! BIP-39 seed S = PBKDF2-HMAC-SHA512(phrase, "mnemonic"+passphrase, 2048, 64)
//!
//! ml-dsa-65   HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)
//! falcon-512  HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)
//! secp256k1   HMAC-SHA512("Bitcoin seed", S)[0..32]
//! ```
//!
//! `secp256k1` does not use HKDF, and that is not an oversight. The
//! JavaScript SDK has shipped `restoreBIP39Key` with the construction above
//! since before the post-quantum types existed, so phrases are already in
//! use. Changing it would hand every one of those users a different key for
//! a phrase that used to work -- not an error, just an identity that is no
//! longer theirs. The post-quantum types are new and carry no such debt, so
//! they get the construction with proper domain separation.
//!
//! Published, with cross-language vectors, in the JavaScript SDK's
//! `vectors/seed-vectors.json`.
//!
//! `falcon-512`'s seed derives here even though this SDK cannot use Falcon,
//! so a phrase can still produce the seed for an identity created elsewhere.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::keys::{KeyError, KeyType};

type HmacSha512 = Hmac<Sha512>;

/// BIP-39's fixed PBKDF2 iteration count. Not tunable: changing it changes
/// every identity ever derived from a phrase.
const ITERATIONS: u32 = 2048;

/// A BIP-39 seed is always 64 bytes.
pub const BIP39_SEED_SIZE: usize = 64;

const WORDLIST: &str = include_str!("bip39-english.txt");

/// The seed length the given key type takes.
///
/// A wrong length is refused, never padded: a padded seed is a different
/// identity, not a malformed one.
pub fn seed_size(key_type: KeyType) -> Result<usize, KeyError> {
    match key_type {
        KeyType::Secp256k1 | KeyType::MlDsa65 => Ok(32),
        KeyType::Falcon512 => Ok(48),
        KeyType::Rsa => Err(KeyError::UnknownKeyType("rsa".into())),
    }
}

/// Checks a phrase and returns it normalised and single-spaced.
///
/// The checksum is verified, not just word membership. A mistyped phrase
/// that is not checked does not fail: it derives a perfectly valid key for
/// an identity nobody owns, and the only symptom is the ledger not
/// recognising it.
pub fn validate(phrase: &str) -> Result<String, KeyError> {
    let words: Vec<&str> = phrase.split_whitespace().collect();

    // 12, 15, 18, 21 and 24 are the only valid lengths.
    if words.len() < 12 || words.len() > 24 || !words.len().is_multiple_of(3) {
        return Err(KeyError::WrongWordCount {
            actual: words.len(),
        });
    }

    let wordlist: Vec<&str> = WORDLIST.split_whitespace().collect();
    debug_assert_eq!(wordlist.len(), 2048);

    let mut bits = String::with_capacity(words.len() * 11);
    for (position, word) in words.iter().enumerate() {
        let index = wordlist
            .iter()
            .position(|candidate| candidate == word)
            .ok_or_else(|| KeyError::UnknownWord {
                position: position + 1,
                word: (*word).to_string(),
            })?;

        bits.push_str(&format!("{index:011b}"));
    }

    let checksum_bits = words.len() / 3;
    let entropy_bits = bits.len() - checksum_bits;

    let entropy: Vec<u8> = bits.as_bytes()[..entropy_bits]
        .chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .fold(0u8, |acc, bit| (acc << 1) | u8::from(*bit == b'1'))
        })
        .collect();

    let expected: String = (0..checksum_bits)
        .map(|bit| {
            if Sha256::digest(&entropy)[0] & (1 << (7 - bit)) != 0 {
                '1'
            } else {
                '0'
            }
        })
        .collect();

    if bits[entropy_bits..] != expected {
        return Err(KeyError::BadChecksum);
    }

    Ok(words.join(" "))
}

/// Turns a recovery phrase into its 64-byte BIP-39 seed.
pub fn to_seed(phrase: &str, passphrase: &str) -> Result<Vec<u8>, KeyError> {
    let normalised = validate(phrase)?;

    // BIP-39's salt: the passphrase is appended to the literal "mnemonic",
    // not passed separately.
    let salt = format!("mnemonic{passphrase}");
    let mut out = vec![0u8; BIP39_SEED_SIZE];
    pbkdf2::pbkdf2_hmac::<Sha512>(normalised.as_bytes(), salt.as_bytes(), ITERATIONS, &mut out);

    Ok(out)
}

/// HKDF-SHA512 with an empty salt.
///
/// An empty salt means a block of zero bytes of the hash length, which is
/// what RFC 5869 specifies -- checked byte for byte against node's
/// `crypto.hkdfSync` and PHP's `hash_hkdf`.
fn hkdf_sha512(ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let mut extract = HmacSha512::new_from_slice(&[0u8; 64]).expect("hmac accepts any key length");
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    let mut out = Vec::with_capacity(length);
    let mut block: Vec<u8> = Vec::new();
    let mut counter = 1u8;

    while out.len() < length {
        let mut expand = HmacSha512::new_from_slice(&prk).expect("hmac accepts any key length");
        expand.update(&block);
        expand.update(info);
        expand.update(&[counter]);
        block = expand.finalize().into_bytes().to_vec();
        out.extend_from_slice(&block);
        counter += 1;
    }

    out.truncate(length);
    out
}

/// Turns a BIP-39 seed into the seed the given key type takes.
pub fn derive_seed(key_type: KeyType, bip39_seed: &[u8]) -> Result<Vec<u8>, KeyError> {
    if bip39_seed.len() != BIP39_SEED_SIZE {
        return Err(KeyError::WrongBip39SeedLength {
            actual: bip39_seed.len(),
        });
    }

    let size = seed_size(key_type)?;

    if key_type == KeyType::Secp256k1 {
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").expect("hmac accepts any key");
        mac.update(bip39_seed);
        return Ok(mac.finalize().into_bytes()[..32].to_vec());
    }

    let info = format!("activeledger-seed-v1:{}", key_type.as_wire());
    Ok(hkdf_sha512(bip39_seed, info.as_bytes(), size))
}
