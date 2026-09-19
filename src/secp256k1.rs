//! secp256k1, encoded the way Activeledger stores it.
//!
//! Kept apart from the post-quantum [`crate::KeyPair`] because almost nothing
//! is shared. Those keys are raw bytes in base64; these are hex with an `0x`
//! prefix. Those signatures are fixed-length raw blobs; these are
//! variable-length DER. Folding them together invites the one mistake that
//! matters here -- reusing a base64 path for a hex key, which produces
//! material the ledger rejects as 1220 "Signature Incorrect" while saying
//! nothing else.

use base64::{engine::general_purpose::STANDARD, Engine};
use k256::ecdsa::signature::{Signer as _, Verifier as _};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::rand_core::OsRng;

use crate::keys::{KeyError, KeyType, Signer};

/// Compressed SEC1 public key length.
pub const PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;
/// Uncompressed SEC1 public key length.
pub const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
/// The private scalar, always left-padded to this.
pub const PRIVATE_KEY_SIZE: usize = 32;

/// A secp256k1 key pair.
#[derive(Clone)]
pub struct Secp256k1KeyPair {
    verifying: VerifyingKey,
    signing: Option<SigningKey>,
    public_bytes: Vec<u8>,
}

impl Secp256k1KeyPair {
    /// Generates a key pair, with a compressed public key.
    ///
    /// Compressed by default: 33 bytes rather than 65, and this key is written
    /// into a transaction and then stored on an identity stream permanently.
    pub fn generate() -> Self {
        Self::generate_with(true)
    }

    /// Generates a key pair, choosing the public key form.
    ///
    /// The ledger accepts both, and tells them apart by length.
    pub fn generate_with(compressed: bool) -> Self {
        let signing = SigningKey::random(&mut OsRng);
        let verifying = *signing.verifying_key();

        Self {
            public_bytes: verifying.to_encoded_point(compressed).as_bytes().to_vec(),
            verifying,
            signing: Some(signing),
        }
    }

    /// Derives a key pair from a 32-byte seed.
    ///
    /// For secp256k1 the seed IS the private scalar -- there is no key
    /// derivation step -- which is why it has to be a valid one. A scalar of
    /// zero, or one at or above the group order, is refused rather than
    /// reduced mod n: reducing produces a perfectly functional key belonging
    /// to a different identity, and nothing downstream ever reports a
    /// problem.
    pub fn from_seed(seed: &[u8], compressed: bool) -> Result<Self, KeyError> {
        if seed.len() != PRIVATE_KEY_SIZE {
            return Err(KeyError::WrongSeedLength {
                key_type: "secp256k1",
                actual: seed.len(),
                expected: PRIVATE_KEY_SIZE,
            });
        }

        // from_slice rejects an out-of-range scalar rather than reducing it,
        // which is the behaviour wanted here.
        let signing = SigningKey::from_slice(seed).map_err(|_| KeyError::InvalidScalar)?;
        let verifying = *signing.verifying_key();

        Ok(Self {
            public_bytes: verifying.to_encoded_point(compressed).as_bytes().to_vec(),
            verifying,
            signing: Some(signing),
        })
    }

    /// Derives a key pair from a BIP-39 recovery phrase.
    pub fn from_phrase(phrase: &str, passphrase: &str, compressed: bool) -> Result<Self, KeyError> {
        let bip39_seed = crate::recovery::to_seed(phrase, passphrase)?;
        let seed = crate::recovery::derive_seed(KeyType::Secp256k1, &bip39_seed)?;
        Self::from_seed(&seed, compressed)
    }

    /// Recovers a key pair from a phrase made by `@activeledger/sdk-bip39`.
    ///
    /// That scheme is SHA256(phrase) used directly as the scalar -- no key
    /// stretching, no domain separation, no passphrase. It exists so an old
    /// phrase can be recovered, never so a new key can be made with it.
    ///
    /// Deliberately does NOT validate the mnemonic: the original package
    /// hashed the string as given and never consulted the wordlist, so
    /// rejecting a phrase here that it accepted would make a recoverable
    /// identity unrecoverable.
    pub fn from_legacy_phrase(phrase: &str, compressed: bool) -> Result<Self, KeyError> {
        use sha2::{Digest, Sha256};

        Self::from_seed(&Sha256::digest(phrase.as_bytes()), compressed)
    }

    /// A verify-only key pair from a stored public key.
    pub fn from_public(public_key: &str) -> Result<Self, KeyError> {
        let bytes = decode_hex(public_key, "public")?;
        check_public(&bytes)?;

        let verifying = VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|_| KeyError::Malformed { role: "public" })?;

        Ok(Self {
            verifying,
            signing: None,
            public_bytes: bytes,
        })
    }

    /// Restores a signing key pair from stored key material.
    pub fn from_keys(public_key: &str, private_key: &str) -> Result<Self, KeyError> {
        let mut pair = Self::from_public(public_key)?;

        let scalar = decode_hex(private_key, "private")?;
        if scalar.len() != PRIVATE_KEY_SIZE {
            return Err(KeyError::WrongLength {
                role: "private",
                actual: scalar.len(),
                expected: PRIVATE_KEY_SIZE,
            });
        }

        pair.signing = Some(
            SigningKey::from_slice(&scalar).map_err(|_| KeyError::Malformed { role: "private" })?,
        );
        Ok(pair)
    }

    /// The public key, `0x`-prefixed hex, exactly as the ledger stores it.
    pub fn public_key(&self) -> String {
        encode_hex(&self.public_bytes)
    }

    /// The private key, `0x`-prefixed hex. `None` when verify-only.
    ///
    /// Always 32 bytes: the scalar is left-padded, because a shorter value is
    /// a different scalar to anything that reads it strictly.
    pub fn private_key(&self) -> Option<String> {
        self.signing.as_ref().map(|k| encode_hex(&k.to_bytes()))
    }

    pub fn can_sign(&self) -> bool {
        self.signing.is_some()
    }

    /// Verifies a signature, accepting HIGH-S as well as low.
    ///
    /// `k256` rejects high-S outright, and that default is wrong here: the
    /// ledger verifies through OpenSSL, which neither normalises nor requires
    /// low-S, so roughly half of everything it produces is high-S. Measured
    /// against the published vectors, the unmodified `k256` path rejects 7 of
    /// 12 valid signatures.
    ///
    /// `(r, s)` and `(r, n - s)` are the same signature, so normalising first
    /// accepts either form without weakening anything: a tampered message, a
    /// wrong key and malformed bytes all still fail.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(parsed) = Signature::from_der(signature) else {
            return false;
        };

        let normalised = parsed.normalize_s().unwrap_or(parsed);
        self.verifying.verify(message, &normalised).is_ok()
    }
}

impl Signer for Secp256k1KeyPair {
    fn key_type(&self) -> KeyType {
        KeyType::Secp256k1
    }

    fn public_key(&self) -> String {
        Secp256k1KeyPair::public_key(self)
    }

    /// Signs, deterministically and low-S.
    ///
    /// Both properties come from `k256` rather than being applied here, and
    /// both are load-bearing.
    ///
    /// **Deterministic k (RFC 6979)** is about testability, not security. The
    /// same key and message give the same bytes in every correct
    /// implementation, so exact expected bytes can be published as
    /// cross-language vectors -- and an exact comparison is the only kind of
    /// test that can catch a low-S regression. A verify-round-trip test
    /// passes just as happily on a high-S signature.
    ///
    /// **Low S** is not for the ledger, which accepts either. It is for
    /// `@noble/curves`, the reference for the JavaScript side, and for
    /// libsecp256k1 -- both reject high-S by default. A signer emitting high-S
    /// half the time fails against them half the time, which reads as
    /// flakiness rather than as a signature format problem.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let key = self.signing.as_ref().ok_or(KeyError::VerifyOnly)?;
        let signature: Signature = key.sign(message);

        Ok(signature.to_der().as_bytes().to_vec())
    }
}

impl std::fmt::Debug for Secp256k1KeyPair {
    /// Never prints private key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Secp256k1KeyPair({})",
            if self.can_sign() {
                "public+private"
            } else {
                "public only"
            }
        )
    }
}

/// True when a DER signature's S is in the upper half of the curve order.
///
/// Exposed because a test that cannot tell the two apart cannot prove this
/// SDK emits only low-S, nor that it still accepts high-S from elsewhere.
pub fn is_high_s(signature: &[u8]) -> bool {
    Signature::from_der(signature)
        .map(|s| s.normalize_s().is_some())
        .unwrap_or(false)
}

/// True when a base64 DER signature's S is high.
pub fn is_high_s_base64(signature: &str) -> bool {
    STANDARD
        .decode(signature)
        .map(|bytes| is_high_s(&bytes))
        .unwrap_or(false)
}

fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Decodes an `0x`-prefixed hex key.
///
/// The prefix is required rather than tolerated: it is part of what the ledger
/// stores, and a hex string without it can decode as base64 into
/// plausible-looking bytes of the wrong length.
fn decode_hex(value: &str, role: &'static str) -> Result<Vec<u8>, KeyError> {
    let body = value
        .strip_prefix("0x")
        .ok_or(KeyError::MissingHexPrefix { role })?;

    hex::decode(body).map_err(|_| KeyError::NotHex { role })
}

/// Checks a public key's length and that its SEC1 prefix agrees with it.
fn check_public(bytes: &[u8]) -> Result<(), KeyError> {
    let compressed = match bytes.len() {
        PUBLIC_KEY_COMPRESSED_SIZE => true,
        PUBLIC_KEY_UNCOMPRESSED_SIZE => false,
        other => {
            return Err(KeyError::WrongPublicKeyLength { actual: other });
        }
    };

    let prefix = bytes[0];
    let ok = if compressed {
        prefix == 0x02 || prefix == 0x03
    } else {
        prefix == 0x04
    };

    if ok {
        Ok(())
    } else {
        Err(KeyError::PointPrefixMismatch {
            prefix,
            length: bytes.len(),
        })
    }
}
