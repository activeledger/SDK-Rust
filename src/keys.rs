//! Key types and signing.

use base64::{engine::general_purpose::STANDARD, Engine};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen as _, SerDes, Signer as _, Verifier as _};

/// Key algorithms, with the exact strings the ledger uses.
///
/// These strings are the whole contract: the ledger validates nothing else
/// about them. A typo, or key material of the wrong length, surfaces as
/// 1220 "Signature Incorrect" and never as "unknown algorithm". The ledger
/// also DEFAULTS a missing type to `rsa` and then attempts RSA
/// verification against whatever it was given, so this SDK always sends the
/// type explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    Rsa,
    Secp256k1,
    MlDsa65,
    Falcon512,
}

impl KeyType {
    pub fn as_wire(&self) -> &'static str {
        match self {
            KeyType::Rsa => "rsa",
            KeyType::Secp256k1 => "secp256k1",
            KeyType::MlDsa65 => "ml-dsa-65",
            KeyType::Falcon512 => "falcon-512",
        }
    }

    /// Parses a wire string. Deliberately strict and case-sensitive: the
    /// ledger compares these exactly, so accepting `ML-DSA-65` here would
    /// only move the failure somewhere less informative.
    pub fn from_wire(wire: &str) -> Result<Self, KeyError> {
        match wire {
            "rsa" => Ok(KeyType::Rsa),
            "secp256k1" => Ok(KeyType::Secp256k1),
            "ml-dsa-65" => Ok(KeyType::MlDsa65),
            "falcon-512" => Ok(KeyType::Falcon512),

            // The ledger routes these to identical secp256k1 verification, so
            // an existing identity may already carry either. Accepted here and
            // NEVER emitted: as_wire always returns "secp256k1".
            "bitcoin" | "ethereum" => Ok(KeyType::Secp256k1),
            other => Err(KeyError::UnknownKeyType(other.to_owned())),
        }
    }

    pub fn is_post_quantum(&self) -> bool {
        matches!(self, KeyType::MlDsa65 | KeyType::Falcon512)
    }
}

/// ML-DSA-65 sizes, fixed by FIPS 204.
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
pub const ML_DSA_65_PRIVATE_KEY_SIZE: usize = 4032;
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("unknown key type '{0}' - expected rsa, secp256k1, ml-dsa-65 or falcon-512")]
    UnknownKeyType(String),

    #[error("{role} key is {actual} bytes, expected {expected}")]
    WrongLength {
        role: &'static str,
        actual: usize,
        expected: usize,
    },

    #[error("{role} key is not valid base64: {source}")]
    NotBase64 {
        role: &'static str,
        #[source]
        source: base64::DecodeError,
    },

    #[error("{role} key was rejected by ML-DSA")]
    Malformed { role: &'static str },

    #[error("this key pair has no private key - it was created for verification only")]
    VerifyOnly,

    #[error(
        "secp256k1 {role} key must start with '0x' - that prefix is part of what the ledger \
         stores, not decoration. Post-quantum keys are base64; these are not."
    )]
    MissingHexPrefix { role: &'static str },

    #[error("secp256k1 {role} key is not valid hex")]
    NotHex { role: &'static str },

    #[error(
        "secp256k1 public key is {actual} bytes, expected 33 (compressed) or 65 (uncompressed)"
    )]
    WrongPublicKeyLength { actual: usize },

    #[error(
        "secp256k1 public key starts with {prefix:#04x}, which does not match its length of \
         {length} bytes (expected 0x02/0x03 for 33, 0x04 for 65)"
    )]
    PointPrefixMismatch { prefix: u8, length: usize },

    #[error("signing failed")]
    SigningFailed,

    #[error(
        "{key_type} needs a {expected}-byte seed, got {actual}. It is refused rather than \
         padded: a padded seed is a different identity, not a malformed one."
    )]
    WrongSeedLength {
        key_type: &'static str,
        actual: usize,
        expected: usize,
    },

    /// A secp256k1 seed IS the private scalar, so it has to be a valid one.
    ///
    /// Refused rather than reduced mod n: reducing produces a perfectly
    /// functional key belonging to a different identity, and nothing
    /// downstream ever reports a problem.
    #[error("seed is not a valid secp256k1 private key - the scalar must be in [1, n-1]")]
    InvalidScalar,

    #[error("a BIP-39 phrase is 12, 15, 18, 21 or 24 words, got {actual}")]
    WrongWordCount { actual: usize },

    #[error("word {position} (\"{word}\") is not in the BIP-39 English wordlist")]
    UnknownWord { position: usize, word: String },

    /// An unchecked phrase is a silent failure, not a loud one: it derives a
    /// perfectly valid key for an identity nobody owns.
    #[error(
        "the BIP-39 checksum does not match - the phrase has a typo or the words are in the \
         wrong order. Deriving from it anyway would produce a valid key for an identity \
         nobody owns."
    )]
    BadChecksum,

    #[error("a BIP-39 seed is 64 bytes, got {actual}")]
    WrongBip39SeedLength { actual: usize },

    /// Falcon-512 identities work on the ledger and are supported by the JS,
    /// JVM and C# SDKs. They are not supported here.
    ///
    /// No pure-Rust Falcon implementation reads the key encoding the ledger
    /// stores: `fn-dsa` cannot decode the ledger's keys at all, which was
    /// established by trying it rather than by reading about it. Returning
    /// this error is the honest outcome; silently producing a key the ledger
    /// would reject as a bad signature is not.
    #[error(
        "falcon-512 is not supported by the Rust SDK - no pure-Rust implementation reads \
         the ledger's key encoding. Use ml-dsa-65, or one of the JS, JVM or C# SDKs."
    )]
    FalconUnsupported,
}

/// Anything that can sign transaction bytes and name its key type.
///
/// A trait rather than a concrete type so a caller can sign elsewhere -- an
/// HSM, a remote signing service, a key in a user's wallet -- without this
/// SDK needing to know about it.
pub trait Signer {
    fn key_type(&self) -> KeyType;
    fn public_key(&self) -> String;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError>;
}

/// An ML-DSA-65 key pair.
#[derive(Clone)]
pub struct KeyPair {
    public: ml_dsa_65::PublicKey,
    private: Option<ml_dsa_65::PrivateKey>,
    public_bytes: Vec<u8>,
    private_bytes: Option<Vec<u8>>,
}

impl KeyPair {
    /// Generates a fresh key pair from the system's secure random source.
    pub fn generate() -> Result<Self, KeyError> {
        let (public, private) = ml_dsa_65::try_keygen().map_err(|_| KeyError::SigningFailed)?;
        let public_bytes = public.clone().into_bytes().to_vec();
        let private_bytes = private.clone().into_bytes().to_vec();
        Ok(Self {
            public,
            private: Some(private),
            public_bytes,
            private_bytes: Some(private_bytes),
        })
    }

    /// Derives a key pair from a 32-byte seed (FIPS 204's xi).
    ///
    /// This is how an ML-DSA-65 private key moves between Activeledger SDKs.
    /// The PHP SDK's private key IS a seed -- its library implements FIPS 204
    /// key generation from a seed but not skEncode/skDecode -- so the
    /// 4032-byte encoding this SDK exports cannot be loaded there. The seed
    /// can be, and gives an identical public key: verified against the
    /// published vectors and against BouncyCastle.
    pub fn from_seed(seed: &[u8]) -> Result<Self, KeyError> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| KeyError::WrongSeedLength {
            key_type: "ml-dsa-65",
            actual: seed.len(),
            expected: 32,
        })?;

        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&seed);
        let public_bytes = public.clone().into_bytes().to_vec();
        let private_bytes = private.clone().into_bytes().to_vec();

        Ok(Self {
            public,
            private: Some(private),
            public_bytes,
            private_bytes: Some(private_bytes),
        })
    }

    /// Derives a key pair from a BIP-39 recovery phrase.
    ///
    /// One phrase can back an ml-dsa-65 and a secp256k1 identity at once:
    /// each type derives its own seed, so neither reveals the other.
    pub fn from_phrase(phrase: &str, passphrase: &str) -> Result<Self, KeyError> {
        let bip39_seed = crate::recovery::to_seed(phrase, passphrase)?;
        let seed = crate::recovery::derive_seed(KeyType::MlDsa65, &bip39_seed)?;
        Self::from_seed(&seed)
    }

    /// A verify-only key pair from a stored public key.
    pub fn from_public(public_key_base64: &str) -> Result<Self, KeyError> {
        let public_bytes = decode(public_key_base64, "public", ML_DSA_65_PUBLIC_KEY_SIZE)?;
        let array: [u8; ML_DSA_65_PUBLIC_KEY_SIZE] = public_bytes
            .clone()
            .try_into()
            .map_err(|_| KeyError::Malformed { role: "public" })?;
        let public = ml_dsa_65::PublicKey::try_from_bytes(array)
            .map_err(|_| KeyError::Malformed { role: "public" })?;
        Ok(Self {
            public,
            private: None,
            public_bytes,
            private_bytes: None,
        })
    }

    /// Restores a signing key pair from stored key material.
    ///
    /// Both halves are required: ML-DSA cannot derive a public key from a
    /// private one, and the ledger stores the two separately anyway.
    pub fn from_keys(public_key_base64: &str, private_key_base64: &str) -> Result<Self, KeyError> {
        let mut pair = Self::from_public(public_key_base64)?;
        let private_bytes = decode(private_key_base64, "private", ML_DSA_65_PRIVATE_KEY_SIZE)?;
        let array: [u8; ML_DSA_65_PRIVATE_KEY_SIZE] = private_bytes
            .clone()
            .try_into()
            .map_err(|_| KeyError::Malformed { role: "private" })?;
        pair.private = Some(
            ml_dsa_65::PrivateKey::try_from_bytes(array)
                .map_err(|_| KeyError::Malformed { role: "private" })?,
        );
        pair.private_bytes = Some(private_bytes);
        Ok(pair)
    }

    /// The public key, base64, exactly as the ledger stores it.
    ///
    /// Named without an encoding because [`Signer::public_key`] is: the
    /// post-quantum schemes are base64 and secp256k1 is hex, and the trait
    /// has to cover both.
    pub fn public_key(&self) -> String {
        STANDARD.encode(&self.public_bytes)
    }

    /// The private key, base64. `None` when this pair can only verify.
    pub fn private_key(&self) -> Option<String> {
        self.private_bytes.as_ref().map(|b| STANDARD.encode(b))
    }

    pub fn can_sign(&self) -> bool {
        self.private.is_some()
    }

    /// Verifies a signature over a message.
    ///
    /// Returns `false` for malformed input rather than erroring: a caller
    /// checking a signature wants a yes or no, and a signature of the wrong
    /// length is simply a no.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match <[u8; ML_DSA_65_SIGNATURE_SIZE]>::try_from(signature) {
            Ok(array) => self.public.verify(message, &array, &[]),
            Err(_) => false,
        }
    }
}

impl Signer for KeyPair {
    fn key_type(&self) -> KeyType {
        KeyType::MlDsa65
    }

    fn public_key(&self) -> String {
        KeyPair::public_key(self)
    }

    /// Signs a message, returning the raw signature.
    ///
    /// Signing is HEDGED: fresh entropy goes into every call, so signing one
    /// message twice gives different bytes. That matches the reference
    /// implementation, and it means a signature can never be compared for
    /// equality -- only verified.
    ///
    /// The context string is empty, which is what the ledger signs with.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let private = self.private.as_ref().ok_or(KeyError::VerifyOnly)?;
        private
            .try_sign(message, &[])
            .map(|sig| sig.to_vec())
            .map_err(|_| KeyError::SigningFailed)
    }
}

impl std::fmt::Debug for KeyPair {
    /// Never prints private key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "KeyPair(ml-dsa-65, {})",
            if self.can_sign() {
                "public+private"
            } else {
                "public only"
            }
        )
    }
}

fn decode(value: &str, role: &'static str, expected: usize) -> Result<Vec<u8>, KeyError> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|source| KeyError::NotBase64 { role, source })?;
    if bytes.len() != expected {
        return Err(KeyError::WrongLength {
            role,
            actual: bytes.len(),
            expected,
        });
    }
    Ok(bytes)
}
