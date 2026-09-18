//! Key types and signing.

use base64::{engine::general_purpose::STANDARD, Engine};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as _, Verifier as _};

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

    #[error("signing failed")]
    SigningFailed,

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
    fn public_key_base64(&self) -> String;
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

    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(&self.public_bytes)
    }

    /// The private key, base64. `None` when this pair can only verify.
    pub fn private_key_base64(&self) -> Option<String> {
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

    fn public_key_base64(&self) -> String {
        KeyPair::public_key_base64(self)
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
