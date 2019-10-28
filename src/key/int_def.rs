/*
 * MIT License (MIT)
 * Copyright (c) 2019 Activeledger
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

//! Internal definitions
//! The code in this file is intended to be used by code in this crate

extern crate base64;
extern crate openssl;

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::{Signer, Verifier};

use base64::{decode, encode};

use crate::key::{KeyError, KeyResult};

/// PEM byte holder
#[derive(Debug, Clone)]
pub struct Pkcs8pemBytes {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

impl Pkcs8pemBytes {
    /// Create a new PEM Byte holder object
    pub fn new(private: &[u8], public: &[u8]) -> Pkcs8pemBytes {
        Pkcs8pemBytes {
            private: private.to_vec(),
            public: public.to_vec(),
        }
    }
}

/// Siging function holder
pub struct Signing;

impl Signing {
    /// Sign given data using the given keypair and data
    pub fn sign(keypair: &PKey<Private>, data: &str) -> KeyResult<String> {
        // Create a signer
        let mut signer = match Signer::new(MessageDigest::sha256(), &keypair) {
            Ok(signer) => signer,
            Err(_) => return Err(KeyError::SigningError(2000)),
        };

        // Add data to signer
        match signer.update(data.as_bytes()) {
            Ok(_) => (),
            Err(_) => {
                return Err(KeyError::SigningError(2001));
            }
        };

        // Get the signature as a vector of bytes
        let signature_bytes = match signer.sign_to_vec() {
            Ok(sig) => sig,
            Err(_) => {
                return Err(KeyError::SigningError(2002));
            }
        };

        Ok(encode(&signature_bytes))
    }

    /// Verify a signature using the given keypair and data
    pub fn verify(keypair: &PKey<Private>, data: &str, signature: &str) -> KeyResult<bool> {
        // Decode the signature (base64 encoded)
        let signature_bytes = match decode(signature) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(KeyError::SigningError(2003));
            }
        };

        // Initialise the OpenSSL verifier
        let mut verifier = match Verifier::new(MessageDigest::sha256(), &keypair) {
            Ok(verifier) => verifier,
            Err(_) => {
                return Err(KeyError::SigningError(2004));
            }
        };

        // Give it the data
        match verifier.update(data.as_bytes()) {
            Ok(_) => (),
            Err(_) => {
                return Err(KeyError::SigningError(2005));
            }
        };

        // Run verification on the given signature
        match verifier.verify(&signature_bytes) {
            Ok(result) => return Ok(result),
            Err(_) => {
                return Err(KeyError::SigningError(2006));
            }
        };
    }
}
