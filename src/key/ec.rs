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

//! # EC Key
//!
//! This module is used to generate an elliptic curve key, this is generated using
//! the secp256k1 alogrithm.
//!
//! ## Examples
//! ### Create a new key
//! ```
//! # use activeledger::key::EllipticCurve;
//! let ec_key = EllipticCurve::new("key name").unwrap();
//! ```
//!
//! ### Use an existing PEM to create a key object
//! ```
//! # use activeledger::key::EllipticCurve;
//! # use activeledger::key::Pkcs8pem;
//! # let pem = Pkcs8pem::new("", "");
//! // The PEM must be of type Pkcs8pem
//! let ec_key = EllipticCurve::create_from_pem("keyname", &pem);
//! ```
//! ### Sign data
//! ```
//! # use activeledger::key::EllipticCurve;
//! let ec_key = EllipticCurve::new("keyname").unwrap();
//!
//! let signature = ec_key.sign("<Data to sign>").unwrap();
//! ```
//! ### Verify signed data
//! ```
//! # use activeledger::key::EllipticCurve;
//! let ec_key = EllipticCurve::new("keyname").unwrap();
//!
//! let signature = ec_key.sign("<Data to sign>").unwrap();
//!
//! let verification_result = ec_key.verify("<Data to sign>", &signature).unwrap();
//! ```
//! ### Get a stringified version of the keys PEM
//! ```
//! # use activeledger::key::EllipticCurve;
//! let ec_key = EllipticCurve::new("keyname").unwrap();
//!
//! // Get a Pkcs8pem object containing the public private pems as strings
//! let pem = ec_key.get_pem();
//! ```

extern crate openssl;

use std::str;

use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};

use crate::key::Pkcs8pem;

use super::error::{KeyError, KeyResult};

#[path = "int_def.rs"]
mod int_def;
use int_def::{Pkcs8pemBytes, Signing};

#[derive(Clone)]
pub struct EllipticCurve {
    pub name: String,
    pkcs8pem: Pkcs8pemBytes,
}

// Public functions
impl EllipticCurve {
    /// Generate a new EC Key
    ///
    /// # Example
    /// ```
    /// # use activeledger::key::EllipticCurve;
    /// let ec_key = EllipticCurve::new("key name").unwrap();
    /// ```
    pub fn new(name: &str) -> KeyResult<EllipticCurve> {
        let pkcs8pem = EllipticCurve::generate()?;

        Ok(EllipticCurve {
            name: String::from(name),
            pkcs8pem,
        })
    }

    /// Create a new key using a given PEM
    ///
    /// # Example
    /// ```
    /// # use activeledger::key::EllipticCurve;
    /// # use activeledger::key::Pkcs8pem;
    /// # let pem: Pkcs8pem = Pkcs8pem::new("", "");
    /// let ec_key = EllipticCurve::create_from_pem("NAME", &pem);
    /// ```
    pub fn create_from_pem(name: &str, pem: &Pkcs8pem) -> EllipticCurve {
        // Use the given pem to recreate a keypair
        let pkcs8pem = Pkcs8pemBytes::new(
            pem.private.to_string().as_bytes(),
            pem.public.to_string().as_bytes(),
        );

        EllipticCurve {
            name: String::from(name),
            pkcs8pem,
        }
    }

    /// Sign the given data
    ///
    /// # Example
    /// ```
    /// # use activeledger::key::EllipticCurve;
    /// let ec = EllipticCurve::new("keyname").unwrap();
    ///
    /// let signature = ec.sign("Data to sign").unwrap();
    /// ```
    pub fn sign(&self, data: &str) -> KeyResult<String> {
        let keypair = self.get_keypair()?;

        let signature = Signing::sign(&keypair, &data)?;

        Ok(signature)
    }

    /// Verify a signature against some data
    ///
    /// # Example
    /// ```
    /// # use activeledger::key::EllipticCurve;
    /// let ec = EllipticCurve::new("keyname").unwrap();
    ///
    /// let data_to_sign = String::from("Data to sign");
    /// let signature: String = ec.sign(&data_to_sign).unwrap();
    ///
    /// let verify: bool = ec.verify(&data_to_sign, &signature).unwrap();
    /// ```
    pub fn verify(&self, data: &str, signature: &str) -> KeyResult<bool> {
        let keypair = self.get_keypair()?;

        let verified = Signing::verify(&keypair, &data, &signature)?;

        Ok(verified)
    }

    /// Get a keys PEM as string values
    ///
    /// # Example
    /// ```
    /// # use activeledger::key::EllipticCurve;
    /// # use activeledger::key::Pkcs8pem;
    /// let ec = EllipticCurve::new("keyname").unwrap();
    ///
    /// let pem: Pkcs8pem = ec.get_pem().unwrap();
    /// ```
    pub fn get_pem(&self) -> KeyResult<Pkcs8pem> {
        let private_pem = match str::from_utf8(&self.pkcs8pem.private) {
            Ok(pem) => pem,
            Err(_) => return Err(KeyError::StringifyError(3000)),
        };

        let public_pem = match str::from_utf8(&self.pkcs8pem.public) {
            Ok(pem) => pem,
            Err(_) => return Err(KeyError::StringifyError(3001)),
        };

        Ok(Pkcs8pem {
            private: private_pem.to_string(),
            public: public_pem.to_string(),
        })
    }
}

// Private functions
impl EllipticCurve {
    /// Generate the PEM
    fn generate() -> KeyResult<Pkcs8pemBytes> {
        let ec_group = match EcGroup::from_curve_name(Nid::SECP256K1) {
            Ok(group) => group,
            Err(_) => return Err(KeyError::GenerationError(1000)),
        };

        let ec_key = match EcKey::generate(&ec_group) {
            Ok(key) => key,
            Err(_) => return Err(KeyError::GenerationError(1001)),
        };

        let pkey = match PKey::from_ec_key(ec_key) {
            Ok(pkey) => pkey,
            Err(_) => return Err(KeyError::GenerationError(1001)),
        };

        let mut pkcs8pem = Pkcs8pemBytes::new(&vec![], &vec![]);

        pkcs8pem.private = match pkey.private_key_to_pem_pkcs8() {
            Ok(bytes) => bytes,
            Err(_) => return Err(KeyError::GenerationError(1002)),
        };

        // Get the public key PEM
        pkcs8pem.public = match pkey.public_key_to_pem() {
            Ok(bytes) => bytes,
            Err(_) => return Err(KeyError::GenerationError(1003)),
        };

        Ok(pkcs8pem)
    }

    /// Get the PEM keypair in byte form
    fn get_keypair(&self) -> KeyResult<PKey<Private>> {
        let keypair = match EcKey::private_key_from_pem(&self.pkcs8pem.private) {
            Ok(keypair) => keypair,
            Err(_) => return Err(KeyError::SigningError(2007)),
        };

        let keypair = match PKey::from_ec_key(keypair) {
            Ok(keypair) => keypair,
            Err(_) => return Err(KeyError::SigningError(2008)),
        };

        Ok(keypair)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ec_gen() {
        use std::time::Instant;
        let start = Instant::now();
        let key = EllipticCurve::new("Test").unwrap();
        let duration = start.elapsed();

        println!("EC generated in {:?}", duration);

        let string = key.get_pem().unwrap();

        println!("Key pub: {:?}", string.public);

        println!("Key prv: {:?}", string.private);

        // println!("Key {}", key);

        // let pem = key.get_pem().unwrap();
    }

    #[test]
    fn ec_sign() {
        let data_to_sign = String::from("Test data");

        let key = EllipticCurve::new("Test").unwrap();

        let signature = key.sign(&data_to_sign).unwrap();
        println!("EC Sig: {}", signature);

        println!(
            "Verification: {:?}",
            key.verify(&data_to_sign, &signature).unwrap()
        );

        assert!(key.verify(&data_to_sign, &signature).unwrap());
    }
}
