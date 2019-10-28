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

//! # RSA Key
//!
//! This module is used to generate or injest an RSA key,
//! used to sign transactions.
//!
//! ## Examples
//! ### Create a new key
//! ```
//! # use activeledger::key::RSA;
//! let rsa_key = RSA::new("keyname").unwrap();
//! ```
//!
//! ### Use an existing PEM to create a key object
//! ```
//! # use activeledger::key::RSA;
//! # use activeledger::key::Pkcs8pem;
//! # let pem = Pkcs8pem::new("", "");
//! // The PEM must be of type Pkcs8pem
//! let rsa_key = RSA::create_from_pem("keyname", &pem);
//! ```
//!
//! ### Sign data
//! ```
//! # use activeledger::key::RSA;
//! let rsa_key = RSA::new("keyname").unwrap();
//!
//! let signature = rsa_key.sign("<Data to sign>").unwrap();
//! ```
//!
//! ### Verify signed data
//! ```
//! # use activeledger::key::RSA;
//! let rsa_key = RSA::new("keyname").unwrap();
//!
//! let signature = rsa_key.sign("<Data to sign>").unwrap();
//!
//! let verification_result = rsa_key.verify("<Data to sign>", &signature).unwrap();
//! ```
//!
//! ### Get a stringified version of the keys PEM
//! ```
//! # use activeledger::key::RSA;
//! let rsa_key = RSA::new("keyname").unwrap();
//!
//! // Get a Pkcs8pem object containing the public private pems as strings
//! let pem = rsa_key.get_pem();
//! ```

extern crate openssl;

use std::str;

use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa as openssl_rsa;

use crate::key::Pkcs8pem;

use super::{KeyError, KeyResult};

#[path = "int_def.rs"]
mod int_def;
use int_def::{Pkcs8pemBytes, Signing};

#[derive(Clone)]
pub struct RSA {
    pub name: String,
    pkcs8pem: Pkcs8pemBytes,
}

// Public functions
impl RSA {
    /// Generate a new RSA key
    ///
    /// # Example
    /// ```
    /// # use activeledger::key::RSA;
    /// let rsa_key = RSA::new("Key name").unwrap();
    /// ```
    pub fn new(name: &str) -> KeyResult<RSA> {
        let pkcs8pem = match RSA::generate() {
            Ok(pem) => pem,
            Err(error) => return Err(error),
        };

        Ok(RSA {
            name: String::from(name),
            pkcs8pem,
        })
    }

    /// Create a new key using a given PEM
    ///
    /// # Example
    /// ```
    /// # use activeledger::key::RSA;
    /// # use activeledger::key::Pkcs8pem;
    /// # let pem = Pkcs8pem::new("", "");
    /// let rsa_key = RSA::create_from_pem("NAME", &pem);
    /// ```
    pub fn create_from_pem(name: &str, pem: &Pkcs8pem) -> RSA {
        // Use the given pem to recreate a keypair
        let pkcs8pem = Pkcs8pemBytes::new(
            pem.private.to_string().as_bytes(),
            pem.public.to_string().as_bytes(),
        );

        RSA {
            name: String::from(name),
            pkcs8pem,
        }
    }

    /// Sign the given data
    ///
    /// # Example
    /// ```
    /// # use activeledger::key::RSA;
    /// let rsa = RSA::new("keyname").unwrap();
    ///
    /// let signature = rsa.sign("Data to sign").unwrap();
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
    /// # use activeledger::key::RSA;
    /// let rsa = RSA::new("keyname").unwrap();
    ///
    /// let data_to_sign = String::from("Data to sign");
    /// let signature: String = rsa.sign(&data_to_sign).unwrap();
    ///
    /// let verify: bool = rsa.verify(&data_to_sign, &signature).unwrap();
    /// ```
    pub fn verify(&self, data: &str, signature: &str) -> KeyResult<bool> {
        let keypair = self.get_keypair()?;

        let verification = Signing::verify(&keypair, &data, &signature)?;

        Ok(verification)
    }

    /// Get a keys PEM as string values
    ///
    /// # Example
    /// ```
    /// # use activeledger::key::RSA;
    /// # use activeledger::key::Pkcs8pem;
    /// let rsa = RSA::new("keyname").unwrap();
    ///
    /// let pem: Pkcs8pem = rsa.get_pem().unwrap();
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

impl RSA {
    /// Generate the PEM of the RSA keypair
    fn generate() -> KeyResult<Pkcs8pemBytes> {
        // Generate the keypair with openssl
        let rsa = match openssl_rsa::generate(2048) {
            Ok(rsa) => rsa,
            Err(_) => return Err(KeyError::GenerationError(1004)),
        };

        // Get the private key PEM
        let private = match rsa.private_key_to_pem() {
            Ok(bytes) => bytes,
            Err(_) => return Err(KeyError::GenerationError(1005)),
        };

        // Get the public key PEM
        let public = match rsa.public_key_to_pem() {
            Ok(bytes) => bytes,
            Err(_) => return Err(KeyError::GenerationError(1006)),
        };

        Ok(Pkcs8pemBytes::new(&private, &public))
    }

    /// Get the PEM keypair in their byte form
    fn get_keypair(&self) -> KeyResult<PKey<Private>> {
        // Generate private key from pem
        let keypair = match openssl_rsa::private_key_from_pem(&self.pkcs8pem.private) {
            Ok(keypair) => keypair,
            Err(_) => return Err(KeyError::SigningError(2007)),
        };

        // Handle the public key
        let keypair = match PKey::from_rsa(keypair) {
            Ok(keypair) => keypair,
            Err(_) => return Err(KeyError::SigningError(2008)),
        };

        Ok(keypair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_gen() {
        use std::time::Instant;
        let start = Instant::now();
        let key = RSA::new("Test").unwrap();
        let duration = start.elapsed();

        let start2 = Instant::now();
        let pem = key.get_pem().unwrap();
        let duration_of_pem_stringification = start2.elapsed();
        let overall_duration = start.elapsed();

        println!(
            "Private PEM: \n{}\n Public PEM: \n{}\n",
            pem.private, pem.public
        );
        println!("RSA Generation time: {:?}", duration);
        println!(
            "RSA PEM stringification time: {:?}",
            duration_of_pem_stringification
        );
        println!("RSA Overall time: {:?}", overall_duration);
    }

    #[test]
    fn rsa_sign() {
        let sig_data = String::from("I am test data");

        let key = RSA::new("Test").unwrap();

        let signature = key.sign(&sig_data).unwrap();
        println!("Sig {}", signature);

        println!(
            "Verification: {:?}",
            key.verify(&sig_data, &signature).unwrap()
        );

        assert!(key.verify(&sig_data, &signature).unwrap());
    }
}
