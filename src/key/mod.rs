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

//! # Key
//!
//! The key module handles key generation, data signing, and key importing and exporting.
//!
//! Currently RSA and EC (SECP256K1) keys can be generated.
//! See the various modules below for more information.

mod ec;
mod error;
pub mod export;
pub mod import;
mod rsa;

pub use ec::EllipticCurve;
pub use error::{KeyError, KeyResult};
pub use rsa::RSA;

/// Holds the private and public PEMs as strings
pub struct Pkcs8pem {
    pub private: String,
    pub public: String,
}

impl Pkcs8pem {
    /// Create a new Pkcs8pem
    ///
    /// This function is primarily intended for use within this package.
    /// The recommended way to get a Pkcs8pem is via the get_pem() method
    /// in the key.
    pub fn new(private: &str, public: &str) -> Pkcs8pem {
        Pkcs8pem {
            private: private.to_string(),
            public: public.to_string(),
        }
    }
}
