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

//! # Importer
//!
//! The importer module is used to import keys from files.
//!
//! The file passed to the importer must be JSON that matches the expected structure.
//!
//! Currently RSA and EC (SECP256K1) keys can be imported.
//!
//! ## Examples
//! This example will use an RSA key as an example but other keys should
//! use the same process. Examples will be provided if this is not the case.
//! Alternative functions will be listed at the end of the example.
//! ```
//! # use activeledger::key::import;
//! let rsa_key_path = "/path/to/key.json";
//!
//! # let rsa_key_path = "./testfiles/rsa.json";
//!
//! let rsa = import::import_rsa(&rsa_key_path).unwrap();
//! ```
//! The other functions for key importing are:
//!
//! ```
//! # use activeledger::key::import;
//! # let ec_key_path = "./testfiles/ec.json";
//! import::import_ec(ec_key_path).unwrap();
//! ```
//!
//! ## File Structure
//! The file you import should have the following structure, otherwise the import will fail.
//! ```JSON
//! {
//!     "name":"",
//!     "type":"",
//!     "pem": {
//!        "private": "",
//!        "public":""
//!     }
//! }
//! ```

extern crate serde_json;

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str;

use crate::key::Pkcs8pem;

use super::error::{KeyError, KeyResult};
use super::EllipticCurve;
use super::RSA;

struct ImportData {
    name: String,
    pkcs8pem: Pkcs8pem,
}

/// Import an RSA key from the specified file.
///
/// The document must be a JSON file of the expected structure else importing will fail.
/// An template of the structure is provided below if you are importing a file not exported
/// from this SDK.
///
/// # Example
/// ```
/// use activeledger::key::import;
///
/// let rsa_key_path = "/path/to/key.json";
/// # let rsa_key_path = "./testfiles/rsa.json";
/// let rsa = import::import_rsa(&rsa_key_path).unwrap();
/// ```
///
/// ## File Structure
/// The file you import should have the following structure, otherwise the import will fail.
/// ```JSON
/// {
///     "name":"",
///     "type":"",
///     "pem": {
///        "private": "",
///        "public":""
///     }
/// }
/// ```
pub fn import_rsa(path: &str) -> KeyResult<RSA> {
    let rsa_data = import(path, "\"rsa\"")?;

    Ok(RSA::create_from_pem(&rsa_data.name, &rsa_data.pkcs8pem))
}

/// Import an EC (SECP256K1) key from the specified file.
///
/// The document must be a JSON file of the expected structure else importing will fail.
/// An template of the structure is provided below if you are importing a file not exported
/// from this SDK.
///
/// # Example
/// ```
/// use activeledger::key::import;
/// let ec_key_path = "/path/to/key.json";
/// # let ec_key_path = "./testfiles/ec.json";
///
/// let ec = import::import_ec(&ec_key_path).unwrap();
/// ```
///
/// ## File Structure
/// The file you import should have the following structure, otherwise the import will fail.
/// ```JSON
/// {
///     "name":"",
///     "type":"",
///     "pem": {
///        "private": "",
///        "public":""
///     }
/// }
/// ```
pub fn import_ec(path: &str) -> KeyResult<EllipticCurve> {
    let ec_data = import(path, "\"ec\"")?;

    Ok(EllipticCurve::create_from_pem(
        &ec_data.name,
        &ec_data.pkcs8pem,
    ))
}

/// Handle opening the file and returning the contents as JSON
fn import(path: &str, expected_type: &str) -> KeyResult<ImportData> {
    let path = Path::new(path);

    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(_) => return Err(KeyError::ImportError(4000)),
    };

    let mut contents = String::new();

    match file.read_to_string(&mut contents) {
        Ok(_) => (),
        Err(_) => return Err(KeyError::ImportError(4001)),
    };

    let data_obj: serde_json::Value = match serde_json::from_str(&contents) {
        Ok(json) => json,
        Err(_) => return Err(KeyError::ImportError(4001)),
    };

    let name = match data_obj["name"].as_str() {
        Some(data) => data,
        None => return Err(KeyError::ImportError(4001)),
    };

    let pem_public = match data_obj["pem"]["public"].as_str() {
        Some(data) => data,
        None => return Err(KeyError::ImportError(4001)),
    };

    let pem_private = match data_obj["pem"]["private"].as_str() {
        Some(data) => data,
        None => return Err(KeyError::ImportError(4001)),
    };

    if data_obj["type"].to_string() != expected_type {
        return Err(KeyError::ImportError(4002));
    }

    let pkcs8pem = Pkcs8pem {
        public: pem_public.to_string(),
        private: pem_private.to_string(),
    };

    Ok(ImportData {
        name: name.to_string(),
        pkcs8pem,
    })
}

#[cfg(test)]
mod tests {
    use crate::key::import;

    #[test]
    fn import_rsa() {
        import::import_rsa("./testfiles/rsa.json").unwrap();
    }

    #[test]
    fn import_ec() {
        import::import_ec("./testfiles/ec.json").unwrap();
    }
}
