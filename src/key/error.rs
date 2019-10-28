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

//! # Key Error definitions

use std::error::Error;
use std::fmt;

/// KeyResult definition - Shorthand for: Result<T, KeyError>
pub type KeyResult<T> = Result<T, KeyError>;

/// KeyError data holder
#[derive(Debug)]
pub enum KeyError {
    GenerationError(u16), // 1000
    SigningError(u16),    // 2000
    StringifyError(u16),  // 3000
    ImportError(u16),     // 4000
    ExportError(u16),     // 5000
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeyError::GenerationError(ref code) => {
                let error = KeyErrorHandler::get_generation_error(code);
                write!(f, "Generation Error - {}: {}", code, error)
            }
            KeyError::SigningError(ref code) => {
                let error = KeyErrorHandler::get_signing_error(code);
                write!(f, "Signing Error - {}: {}", code, error)
            }
            KeyError::StringifyError(ref code) => {
                let error = KeyErrorHandler::get_stringify_error(code);
                write!(f, "Stringify Error - {}: {}", code, error)
            }
            KeyError::ImportError(ref code) => {
                let error = KeyErrorHandler::get_import_error(code);
                write!(f, "Import Error - {}: {}", code, error)
            }
            KeyError::ExportError(ref code) => {
                let error = KeyErrorHandler::get_export_error(code);
                write!(f, "Export Error - {}: {}", code, error)
            }
        }
    }
}

impl Error for KeyError {}

struct KeyErrorHandler;

impl KeyErrorHandler {
    fn get_generation_error(code: &u16) -> &str {
        match code {
            // EC
            1000 => "Error generating Elliptic Curve Group for keygen",
            1001 => "Error generating Elliptic Curve Keypair",
            1002 => "Error generating Elliptic Curve Private PEM",
            1003 => "Error generating Elliptic Curve Public PEM",

            // RSA
            1004 => "Error generating the RSA Key",
            1005 => "Error generating RSA Private PEM",
            1006 => "Error generating RSA Public PEM",
            _ => "Unknown Error",
        }
    }

    fn get_signing_error(code: &u16) -> &str {
        match code {
            2000 => "Error creating signer",
            2001 => "Error passing data to sign",
            2002 => "Error generating signature",
            2003 => "Error decoding signature for verification",
            2004 => "Error creating verifier",
            2005 => "Error passing data to verify",
            2006 => "Signature verification failed",
            2007 => "Error initialising private key",
            2008 => "Error initialising public key",
            _ => "Unknown Error",
        }
    }

    fn get_stringify_error(code: &u16) -> &str {
        match code {
            3000 => "Error converting private pem to string",
            3001 => "Error converting public pem to string",
            3007 => "Error initialising private key",
            3008 => "Error initialising public key",
            _ => "Unknown Error",
        }
    }

    fn get_import_error(code: &u16) -> &str {
        match code {
            4000 => "Error opening file for import",
            4001 => "Error reading file contents",
            4002 => "Key Type missmatch",
            _ => "Unknown Error",
        }
    }

    fn get_export_error(code: &u16) -> &str {
        match code {
            5000 => "Error generating JSON",
            5001 => "Error preparing the export file for writing",
            5002 => "Error writing to the export file",
            _ => "Unknown Error",
        }
    }
}
