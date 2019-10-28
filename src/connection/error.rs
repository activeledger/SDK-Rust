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

//! # Connection Error definitions

use std::error::Error;
use std::fmt;

/// ConnectionResult definition - Shorthand for: Result<T, ConnectionError>
pub type ConnectionResult<T> = Result<T, ConnectionError>;

/// ConnectionError data holder
#[derive(Debug)]
pub enum ConnectionError {
    HttpError(u16),       // 1000
    UrlError(u16),        // 2000
    ResponseError(u16),   // 3000
    EncryptionError(u16), // 4000
    EncodingError(u16),   // 5000
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConnectionError::HttpError(ref code) => {
                let error = ConnectionErrorHandler::get_http_error(code);
                write!(f, "HTTP Error - {}: {}", code, error)
            }
            ConnectionError::UrlError(ref code) => {
                let error = ConnectionErrorHandler::get_url_error(code);
                write!(f, "Url Error - {}: {}", code, error)
            }
            ConnectionError::ResponseError(ref code) => {
                let error = ConnectionErrorHandler::get_response_error(code);
                write!(f, "Response Error - {}: {}", code, error)
            }
            ConnectionError::EncryptionError(ref code) => {
                let error = ConnectionErrorHandler::get_encryption_error(code);
                write!(f, "EncryptionError Error - {}: {}", code, error)
            }
            ConnectionError::EncodingError(ref code) => {
                let error = ConnectionErrorHandler::get_encoding_error(code);
                write!(f, "Encoding Error - {}: {}", code, error)
            }
        }
    }
}

impl Error for ConnectionError {}

struct ConnectionErrorHandler;

impl ConnectionErrorHandler {
    fn get_http_error(code: &u16) -> &str {
        match code {
            1000 => "Error POSTing the transaction",
            1001 => "Error during GET request",
            _ => "Unknown Error",
        }
    }

    fn get_url_error(code: &u16) -> &str {
        match code {
            2000 => "Error creating signer",
            _ => "Unknown Error",
        }
    }

    fn get_response_error(code: &u16) -> &str {
        match code {
            3000 => "No response body",
            3001 => "The server did not return 200",
            _ => "Unknown Error",
        }
    }

    fn get_encryption_error(code: &u16) -> &str {
        match code {
            4000 => "Key data missing",
            4001 => "Error creating key data request",
            4002 => "Error processing response",
            4003 => "Unable to parse JSON",
            4004 => "Error preparing key for encryption",
            4005 => "Error creating public key for transaction encryption",
            4006 => "Error generating RSA key for encryption",
            4007 => "Error encrypting transaction",
            _ => "Unknown Error",
        }
    }

    fn get_encoding_error(code: &u16) -> &str {
        match code {
            5000 => "Error generating JSON",
            _ => "Unknown Error",
        }
    }
}
