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

use base64;
use openssl;
use reqwest;
use serde_json;

use base64::{decode, encode};

use openssl::{pkey::PKey, rsa::Padding};

use super::error::{
    ConnectionError::{EncryptionError, HttpError, ResponseError},
    ConnectionResult,
};

use crate::Transaction;

/// # Connection
///
/// The connection section of the Activeledger SDK handles creating a connection
/// to a specific instance of Activeledger.
///
/// It also handles sending a transaction (The active_txbuilder crate can be
/// used to generate transactions)
///
/// ## Examples
/// ### Create a new connection
/// ```
/// # use activeledger::Connection;
/// // Create a new unencrypted connection to a node on localhost
/// let connection = Connection::new("http://localhost:5260", false).unwrap();
/// ```
///
/// ### Send a transaction
/// ```
/// # use activeledger::{Connection, error::ConnectionError, Transaction};
/// // Create a new unencrypted connection to a node on localhost
/// let connection = Connection::new("http://localhost:5260", false).unwrap();
///
/// // Define the transaction data (JSON)
/// let transaction_data = "{TX DATA HERE}";
///
/// # let transaction_data = r#"{
/// #   "$tx": {
/// #       "$namespace": "default",
/// #       "$contract": "onboard",
/// #       "$i": {
/// #           "rsaresr2": {
/// #               "type":"rsa",
/// #               "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhJRHkOww8XL68Pdsw4nA\nGUz1xhdIbtrP9lksa0cePR8QPT4gj314fqW6U4J33MJfwMeEF8XAseYsi1vZq63Q\nIU1+TFSvxINcushyy7X8hCqp6cMvrzj1+PhAI2LdK5pbsJQXK7VHNe5ls9JsCtbz\nKTyedzoeXoQma2KJ8FZEfy2m0ElupL4TVgVKm5qac8XirGO3FGVIegnB/Hj/u8+b\nnMDWoZ7leZ0OFAwbPIme6GtodekQjGXvimld2VIicU0KSNvwLAp1QHzPu3AYhiZo\n5FDzFB4klTLp38sGvKua7bXRXVyWO4XK+O59cfTaAlH+KZaf9RTXGfnpifJl/JHc\nkQIDAQAB\n-----END PUBLIC KEY-----"
/// #            }
/// #        }
/// #     },
/// #    "$selfsign": true,
/// #    "$sigs": {
/// #       "rsaresr2":"aOyk5aglk/cjcD6UnV9Ivr0kCNzxTkHyoWHoPx69V0z39q/VL21YVWwcbc4XquWv2FE0k6L1VsW3nCd1W1XlXmHCQXYiU52vllNqoaNSfHyp8BjvyCBAhpKXA4RsAODoX8hOeumeRNzlelFalmDZH228mRD+ck7S+0a/CLImLWs5XXI+zyzNryYVHOV9XoKPHFFzJT2Lm5OqVtI8QUQjPOgVYaTBorMA+FlEmUiTrRyxVaFBvtrZudgbE1yptzW9ztCJkppV6E4iR72o8bcv1aDHi5ihs2M5r6x9lNB+meVnAdnZdFoqG+JmjOVUy4a4tXQZchbCJgwyIDRzgLGUDg=="
/// #    }
/// # }"#;
/// // Create a new transaction
/// let transaction = Transaction::new(transaction_data);
///
/// // Send the transaction to the node specified when creating the connection
/// connection.send_transaction(transaction).unwrap();
/// ```
///
/// ### Send an encrypted transaction
/// ```
/// # use activeledger::{Connection, error::ConnectionError, Transaction};
/// // Create a new encrypted transaction
/// let connection = Connection::new("http://localhost:5260", true).unwrap();
///
/// // Define the transaction data (JSON)
/// let transaction_data = "{TX DATA HERE}";
///
/// # let transaction_data = r#"{
/// #   "$tx": {
/// #       "$namespace": "default",
/// #       "$contract": "onboard",
/// #       "$i": {
/// #           "rsaresr2": {
/// #               "type":"rsa",
/// #               "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhJRHkOww8XL68Pdsw4nA\nGUz1xhdIbtrP9lksa0cePR8QPT4gj314fqW6U4J33MJfwMeEF8XAseYsi1vZq63Q\nIU1+TFSvxINcushyy7X8hCqp6cMvrzj1+PhAI2LdK5pbsJQXK7VHNe5ls9JsCtbz\nKTyedzoeXoQma2KJ8FZEfy2m0ElupL4TVgVKm5qac8XirGO3FGVIegnB/Hj/u8+b\nnMDWoZ7leZ0OFAwbPIme6GtodekQjGXvimld2VIicU0KSNvwLAp1QHzPu3AYhiZo\n5FDzFB4klTLp38sGvKua7bXRXVyWO4XK+O59cfTaAlH+KZaf9RTXGfnpifJl/JHc\nkQIDAQAB\n-----END PUBLIC KEY-----"
/// #            }
/// #        }
/// #     },
/// #    "$selfsign": true,
/// #    "$sigs": {
/// #       "rsaresr2":"aOyk5aglk/cjcD6UnV9Ivr0kCNzxTkHyoWHoPx69V0z39q/VL21YVWwcbc4XquWv2FE0k6L1VsW3nCd1W1XlXmHCQXYiU52vllNqoaNSfHyp8BjvyCBAhpKXA4RsAODoX8hOeumeRNzlelFalmDZH228mRD+ck7S+0a/CLImLWs5XXI+zyzNryYVHOV9XoKPHFFzJT2Lm5OqVtI8QUQjPOgVYaTBorMA+FlEmUiTrRyxVaFBvtrZudgbE1yptzW9ztCJkppV6E4iR72o8bcv1aDHi5ihs2M5r6x9lNB+meVnAdnZdFoqG+JmjOVUy4a4tXQZchbCJgwyIDRzgLGUDg=="
/// #    }
/// # }"#;
/// // Create a new transaction
/// let transaction = Transaction::new(transaction_data);
///
/// // Send the transaction to the node specified when creating the connection
/// connection.send_transaction(transaction).unwrap();
/// ```
pub struct Connection {
    url: String,
    encrypt: bool,
    node_key_data: Option<NodeKeyData>,
}

/// NodeKeyData struct
/// Used when sending encrypted transactions
struct NodeKeyData {
    _encryption: String, // Future usage if Activeledger provides multiple encryption keys
    pem: String,
}

// Public functions

impl Connection {
    /// Create a new Connection to an Activledger node
    /// # Example
    /// ## Non encrypted transactions
    /// ```
    /// # use activeledger::Connection;
    /// let connection = Connection::new("http://localhost:5260", false).unwrap();
    /// ```
    /// ## Encrypted transactions
    /// ```
    /// # use activeledger::Connection;
    /// let connection = Connection::new("http://localhost:5260", true).unwrap();
    /// ```
    pub fn new(url: &str, encrypt: bool) -> ConnectionResult<Connection> {
        let mut node_key_data = None;

        // If encrypt is true we should get the key data now instead of each tx run
        if encrypt {
            node_key_data = Some(Connection::get_node_key_data(url)?);
        }

        let connection = Connection {
            url: url.to_string(),
            encrypt,
            node_key_data,
        };

        // If connection test successful return Ok
        Connection::test_connection(&connection)?;

        Ok(connection)
    }

    /// Send a transaction via this connection
    /// # Example
    /// ```
    /// # use activeledger::{Connection, Transaction};
    /// // Create a connection
    /// let connection = Connection::new("http://localhost:5260", false).unwrap();
    /// # let connection = Connection::new("http://localhost:5280", false).unwrap();
    ///
    /// // Define transaction data (JSON)
    /// let transaction_data = "{Transaction Data}";
    ///
    /// # let transaction_data = r#"{
    /// #   "$tx": {
    /// #       "$namespace": "default",
    /// #       "$contract": "onboard",
    /// #       "$i": {
    /// #           "rsaresr2": {
    /// #               "type":"rsa",
    /// #               "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhJRHkOww8XL68Pdsw4nA\nGUz1xhdIbtrP9lksa0cePR8QPT4gj314fqW6U4J33MJfwMeEF8XAseYsi1vZq63Q\nIU1+TFSvxINcushyy7X8hCqp6cMvrzj1+PhAI2LdK5pbsJQXK7VHNe5ls9JsCtbz\nKTyedzoeXoQma2KJ8FZEfy2m0ElupL4TVgVKm5qac8XirGO3FGVIegnB/Hj/u8+b\nnMDWoZ7leZ0OFAwbPIme6GtodekQjGXvimld2VIicU0KSNvwLAp1QHzPu3AYhiZo\n5FDzFB4klTLp38sGvKua7bXRXVyWO4XK+O59cfTaAlH+KZaf9RTXGfnpifJl/JHc\nkQIDAQAB\n-----END PUBLIC KEY-----"
    /// #            }
    /// #        }
    /// #     },
    /// #    "$selfsign": true,
    /// #    "$sigs": {
    /// #       "rsaresr2":"aOyk5aglk/cjcD6UnV9Ivr0kCNzxTkHyoWHoPx69V0z39q/VL21YVWwcbc4XquWv2FE0k6L1VsW3nCd1W1XlXmHCQXYiU52vllNqoaNSfHyp8BjvyCBAhpKXA4RsAODoX8hOeumeRNzlelFalmDZH228mRD+ck7S+0a/CLImLWs5XXI+zyzNryYVHOV9XoKPHFFzJT2Lm5OqVtI8QUQjPOgVYaTBorMA+FlEmUiTrRyxVaFBvtrZudgbE1yptzW9ztCJkppV6E4iR72o8bcv1aDHi5ihs2M5r6x9lNB+meVnAdnZdFoqG+JmjOVUy4a4tXQZchbCJgwyIDRzgLGUDg=="
    /// #    }
    /// # }"#;
    /// // Create the transaction
    /// let transaction = Transaction::new(transaction_data);
    ///
    /// // Send the tranasction to the node defined when creating the connection
    /// let response = connection.send_transaction(transaction).unwrap();
    /// ```
    pub fn send_transaction(&self, tx: Transaction) -> ConnectionResult<String> {
        let client = reqwest::Client::new();

        let mut client = client.post(&self.url);

        let mut post_data = tx.get_data().to_string();

        // Encrypt the data if needed
        if self.encrypt {
            let key_data = match &self.node_key_data {
                Some(key_data) => key_data,
                None => return Err(EncryptionError(4000)),
            };

            post_data = Connection::encrypt(&key_data, &post_data)?;

            client = client.header("X-Activeledger-Encrypt", "1");
        }

        // Post the transaction to the node
        let mut response = match client.body(post_data).send() {
            Ok(response) => response,
            Err(_) => return Err(HttpError(1000)),
        };

        // If the status isn't 200 throw an error
        if response.status().is_success() {
            match response.text() {
                Ok(body) => {
                    println!("{:?}", body);
                    Ok(body)
                }
                Err(_) => return Err(ResponseError(3000)),
            }
        } else {
            Err(ResponseError(3001))
        }
    }
}

// Private functions

impl Connection {
    /// Get the PEM from a Node and return it as a NodeKeyData struct
    fn get_node_key_data(url: &str) -> ConnectionResult<NodeKeyData> {
        let url = format!("{}/a/status", url);
        let mut response = match reqwest::get(&url) {
            Ok(val) => val,
            Err(_) => return Err(EncryptionError(4001)),
        };

        // Check if response code is 200
        if !response.status().is_success() {
            return Err(ResponseError(3001));
        }

        let body = match response.text() {
            Ok(body) => body,
            Err(_) => return Err(EncryptionError(4002)),
        };

        let data_obj: serde_json::Value = match serde_json::from_str(&body) {
            Ok(json) => json,
            Err(_) => return Err(EncryptionError(4003)),
        };

        let pem = match data_obj["pem"].as_str() {
            Some(pem) => pem,
            None => return Err(EncryptionError(4003)),
        };

        Ok(NodeKeyData {
            _encryption: String::from("rsa"),
            pem: pem.to_string(),
        })
    }

    /// Encrypt the transaction
    fn encrypt(node_key_data: &NodeKeyData, tx: &str) -> ConnectionResult<String> {
        // Base64 decode the PEM
        let pem = match decode(&node_key_data.pem) {
            Ok(pem) => pem,
            Err(err) => {
                println!("{}", err);
                return Err(EncryptionError(4004));
            }
        };

        // Create a new public key only
        let key = match PKey::public_key_from_pem(&pem) {
            Ok(key) => key,
            Err(_) => return Err(EncryptionError(4005)),
        };

        // Get the RSA version of the key
        let rsa = match key.rsa() {
            Ok(rsa) => rsa,
            Err(_) => return Err(EncryptionError(4006)),
        };

        // Chunck the transaction to avoid data limits
        let tx_chunks: Vec<&[u8]> = tx.as_bytes().chunks(100).collect();

        // Initialise the end encrypted data holder as an empty string
        let mut encrypted_data_holder = String::from("");

        // Encrypt the chunks and append them to the data holder
        for chunk in tx_chunks {
            let mut buffer = vec![0; rsa.size() as usize];
            match rsa.public_encrypt(chunk, &mut buffer, Padding::PKCS1_OAEP) {
                Ok(_) => (),
                Err(_) => return Err(EncryptionError(4007)),
            };

            // Activeledger splits on | so add that to the string between chunks
            encrypted_data_holder = format!("{}{}|", &encrypted_data_holder, &encode(&buffer));
        }

        // Return the data with the final | stripped off the end
        return Ok(encrypted_data_holder[0..(encrypted_data_holder.len() - 1)].to_string());
    }

    fn test_connection(connection: &Connection) -> ConnectionResult<()> {
        let url = format!("{}/a/status", connection.url);

        match reqwest::get(&url) {
            Ok(_) => Ok(()),
            Err(_) => return Err(HttpError(1001)),
        }
    }
}
