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

mod connection;
pub mod error;
pub mod transaction;

pub use connection::Connection;

#[cfg(test)]
mod tests {
    use crate::*;
    use serde_json;

    #[test]
    fn connection_url() {
        Connection::new("http://localhost:5260", false).unwrap();
    }

    #[test]
    fn connection_onboard_rsa() {
        let connection = Connection::new("http://localhost:5260", false).unwrap();
        let key = crate::key::RSA::new("Test").unwrap();

        let mut tx_body: serde_json::Value = serde_json::from_str(
            r#"
            {
                "$namespace": "default",
                "$contract": "onboard",
                "$i": {
                    "rsa": {
                        "type":"rsa",
                        "publicKey": ""
                    }
                }
            }
            "#,
        )
        .unwrap();

        let mut tx: serde_json::Value = serde_json::from_str(
            r#"{
                    "$tx": {},
                    "$selfsign": true,
                    "$sigs": {
                        "rsa":""
                    }
                }"#,
        )
        .unwrap();

        let pem = key.get_pem().unwrap();
        tx_body["$i"]["rsa"]["publicKey"] = pem.public.into();

        let signature = key.sign(&tx_body.to_string()).unwrap();

        tx["$tx"] = tx_body.into();
        tx["$sigs"]["rsa"] = signature.into();

        let tx = Transaction::new(&tx.to_string());
        let res = connection.send_transaction(tx).unwrap();

        let data_obj: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert!(data_obj["$streams"].to_string().chars().count() > 0);
    }

    #[test]
    fn connection_onboard_ec() {
        let connection = Connection::new("http://localhost:5260", false).unwrap();
        let key = crate::key::EllipticCurve::new("Test").unwrap();

        let mut tx_body: serde_json::Value = serde_json::from_str(
            r#"
            {
                "$namespace": "default",
                "$contract": "onboard",
                "$i": {
                    "ec": {
                        "type":"secp256k1",
                        "publicKey": ""
                    }
                }
            }
            "#,
        )
        .unwrap();

        let mut tx: serde_json::Value = serde_json::from_str(
            r#"{
                    "$tx": {},
                    "$selfsign": true,
                    "$sigs": {
                        "ec":""
                    }
                }"#,
        )
        .unwrap();

        let pem = key.get_pem().unwrap();
        tx_body["$i"]["ec"]["publicKey"] = pem.public.into();

        let signature = key.sign(&tx_body.to_string()).unwrap();

        tx["$tx"] = tx_body.into();
        tx["$sigs"]["ec"] = signature.into();

        let tx = Transaction::new(&tx.to_string());
        let res = connection.send_transaction(tx).unwrap();

        let data_obj: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert!(data_obj["$streams"].to_string().chars().count() > 0);
    }

    #[test]
    fn connection_enc_tx() {
        let connection = Connection::new("http://localhost:5270", true).unwrap();

        let tx = r#"{
                        "$tx": {
                            "$namespace": "default",
                            "$contract": "onboard",
                            "$i": {
                                "rsaresr2": {
                                    "type":"rsa",
                                    "publicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhJRHkOww8XL68Pdsw4nA\nGUz1xhdIbtrP9lksa0cePR8QPT4gj314fqW6U4J33MJfwMeEF8XAseYsi1vZq63Q\nIU1+TFSvxINcushyy7X8hCqp6cMvrzj1+PhAI2LdK5pbsJQXK7VHNe5ls9JsCtbz\nKTyedzoeXoQma2KJ8FZEfy2m0ElupL4TVgVKm5qac8XirGO3FGVIegnB/Hj/u8+b\nnMDWoZ7leZ0OFAwbPIme6GtodekQjGXvimld2VIicU0KSNvwLAp1QHzPu3AYhiZo\n5FDzFB4klTLp38sGvKua7bXRXVyWO4XK+O59cfTaAlH+KZaf9RTXGfnpifJl/JHc\nkQIDAQAB\n-----END PUBLIC KEY-----"
                                }
                            }
                        },
                        "$selfsign": true,
                        "$sigs": {
                            "rsaresr2":"aOyk5aglk/cjcD6UnV9Ivr0kCNzxTkHyoWHoPx69V0z39q/VL21YVWwcbc4XquWv2FE0k6L1VsW3nCd1W1XlXmHCQXYiU52vllNqoaNSfHyp8BjvyCBAhpKXA4RsAODoX8hOeumeRNzlelFalmDZH228mRD+ck7S+0a/CLImLWs5XXI+zyzNryYVHOV9XoKPHFFzJT2Lm5OqVtI8QUQjPOgVYaTBorMA+FlEmUiTrRyxVaFBvtrZudgbE1yptzW9ztCJkppV6E4iR72o8bcv1aDHi5ihs2M5r6x9lNB+meVnAdnZdFoqG+JmjOVUy4a4tXQZchbCJgwyIDRzgLGUDg=="
                        }
                    }"#;

        let tx = Transaction::new(&tx);
        let res = connection.send_transaction(tx).unwrap();
        println!("Response {}", res);

        let data_obj: serde_json::Value = serde_json::from_str(&res).unwrap();
        assert!(data_obj["$streams"].to_string().chars().count() > 0);
    }
}
