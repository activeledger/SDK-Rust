//! Shared access to the vectors published by the ledger repository.

use std::sync::OnceLock;

#[allow(dead_code)]
pub struct Vector {
    pub key_type: String,
    pub public_key_form: String,
    pub deterministic_signature: String,
    pub message_name: String,
    pub message: String,
    pub public_key: String,
    pub private_key: String,
    pub signature: String,
}

fn load() -> &'static Vec<Vector> {
    static VECTORS: OnceLock<Vec<Vector>> = OnceLock::new();
    VECTORS.get_or_init(|| {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/pq-vectors.json"
        ))
        .expect("vector file");
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("vector json");
        doc["vectors"]
            .as_array()
            .expect("vectors array")
            .iter()
            .map(|v| Vector {
                key_type: v["type"].as_str().unwrap().to_owned(),
                public_key_form: v["publicKeyForm"].as_str().unwrap_or("").to_owned(),
                deterministic_signature: v["deterministicSignature"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
                message_name: v["messageName"].as_str().unwrap().to_owned(),
                message: v["message"].as_str().unwrap().to_owned(),
                public_key: v["publicKey"].as_str().unwrap().to_owned(),
                private_key: v["privateKey"].as_str().unwrap().to_owned(),
                signature: v["signature"].as_str().unwrap().to_owned(),
            })
            .collect()
    })
}

#[allow(dead_code)]
pub fn all() -> &'static [Vector] {
    load()
}

/// Only the secp256k1 vectors.
#[allow(dead_code)]
pub fn secp256k1() -> impl Iterator<Item = &'static Vector> {
    load().iter().filter(|v| v.key_type == "secp256k1")
}

/// Only the ML-DSA-65 vectors. Falcon is deliberately unsupported here.
#[allow(dead_code)]
pub fn ml_dsa() -> impl Iterator<Item = &'static Vector> {
    load().iter().filter(|v| v.key_type == "ml-dsa-65")
}

/// The canonical JSON the reference produced for a named message.
#[allow(dead_code)]
pub fn reference(name: &str) -> String {
    load()
        .iter()
        .find(|v| v.message_name == name)
        .unwrap_or_else(|| panic!("no vector named {name}"))
        .message
        .clone()
}
