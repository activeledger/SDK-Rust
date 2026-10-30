//! Consumer smoke test: `cargo run --example smoke --offline`.
//!
//! Uses only the crate's public API, the way a dependent crate would. It
//! generates each supported key type, builds and signs transactions, verifies
//! the signatures over the exact signed bytes, and submits to a server on the
//! loopback interface that answers once with a committed reply and once with a
//! rejection carried in an HTTP 200. No ledger and no external network.
//!
//! Exits non-zero (by panicking) on the first failed check.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::JoinHandle;

use activeledger::{Client, KeyPair, KeyType, Object, Secp256k1KeyPair, Signer, Transaction};
use base64::{engine::general_purpose::STANDARD, Engine};

const COMMITTED: &str =
    r#"{"$summary":{"commit":1,"errors":[]},"$streams":{"new":[{"id":"stream-1"}]}}"#;
const REJECTED: &str = r#"{"$summary":{"commit":0,"errors":["1220 Signature Incorrect"]}}"#;

/// Answers the given replies in order, one connection each, all with HTTP 200,
/// and returns the request bodies it received.
fn serve(replies: &'static [&'static str]) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let url = format!("http://{}", listener.local_addr().expect("address"));

    let handle = std::thread::spawn(move || {
        let mut bodies = Vec::new();
        for reply in replies {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut received = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                let n = socket.read(&mut buffer).expect("read");
                received.extend_from_slice(&buffer[..n]);
                let text = String::from_utf8_lossy(&received);
                if let Some(split) = text.find("\r\n\r\n") {
                    let length = text[..split]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if received.len() >= split + 4 + length {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&received).into_owned();
            bodies.push(text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned());

            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{reply}",
                reply.len()
            )
            .expect("reply");
        }
        bodies
    });

    (url, handle)
}

fn check(condition: bool, what: &str) {
    assert!(condition, "smoke check failed: {what}");
    println!("ok   {what}");
}

fn main() {
    let ml_dsa = KeyPair::generate().expect("ml-dsa-65 keygen");
    let compressed = Secp256k1KeyPair::generate();
    let uncompressed = Secp256k1KeyPair::generate_with(false);

    // Every key type signs and verifies, and refuses a different message.
    let message = b"smoke";
    let sig = ml_dsa.sign(message).expect("sign");
    check(ml_dsa.verify(message, &sig), "ml-dsa-65 signature verifies");
    check(
        !ml_dsa.verify(b"other", &sig),
        "ml-dsa-65 rejects another message",
    );
    for (name, key) in [
        ("secp256k1 compressed", &compressed),
        ("secp256k1 uncompressed", &uncompressed),
    ] {
        let sig = key.sign(message).expect("sign");
        check(
            key.verify(message, &sig),
            &format!("{name} signature verifies"),
        );
        check(
            !key.verify(b"other", &sig),
            &format!("{name} rejects another message"),
        );
    }
    check(
        ml_dsa.key_type() == KeyType::MlDsa65,
        "ml-dsa-65 reports its wire type",
    );
    check(
        compressed.key_type().as_wire() == "secp256k1",
        "secp256k1 reports its wire type",
    );

    // Keys survive a round trip through their stored form.
    let restored = KeyPair::from_keys(&ml_dsa.public_key(), &ml_dsa.private_key().unwrap())
        .expect("restore ml-dsa-65");
    check(
        ml_dsa.verify(message, &restored.sign(message).unwrap()),
        "restored ml-dsa-65 key signs for the original",
    );
    let restored =
        Secp256k1KeyPair::from_keys(&compressed.public_key(), &compressed.private_key().unwrap())
            .expect("restore secp256k1");
    check(
        restored.public_key() == compressed.public_key(),
        "restored secp256k1 key matches",
    );

    // A multi-signer transaction: each signature covers the canonical $tx bytes.
    let tx = Transaction::builder()
        .namespace("default")
        .contract("smoke")
        .entry("run")
        .input_with("stream-a", &ml_dsa, Object::new().set("amount", 100))
        .input("stream-b", &compressed)
        .output("stream-c")
        .readonly("ref", "stream-d")
        .build()
        .expect("build");
    let signed = tx.signed_bytes().expect("signed bytes");
    check(tx.sigs().len() == 2, "one signature per input");
    let decode = |label: &str| {
        let (_, sig) = tx.sigs().iter().find(|(l, _)| l == label).expect("label");
        STANDARD.decode(sig).expect("base64 signature")
    };
    check(
        ml_dsa.verify(&signed, &decode("stream-a")),
        "ml-dsa-65 input signature verifies over the signed bytes",
    );
    check(
        compressed.verify(&signed, &decode("stream-b")),
        "secp256k1 input signature verifies over the signed bytes",
    );

    // Onboarding transactions for each type.
    let onboard_ml = Transaction::onboard(&ml_dsa, "identity").expect("onboard");
    check(
        onboard_ml.is_self_signed(),
        "onboard transactions are self-signed",
    );
    check(
        ml_dsa.verify(
            &onboard_ml.signed_bytes().unwrap(),
            &STANDARD.decode(&onboard_ml.sigs()[0].1).unwrap(),
        ),
        "ml-dsa-65 onboard signature verifies",
    );
    let onboard_k1 = Transaction::onboard(&uncompressed, "identity").expect("onboard");
    check(
        uncompressed.verify(
            &onboard_k1.signed_bytes().unwrap(),
            &STANDARD.decode(&onboard_k1.sigs()[0].1).unwrap(),
        ),
        "secp256k1 onboard signature verifies",
    );

    // Submit to the loopback server: a committed reply, then a rejected 200.
    let (url, server) = serve(&[COMMITTED, REJECTED]);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let client = Client::new(url);

        let committed = client.submit(&tx).await.expect("submit");
        check(committed.committed(), "committed reply reads as committed");
        check(
            committed.new_streams() == ["stream-1"],
            "committed reply carries the new stream id",
        );

        let rejected = client
            .submit(&tx)
            .await
            .expect("a 200 rejection is not a transport error");
        check(
            !rejected.committed(),
            "rejected HTTP 200 reply is not committed",
        );
        check(
            rejected.errors() == ["1220 Signature Incorrect"],
            "rejected reply carries the ledger's error",
        );
    });

    let bodies = server.join().expect("server");
    check(
        bodies.len() == 2 && bodies.iter().all(|b| *b == tx.to_json().unwrap()),
        "the server received the exact envelope both times",
    );

    println!("smoke: all checks passed");
}
