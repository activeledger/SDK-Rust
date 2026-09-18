//! Runs against a real 4-node Activeledger network.
//!
//! Every other test here checks this SDK against a published file. This one
//! checks it against a running ledger, which is the only thing that actually
//! decides whether a signature is acceptable -- the type string, the `$sigs`
//! keying and the exact signed bytes are all invisible to a unit test, and
//! all three fail as the same unhelpful 1220.
//!
//! Start the network from an activeledger checkout:
//!
//! ```text
//! npm run test:network:serve
//! ```
//!
//! then run with the URLs it prints:
//!
//! ```text
//! AL_NODES=http://127.0.0.1:5510 AL_STORAGE=http://127.0.0.1:5509 cargo test --test live
//! ```
//!
//! Skips when `AL_NODES` is unset, so `cargo test` works with no ledger.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::StreamExt;

use activeledger::keys::ML_DSA_65_PUBLIC_KEY_SIZE;
use activeledger::{Client, KeyPair, Object, Transaction};

fn nodes() -> Vec<String> {
    split("AL_NODES")
}

fn storage() -> Vec<String> {
    split("AL_STORAGE")
}

fn split(var: &str) -> Vec<String> {
    std::env::var(var)
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A real skip is not available in Rust's test harness, so this prints why
/// it did nothing. A silent early return would report coverage nobody has.
macro_rules! require_network {
    () => {{
        let nodes = nodes();
        if nodes.is_empty() {
            eprintln!("SKIP: AL_NODES not set - start 'npm run test:network:serve'");
            return;
        }
        nodes
    }};
}

/// Namespaces are claimed permanently, so a fixed name passes once and fails
/// every re-run against the same network -- which reads exactly like a
/// regression and is not one.
fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}{}", nanos % 100_000_000)
}

/// Reads a document straight from a node's storage service.
///
/// Deliberately in the test and NOT in the SDK: storage listens only on the
/// node's own host, so a real client cannot reach it and reads state through
/// a transaction's `$r` instead. This harness runs locally, where storage is
/// reachable by definition, and it is used here to assert what the ledger
/// RECORDED rather than what a contract chose to report.
async fn storage_read(index: usize, id: &str) -> Option<serde_json::Value> {
    let base = storage().get(index)?.trim_end_matches('/').to_owned();
    let url = format!("{base}/activeledger/{}", urlencode(id));
    let body = reqwest::get(&url).await.ok()?.text().await.ok()?;
    serde_json::from_str(&body).ok()
}

fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// Waits for a stream's metadata to appear on a given node.
///
/// Consensus is a majority, so the origin's reply means MOST nodes have
/// committed and the rest may still be writing. Reading immediately is a
/// race that fails a few percent of the time and looks like flakiness in the
/// SDK rather than in the test.
async fn await_authorities(node: usize, stream_id: &str) -> serde_json::Value {
    for _ in 0..40 {
        if let Some(meta) = storage_read(node, &format!("{stream_id}:stream")).await {
            if let Some(authorities) = meta.get("authorities").and_then(|a| a.as_array()) {
                if !authorities.is_empty() {
                    return serde_json::Value::Array(authorities.clone());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("stream meta for {stream_id} never appeared on node {node}");
}

#[tokio::test]
async fn an_identity_onboards_and_is_recorded_correctly() {
    let nodes = require_network!();
    assert!(!storage().is_empty(), "AL_STORAGE is needed for this test");

    let client = Client::new(&nodes[0]);
    let key = KeyPair::generate().unwrap();
    let identity = client.onboard(&key).await.expect("onboard");
    assert!(!identity.stream_id.is_empty());

    let authorities = await_authorities(0, &identity.stream_id).await;
    let authority = &authorities[0];

    // The type the LEDGER stored. If this is "rsa", the SDK omitted it and
    // every later signature would fail verification.
    assert_eq!(Some("ml-dsa-65"), authority["type"].as_str());

    let stored = authority["public"].as_str().expect("public key");
    assert_eq!(key.public_key_base64(), stored);
    assert_eq!(
        ML_DSA_65_PUBLIC_KEY_SIZE,
        STANDARD.decode(stored).unwrap().len()
    );
}

#[tokio::test]
async fn a_transaction_signed_by_this_sdk_is_accepted() {
    let nodes = require_network!();

    let client = Client::new(&nodes[0]);
    let key = KeyPair::generate().unwrap();
    let identity = client.onboard(&key).await.expect("onboard");

    let tx = Transaction::builder()
        .namespace("default")
        .contract("namespace")
        .input_with(
            &identity.stream_id,
            &key,
            Object::new().set("namespace", unique("rust")),
        )
        .build()
        .unwrap();

    let response = client.submit(&tx).await.expect("submit");
    assert!(response.committed(), "rejected: {}", response.raw());
}

/// Without this the suite would pass against a ledger that accepted
/// everything, which would make every test above meaningless.
#[tokio::test]
async fn a_tampered_payload_is_rejected() {
    let nodes = require_network!();

    let client = Client::new(&nodes[0]);
    let key = KeyPair::generate().unwrap();
    let identity = client.onboard(&key).await.expect("onboard");

    let honest = Transaction::builder()
        .namespace("default")
        .contract("namespace")
        .input_with(
            &identity.stream_id,
            &key,
            Object::new().set("namespace", unique("rusttamper")),
        )
        .build()
        .unwrap();

    // Same signature, different body. Submitted raw, because the builder
    // would re-sign it into a valid transaction.
    let tampered = honest
        .to_json()
        .unwrap()
        .replace("rusttamper", "ruststolen");

    let response = client.submit_raw(&tampered).await.expect("submit");
    assert!(
        !response.committed(),
        "a tampered payload was accepted: {}",
        response.raw()
    );
}

#[tokio::test]
async fn an_identity_onboarded_here_is_visible_from_every_node() {
    let nodes = require_network!();
    assert!(!storage().is_empty(), "AL_STORAGE is needed for this test");

    let client = Client::new(&nodes[0]);
    let key = KeyPair::generate().unwrap();
    let identity = client.onboard(&key).await.expect("onboard");

    for node in 0..storage().len() {
        let authorities = await_authorities(node, &identity.stream_id).await;
        assert_eq!(Some("ml-dsa-65"), authorities[0]["type"].as_str());
    }
}

/// SSE against a real Activeledger event stream.
///
/// Aimed at the storage engine's `/activeledgerevents/events`, because that
/// is what this harness runs: Activecore, which serves the remote-facing
/// `/api/activity` and `/api/events` feeds, is a separate service and is not
/// started here. Storage listens only on the node's own host, so this is NOT
/// how a real client subscribes -- but it is a genuine ledger SSE endpoint.
///
/// What this proves, and the parser tests cannot: the request headers are
/// acceptable to a real server, the response is not rejected, and events
/// arrive over a real socket with real chunk boundaries.
///
/// It does not assert event DELIVERY, because events exist only when a
/// contract emits one -- observing a payload would mean deploying an
/// emitting contract from here, and the ledger's own harness already covers
/// delivery across all four nodes.
#[tokio::test]
async fn subscribing_to_a_real_node_opens_and_holds_the_stream() {
    require_network!();
    let storage = storage();
    if storage.is_empty() {
        eprintln!("SKIP: AL_STORAGE not set");
        return;
    }

    let endpoint = format!(
        "{}/activeledgerevents/events",
        storage[0].trim_end_matches('/')
    );
    let client = Client::new(&nodes()[0]);

    let mut stream = Box::pin(client.subscribe(&endpoint).await.expect("subscribe"));

    // A refused or immediately-closed stream ends within milliseconds; a
    // healthy one simply has nothing to say yet.
    match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
        Err(_) => { /* still open after 5s, which is the point */ }
        Ok(None) => panic!("the stream closed on its own"),
        Ok(Some(Err(error))) => panic!("the stream failed: {error}"),
        Ok(Some(Ok(_))) => { /* an event arrived, which is also fine */ }
    }
}

/// Pointing a subscription at the node rather than Activecore is the easy
/// mistake, and the node's answer (403) must surface as an error rather than
/// as a stream that never produces anything.
#[tokio::test]
async fn subscribing_to_the_node_port_is_reported_as_an_error() {
    let nodes = require_network!();
    let client = Client::new(&nodes[0]);

    assert!(
        client.subscribe("/api/events").await.is_err(),
        "a node's 403 was not reported"
    );
}
