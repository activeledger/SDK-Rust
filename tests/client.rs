//! The client against a throwaway server on the loopback interface.
//!
//! `Response` has no public constructor, so the only way to reach its parsing
//! is a real HTTP exchange. Each test starts a one-shot server on 127.0.0.1
//! that records the request it receives and sends back a canned reply, so
//! nothing leaves the machine and nothing needs a ledger.

// The event API is deprecated; its behaviour stays tested until it is removed.
#![allow(deprecated)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::JoinHandle;

use futures_util::StreamExt;

use activeledger::{Client, ClientError, KeyPair, Object, Transaction};

/// Serves exactly one request with `reply` and returns what it received.
fn serve(status: &str, content_type: &str, reply: &'static str) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        reply.len()
    );

    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        let mut received = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let n = socket.read(&mut buffer).expect("read");
            received.extend_from_slice(&buffer[..n]);
            let text = String::from_utf8_lossy(&received).into_owned();
            if let Some(split) = text.find("\r\n\r\n") {
                let length = text[..split]
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
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
        socket.write_all(head.as_bytes()).expect("head");
        socket.write_all(reply.as_bytes()).expect("body");
        String::from_utf8_lossy(&received).into_owned()
    });

    (url, handle)
}

async fn submit(reply: &'static str) -> activeledger::Response {
    let (url, server) = serve("200 OK", "application/json", reply);
    let response = Client::new(url).submit_raw("{}").await.expect("submit");
    server.join().expect("server");
    response
}

#[tokio::test]
async fn a_reply_with_errors_is_not_committed_despite_http_200() {
    let response = submit(r#"{"$summary":{"errors":["1220 Signature Incorrect","bad"]}}"#).await;

    assert!(!response.committed());
    assert_eq!(vec!["1220 Signature Incorrect", "bad"], response.errors());
}

#[tokio::test]
async fn a_reply_with_an_empty_error_list_is_committed() {
    let response = submit(r#"{"$summary":{"errors":[],"commit":1}}"#).await;

    assert!(response.committed());
    assert!(response.errors().is_empty());
}

#[tokio::test]
async fn non_string_errors_are_reported_as_json_text() {
    let response = submit(r#"{"$summary":{"errors":[{"code":1220},42]}}"#).await;

    assert_eq!(vec![r#"{"code":1220}"#, "42"], response.errors());
    assert!(!response.committed());
}

/// Documented behaviour: a body that is not JSON carries no `$summary`, so it
/// reads as committed. The caller has to check `raw()` when that matters.
#[tokio::test]
async fn a_non_json_body_reads_as_committed_and_is_kept_verbatim() {
    let response = submit("<html>502 Bad Gateway</html>").await;

    assert!(response.committed());
    assert!(response.errors().is_empty());
    assert!(response.new_streams().is_empty());
    assert!(response.responses().is_empty());
    assert_eq!("<html>502 Bad Gateway</html>", response.raw());
}

#[tokio::test]
async fn an_empty_body_does_not_panic() {
    let response = submit("").await;

    assert_eq!("", response.raw());
    assert!(response.errors().is_empty());
}

#[tokio::test]
async fn wrongly_shaped_json_yields_empty_accessors() {
    let response =
        submit(r#"{"$summary":{"errors":"oops"},"$streams":{"new":7},"$responses":"x"}"#).await;

    assert!(response.errors().is_empty());
    assert!(response.new_streams().is_empty());
    assert!(response.responses().is_empty());
}

#[tokio::test]
async fn new_streams_returns_ids_and_skips_entries_without_one() {
    let response =
        submit(r#"{"$streams":{"new":[{"id":"abc"},{"name":"no id"},{"id":7},{"id":"def"}]}}"#)
            .await;

    assert_eq!(vec!["abc", "def"], response.new_streams());
}

#[tokio::test]
async fn contract_responses_come_back_in_order() {
    let response = submit(r#"{"$responses":[{"a":1},"two",null]}"#).await;

    let responses = response.responses();
    assert_eq!(3, responses.len());
    assert_eq!(serde_json::json!({"a": 1}), responses[0]);
    assert_eq!(serde_json::json!("two"), responses[1]);
    assert!(responses[2].is_null());
}

#[tokio::test]
async fn submit_posts_the_envelope_as_json_to_the_root_path() {
    let key = KeyPair::generate().expect("generate");
    let tx = Transaction::builder()
        .namespace("default")
        .contract("c")
        .input_with("s1", &key, Object::new().set("n", 1))
        .build()
        .expect("build");

    let (url, server) = serve("200 OK", "application/json", "{}");
    // A trailing slash on the base URL must not produce a "//" path.
    Client::new(format!("{url}/"))
        .submit(&tx)
        .await
        .expect("submit");
    let request = server.join().expect("server");

    assert!(request.starts_with("POST / HTTP/1.1\r\n"), "{request}");
    assert!(request
        .to_ascii_lowercase()
        .contains("content-type: application/json"));
    let body = request.split("\r\n\r\n").nth(1).expect("body");
    assert_eq!(tx.to_json().unwrap(), body);
}

#[tokio::test]
async fn onboard_returns_the_new_stream_and_the_signers_key() {
    let key = KeyPair::generate().expect("generate");
    let (url, server) = serve(
        "200 OK",
        "application/json",
        r#"{"$streams":{"new":[{"id":"stream-1"}]}}"#,
    );

    let identity = Client::new(url).onboard(&key).await.expect("onboard");
    let request = server.join().expect("server");

    assert_eq!("stream-1", identity.stream_id);
    assert_eq!(activeledger::Signer::public_key(&key), identity.public_key);
    assert!(request.contains(r#""$selfsign":true"#), "{request}");
}

#[tokio::test]
async fn a_rejected_onboard_is_an_error_carrying_the_raw_reply() {
    let key = KeyPair::generate().expect("generate");
    let (url, server) = serve(
        "200 OK",
        "application/json",
        r#"{"$summary":{"errors":["nope"]}}"#,
    );

    let error = Client::new(url).onboard(&key).await.expect_err("must fail");
    server.join().expect("server");

    match error {
        ClientError::OnboardFailed(raw) => assert_eq!(r#"{"$summary":{"errors":["nope"]}}"#, raw),
        other => panic!("expected OnboardFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unreachable_node_is_an_http_error() {
    // Bind then drop, so the port is known to be closed.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let error = Client::new(format!("http://127.0.0.1:{port}"))
        .submit_raw("{}")
        .await
        .expect_err("nothing is listening");

    assert!(matches!(error, ClientError::Http(_)), "{error:?}");
}

#[test]
fn urls_are_stored_without_trailing_slashes() {
    let client = Client::new("http://node:5260///").with_core("http://core:5261/");

    assert_eq!("http://node:5260", client.base_url());
    assert_eq!(Some("http://core:5261"), client.core_url());
    assert_eq!(None, Client::new("http://node").core_url());
}

#[tokio::test]
async fn event_subscriptions_without_a_core_url_say_so() {
    let client = Client::new("http://127.0.0.1:1");

    assert!(matches!(
        client.subscribe_to_activity(None).await.err(),
        Some(ClientError::NoCoreUrl)
    ));
    assert!(matches!(
        client.subscribe_to_contract_events(None, None).await.err(),
        Some(ClientError::NoCoreUrl)
    ));
}

#[tokio::test]
async fn an_event_name_without_a_contract_is_refused() {
    let client = Client::new("http://127.0.0.1:1").with_core("http://127.0.0.1:1");

    assert!(matches!(
        client
            .subscribe_to_contract_events(None, Some("ev"))
            .await
            .err(),
        Some(ClientError::EventWithoutContract)
    ));
}

#[tokio::test]
async fn a_rejected_subscription_is_an_error_not_an_empty_stream() {
    let (url, server) = serve("403 Forbidden", "text/plain", "no");

    let result = Client::new("http://127.0.0.1:1")
        .with_core(url)
        .subscribe_to_activity(None)
        .await;
    server.join().expect("server");

    assert!(matches!(result.err(), Some(ClientError::Http(_))));
}

async fn requested_path(
    call: impl FnOnce(Client) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>,
) -> String {
    let (url, server) = serve("200 OK", "text/event-stream", "");
    call(Client::new("http://127.0.0.1:1").with_core(url)).await;
    let request = server.join().expect("server");
    request.lines().next().expect("request line").to_owned()
}

#[tokio::test]
async fn subscription_paths_are_built_and_percent_encoded() {
    let line = requested_path(|c| {
        Box::pin(async move {
            c.subscribe_to_activity(None).await.map(drop).unwrap();
        })
    })
    .await;
    assert_eq!("GET /api/activity/subscribe HTTP/1.1", line);

    let line = requested_path(|c| {
        Box::pin(async move {
            c.subscribe_to_activity(Some("a b/c"))
                .await
                .map(drop)
                .unwrap();
        })
    })
    .await;
    assert_eq!("GET /api/activity/subscribe/a%20b%2Fc HTTP/1.1", line);

    let line = requested_path(|c| {
        Box::pin(async move {
            c.subscribe_to_contract_events(None, None)
                .await
                .map(drop)
                .unwrap();
        })
    })
    .await;
    assert_eq!("GET /api/events HTTP/1.1", line);

    let line = requested_path(|c| {
        Box::pin(async move {
            c.subscribe_to_contract_events(Some("my contract"), None)
                .await
                .map(drop)
                .unwrap();
        })
    })
    .await;
    assert_eq!("GET /api/events/my%20contract HTTP/1.1", line);

    let line = requested_path(|c| {
        Box::pin(async move {
            c.subscribe_to_contract_events(Some("c"), Some("é"))
                .await
                .map(drop)
                .unwrap();
        })
    })
    .await;
    assert_eq!("GET /api/events/c/%C3%A9 HTTP/1.1", line);
}

#[tokio::test]
async fn a_subscription_delivers_parsed_events_and_ends_with_the_connection() {
    let (url, server) = serve(
        "200 OK",
        "text/event-stream",
        ": heartbeat\n\nevent: ping\nid: 1\ndata: one\n\ndata: two",
    );

    let stream = Client::new("http://127.0.0.1:1")
        .with_core(url)
        .subscribe_to_activity(None)
        .await
        .expect("subscribe");
    let events: Vec<_> = stream.collect().await;
    let request = server.join().expect("server");

    assert!(request
        .to_ascii_lowercase()
        .contains("accept: text/event-stream"));
    assert_eq!(2, events.len());
    let first = events[0].as_ref().expect("event");
    assert_eq!(Some("ping".to_owned()), first.name);
    assert_eq!(Some("1".to_owned()), first.id);
    assert_eq!("one", first.data);
    // The unterminated final event is flushed when the connection closes.
    assert_eq!("two", events[1].as_ref().expect("event").data);
}
