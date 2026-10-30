//! The client against throwaway loopback servers: HTTP client injection,
//! timeouts, onboard failures and broken event streams.
//!
//! Nothing leaves the machine and nothing needs a ledger. Each server handles
//! one connection on 127.0.0.1 and hands back what it received.

// The event API is deprecated; its behaviour stays tested until it is removed.
#![allow(deprecated)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use futures_util::StreamExt;

use activeledger::{Client, ClientError, KeyPair, Secp256k1KeyPair, TransactionError};

/// Reads one HTTP request (head plus any Content-Length body).
fn read_request(socket: &mut TcpStream) -> String {
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
    String::from_utf8_lossy(&received).into_owned()
}

/// Answers one request with exactly `response` and returns the request.
fn serve_bytes(response: String) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        let request = read_request(&mut socket);
        socket.write_all(response.as_bytes()).expect("write");
        request
    });
    (url, handle)
}

fn serve(status: &str, content_type: &str, body: &str) -> (String, JoinHandle<String>) {
    serve_bytes(format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    ))
}

#[tokio::test]
async fn a_supplied_http_client_is_the_one_that_makes_the_request() {
    let (url, server) = serve("200 OK", "application/json", "{}");
    let http = reqwest::Client::builder()
        .user_agent("sdk-test-agent/9")
        .build()
        .expect("client");

    Client::new(url)
        .with_http(http)
        .submit_raw("{}")
        .await
        .expect("submit");

    let request = server.join().expect("server").to_ascii_lowercase();
    assert!(
        request.contains("user-agent: sdk-test-agent/9"),
        "{request}"
    );
}

#[tokio::test]
async fn a_timeout_on_the_supplied_client_surfaces_as_a_timeout_error() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let (release, wait) = mpsc::channel::<()>();

    // Accepts and reads the request but never answers, until told to let go.
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        read_request(&mut socket);
        let _ = wait.recv();
    });

    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(150))
        .build()
        .expect("client");
    let result = Client::new(url).with_http(http).submit_raw("{}").await;
    release.send(()).expect("release server");
    server.join().expect("server");

    match result {
        Err(ClientError::Http(error)) => assert!(error.is_timeout(), "{error}"),
        other => panic!("expected a timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn a_malformed_base_url_is_an_http_error_not_a_panic() {
    let result = Client::new("not a url").submit_raw("{}").await;
    assert!(matches!(result, Err(ClientError::Http(_))), "{result:?}");
}

/// The ledger answers rejections with 200, but a gateway may answer 4xx/5xx
/// with the same JSON. The reply is still parsed, not thrown away.
#[tokio::test]
async fn a_json_error_body_under_a_failing_status_is_still_reported_as_errors() {
    let (url, server) = serve(
        "500 Internal Server Error",
        "application/json",
        r#"{"$summary":{"errors":["1301 Contract Missing"]}}"#,
    );

    let response = Client::new(url).submit_raw("{}").await.expect("reply");
    server.join().expect("server");

    assert!(!response.committed());
    assert_eq!(vec!["1301 Contract Missing"], response.errors());
}

#[tokio::test]
async fn onboard_fails_when_the_reply_names_no_new_stream() {
    let reply = r#"{"$summary":{"commit":1},"$streams":{"new":[]}}"#;
    let (url, server) = serve("200 OK", "application/json", reply);

    let error = Client::new(url)
        .onboard(&KeyPair::generate().expect("keygen"))
        .await
        .unwrap_err();
    server.join().expect("server");

    match error {
        ClientError::OnboardFailed(raw) => assert_eq!(reply, raw),
        other => panic!("expected OnboardFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn onboard_failure_keeps_a_non_json_reply_for_diagnosis() {
    let (url, server) = serve("502 Bad Gateway", "text/html", "<html>bad gateway</html>");

    let error = Client::new(url)
        .onboard(&Secp256k1KeyPair::generate())
        .await
        .unwrap_err();
    server.join().expect("server");

    assert_eq!(
        "onboard failed: <html>bad gateway</html>",
        error.to_string()
    );
}

#[tokio::test]
async fn onboard_takes_the_first_new_stream_when_there_are_several() {
    let (url, server) = serve(
        "200 OK",
        "application/json",
        r#"{"$streams":{"new":[{"id":"first"},{"id":"second"}]}}"#,
    );

    let identity = Client::new(url)
        .onboard(&KeyPair::generate().expect("keygen"))
        .await
        .expect("onboard");
    server.join().expect("server");

    assert_eq!("first", identity.stream_id);
}

/// The type string travels with the key; a missing one would be read as rsa.
#[tokio::test]
async fn onboard_sends_the_signers_type_and_self_sign_marker() {
    let (url, server) = serve(
        "200 OK",
        "application/json",
        r#"{"$streams":{"new":[{"id":"s"}]}}"#,
    );
    let key = Secp256k1KeyPair::generate();

    let identity = Client::new(url).onboard(&key).await.expect("onboard");
    let request = server.join().expect("server");
    let body = request.split("\r\n\r\n").nth(1).expect("body");
    let sent: serde_json::Value = serde_json::from_str(body).expect("json body");

    assert_eq!(key.public_key(), identity.public_key);
    assert_eq!(sent["$selfsign"], true);
    assert_eq!(sent["$tx"]["$i"]["identity"]["type"], "secp256k1");
    assert_eq!(sent["$tx"]["$i"]["identity"]["publicKey"], key.public_key());
    assert!(sent["$sigs"]["identity"].is_string());
}

#[test]
fn client_errors_display_the_underlying_messages() {
    let missing = ClientError::from(TransactionError::MissingContract);
    assert_eq!("contract is required", missing.to_string());

    let no_core = ClientError::NoCoreUrl.to_string();
    assert!(no_core.contains("Client::with_core"), "{no_core}");

    assert_eq!(
        "an event name needs the contract it belongs to",
        ClientError::EventWithoutContract.to_string()
    );
}

#[tokio::test]
async fn a_relative_subscription_path_goes_to_the_node_not_the_core() {
    let (node, server) = serve("200 OK", "text/event-stream", "data: x\n\n");

    let stream = Client::new(node)
        .with_core("http://127.0.0.1:1")
        .subscribe("/some/feed")
        .await
        .expect("subscribe");
    let events: Vec<_> = stream.collect().await;
    let request = server.join().expect("server");

    assert_eq!(
        "GET /some/feed HTTP/1.1",
        request.lines().next().expect("request line")
    );
    assert_eq!(1, events.len());
}

#[tokio::test]
async fn an_absolute_subscription_url_ignores_the_configured_urls() {
    let (target, server) = serve("200 OK", "text/event-stream", "data: y\n\n");

    let stream = Client::new("http://127.0.0.1:1")
        .subscribe(&format!("{target}/elsewhere"))
        .await
        .expect("subscribe");
    let events: Vec<_> = stream.collect().await;
    let request = server.join().expect("server");

    assert_eq!(
        "GET /elsewhere HTTP/1.1",
        request.lines().next().expect("request line")
    );
    assert_eq!("y", events[0].as_ref().expect("event").data);
}

#[tokio::test]
async fn a_connection_cut_mid_stream_yields_an_error_after_the_events_already_sent() {
    // Promises 500 bytes, delivers one event, then closes.
    let (url, server) = serve_bytes(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\nContent-Length: 500\r\n\r\ndata: before\n\n"
            .to_owned(),
    );

    let stream = Client::new(url)
        .subscribe("/feed")
        .await
        .expect("subscribe");
    let items: Vec<_> = stream.collect().await;
    server.join().expect("server");

    assert_eq!(2, items.len(), "{items:?}");
    assert_eq!("before", items[0].as_ref().expect("first event").data);
    assert!(matches!(items[1], Err(ClientError::Http(_))), "{items:?}");
}

#[tokio::test]
async fn a_subscription_refused_with_a_status_reports_that_status() {
    let (url, server) = serve("404 Not Found", "text/plain", "nope");

    let result = Client::new(url).subscribe("/missing").await;
    server.join().expect("server");

    match result {
        Err(ClientError::Http(error)) => {
            assert_eq!(Some(reqwest::StatusCode::NOT_FOUND), error.status())
        }
        Ok(_) => panic!("a 404 must not become an empty stream"),
        Err(other) => panic!("unexpected error {other:?}"),
    }
}
