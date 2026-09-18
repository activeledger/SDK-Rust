//! Talking to a node.

use futures_util::stream::{Stream, StreamExt};

use crate::events::{Event, EventParser};
use crate::keys::Signer;
use crate::transaction::{Transaction, TransactionError};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    Transaction(#[from] TransactionError),

    #[error(transparent)]
    Canonical(#[from] crate::canonical::CanonicalError),

    #[error("onboard failed: {0}")]
    OnboardFailed(String),

    /// Event streams are served by Activecore, a separate service from the
    /// node. Defaulting to the node URL would turn a missing Activecore into
    /// a 403 that suggests a permissions problem instead.
    #[error(
        "no Activecore URL was configured - event streams are served by Activecore, \
         a separate service from the node. Pass it to Client::with_core."
    )]
    NoCoreUrl,

    #[error("an event name needs the contract it belongs to")]
    EventWithoutContract,
}

/// The ledger's reply to a submitted transaction.
#[derive(Debug, Clone)]
pub struct Response {
    raw: String,
    parsed: Option<serde_json::Value>,
}

impl Response {
    fn new(raw: String) -> Self {
        let parsed = serde_json::from_str(&raw).ok();
        Self { raw, parsed }
    }

    /// The response body exactly as the node sent it.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Errors the network reported.
    ///
    /// Non-empty means the transaction did NOT commit, even though the HTTP
    /// status was 200. The ledger answers 200 for a rejected transaction, so
    /// treating HTTP success as ledger success is wrong -- and wrong in a way
    /// that looks fine until something important silently did not happen.
    pub fn errors(&self) -> Vec<String> {
        self.parsed
            .as_ref()
            .and_then(|v| v.get("$summary"))
            .and_then(|s| s.get("errors"))
            .and_then(|e| e.as_array())
            .map(|items| {
                items
                    .iter()
                    .map(|i| match i.as_str() {
                        Some(s) => s.to_owned(),
                        None => i.to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// True when [`Response::errors`] is empty. This, not the HTTP status.
    pub fn committed(&self) -> bool {
        self.errors().is_empty()
    }

    /// Stream ids this transaction created.
    pub fn new_streams(&self) -> Vec<String> {
        self.parsed
            .as_ref()
            .and_then(|v| v.get("$streams"))
            .and_then(|s| s.get("new"))
            .and_then(|n| n.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|i| i.get("id").and_then(|id| id.as_str()))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Values contracts handed back with `returnToRemote`.
    pub fn responses(&self) -> Vec<serde_json::Value> {
        self.parsed
            .as_ref()
            .and_then(|v| v.get("$responses"))
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default()
    }
}

/// An onboarded identity: its stream id and the key controlling it.
#[derive(Debug, Clone)]
pub struct Identity {
    pub stream_id: String,
    pub public_key: String,
}

/// A connection to one Activeledger node.
#[derive(Debug, Clone)]
pub struct Client {
    base_url: String,
    core_url: Option<String>,
    http: reqwest::Client,
}

impl Client {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            core_url: None,
            http: reqwest::Client::new(),
        }
    }

    /// Adds the Activecore URL, which serves the event streams.
    ///
    /// Activecore is a SEPARATE service on its own port, not a path on the
    /// node: a node answers 403 for every event route.
    pub fn with_core(mut self, core_url: impl Into<String>) -> Self {
        self.core_url = Some(core_url.into().trim_end_matches('/').to_owned());
        self
    }

    /// Supplies a pre-configured HTTP client, for proxies, timeouts or
    /// client certificates.
    pub fn with_http(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn core_url(&self) -> Option<&str> {
        self.core_url.as_deref()
    }

    pub async fn submit(&self, transaction: &Transaction) -> Result<Response, ClientError> {
        self.submit_raw(&transaction.to_json()?).await
    }

    /// Submits a pre-built envelope.
    ///
    /// For envelopes built elsewhere, and for testing rejection paths -- a
    /// tampered body cannot be expressed through [`Client::submit`], because
    /// the builder would re-sign it into a valid transaction.
    pub async fn submit_raw(&self, body: &str) -> Result<Response, ClientError> {
        let response = self
            .http
            .post(format!("{}/", self.base_url))
            .header("Content-Type", "application/json")
            .body(body.to_owned())
            .send()
            .await?;
        Ok(Response::new(response.text().await?))
    }

    /// Onboards a new identity.
    ///
    /// Errors if the ledger rejected it, rather than returning an Identity
    /// with an empty stream id -- an onboarding that silently produced no
    /// identity is a failure that surfaces three calls later.
    pub async fn onboard(&self, signer: &dyn Signer) -> Result<Identity, ClientError> {
        let transaction = Transaction::onboard(signer, "identity")?;
        let response = self.submit(&transaction).await?;
        match response.new_streams().into_iter().next() {
            Some(stream_id) => Ok(Identity {
                stream_id,
                public_key: signer.public_key(),
            }),
            None => Err(ClientError::OnboardFailed(response.raw)),
        }
    }

    /// Subscribes to activity: every stream change on the ledger, or the
    /// changes to one stream.
    ///
    /// This is the feed that fires for ordinary transactions. Contract
    /// events are a different feed carrying only what a contract explicitly
    /// emitted, so a subscriber watching there sees nothing for a
    /// transaction that emitted no event -- which looks exactly like a
    /// broken subscription.
    pub async fn subscribe_to_activity(
        &self,
        stream_id: Option<&str>,
    ) -> Result<impl Stream<Item = Result<Event, ClientError>>, ClientError> {
        let core = self.core_url.as_deref().ok_or(ClientError::NoCoreUrl)?;
        let path = match stream_id {
            Some(id) => format!("/api/activity/subscribe/{}", urlencode(id)),
            None => "/api/activity/subscribe".to_owned(),
        };
        self.subscribe(&format!("{core}{path}")).await
    }

    /// Subscribes to events emitted by contracts: all of them, those from
    /// one contract, or one named event from one contract.
    pub async fn subscribe_to_contract_events(
        &self,
        contract: Option<&str>,
        event_name: Option<&str>,
    ) -> Result<impl Stream<Item = Result<Event, ClientError>>, ClientError> {
        let core = self.core_url.as_deref().ok_or(ClientError::NoCoreUrl)?;
        if contract.is_none() && event_name.is_some() {
            return Err(ClientError::EventWithoutContract);
        }

        let mut path = "/api/events".to_owned();
        if let Some(contract) = contract {
            path.push('/');
            path.push_str(&urlencode(contract));
        }
        if let Some(event_name) = event_name {
            path.push('/');
            path.push_str(&urlencode(event_name));
        }
        self.subscribe(&format!("{core}{path}")).await
    }

    /// Subscribes to an arbitrary path or absolute URL.
    ///
    /// Dropping the returned stream closes the connection.
    pub async fn subscribe(
        &self,
        path_or_url: &str,
    ) -> Result<impl Stream<Item = Result<Event, ClientError>>, ClientError> {
        let target = if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
            path_or_url.to_owned()
        } else {
            format!("{}{}", self.base_url, path_or_url)
        };

        let response = self
            .http
            .get(target)
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .send()
            .await?;

        // Without this a rejected subscription becomes an empty event
        // stream: the caller waits forever for events that were never
        // coming, and nothing anywhere reports a problem.
        let response = response.error_for_status()?;

        let mut parser = EventParser::new();
        let mut bytes = response.bytes_stream();

        Ok(async_stream::stream! {
            let mut pending: std::collections::VecDeque<Event> = Default::default();
            loop {
                if let Some(event) = pending.pop_front() {
                    yield Ok(event);
                    continue;
                }

                match bytes.next().await {
                    Some(Ok(chunk)) => {
                        // Lossy rather than strict: a multi-byte character
                        // split across two chunks must not kill the stream.
                        let text = String::from_utf8_lossy(&chunk);
                        pending.extend(parser.push(&text));
                    }
                    Some(Err(error)) => {
                        yield Err(ClientError::Http(error));
                        return;
                    }
                    None => {
                        if let Some(event) = parser.finish() {
                            yield Ok(event);
                        }
                        return;
                    }
                }
            }
        })
    }
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
