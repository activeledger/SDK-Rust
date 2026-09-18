//! # Activeledger SDK for Rust
//!
//! Build, sign and submit Activeledger transactions, with post-quantum
//! identities.
//!
//! ```no_run
//! use activeledger::{Client, KeyPair, Transaction, Object};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = Client::new("http://localhost:5260");
//!
//! let key = KeyPair::generate()?;
//! let identity = client.onboard(&key).await?;
//!
//! let tx = Transaction::builder()
//!     .namespace("default")
//!     .contract("mycontract")
//!     .input_with(&identity.stream_id, &key, Object::new().set("amount", 100))
//!     .build()?;
//!
//! let response = client.submit(&tx).await?;
//! if !response.committed() {
//!     // NOT the HTTP status: the ledger answers 200 for a rejection.
//!     eprintln!("{:?}", response.errors());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Post-quantum support
//!
//! ML-DSA-65 is supported and verified against the ledger's published
//! cross-language vectors. **Falcon-512 is not**: no pure-Rust
//! implementation reads the key encoding the ledger stores, so
//! [`KeyError::FalconUnsupported`] is returned rather than a key the ledger
//! would silently reject. The JS, JVM and C# SDKs support both.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

/// The README's examples, compiled as doctests.
///
/// Documentation that does not compile is worse than none: it is confidently
/// wrong. Including it here means `cargo test` fails the moment an example
/// drifts from the API.
#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

pub mod canonical;
pub mod connection;
pub mod events;
pub mod keys;
pub mod transaction;

pub use canonical::{CanonicalError, Object, Value};
pub use connection::{Client, ClientError, Identity, Response};
pub use events::{Event, EventParser};
pub use keys::{KeyError, KeyPair, KeyType, Signer};
pub use transaction::{Transaction, TransactionBuilder, TransactionError};
