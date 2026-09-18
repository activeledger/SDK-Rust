[![Activeledger](https://www.activeledger.io/wp-content/uploads/2018/09/Asset-1.png)](https://activeledger.io/)

# Activeledger SDK for Rust

Build, sign and submit Activeledger transactions from Rust, with post-quantum
identities.

- **ML-DSA-65** post-quantum identities, verified against the ledger's
  published cross-language vectors
- Canonical JSON that reproduces the exact bytes the ledger signs
- Transaction builder, async client and server-sent event subscriptions
- Pure Rust: no OpenSSL, no C toolchain, no `unsafe`

This crate replaces three: `SDK-Rust`, `SDK-Rust-Events` and
`SDK-Rust-TxBuilder` are now one library.

## Install

```toml
[dependencies]
activeledger = "2"
tokio = { version = "1", features = ["full"] }
```

## Quick start

```rust,no_run
use activeledger::{Client, KeyPair, Object, Transaction};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new("http://localhost:5260");

    // A post-quantum identity
    let key = KeyPair::generate()?;
    let identity = client.onboard(&key).await?;
    println!("{}", identity.stream_id);

    // A transaction signed by it
    let tx = Transaction::builder()
        .namespace("default")
        .contract("mycontract")
        .input_with(&identity.stream_id, &key, Object::new().set("amount", 100))
        .output("someotherstream")
        .build()?;

    let response = client.submit(&tx).await?;

    if !response.committed() {
        // NOT the HTTP status. See "A rejected transaction is an HTTP 200".
        eprintln!("{:?}", response.errors());
    }
    Ok(())
}
```

## Key types

| Key type | Wire string | Public | Private | Signature | Encoding |
|---|---|---|---|---|---|
| ML-DSA-65 | `ml-dsa-65` | 1952 | 4032 | 3309 | base64 |
| secp256k1 | `secp256k1` | 33 or 65 | 32 | ~70-72, variable | `0x` hex |
| Falcon-512 | `falcon-512` | — | — | not supported here | — |

Use **secp256k1** unless the identity must outlive a cryptographically
relevant quantum computer: it is roughly **22x smaller** per transaction, and
every byte is stored on the ledger permanently and replicated to every node.
It also works with hardware wallets and HSMs, and it is the only way to sign
for an identity created before post-quantum support.

```rust
use activeledger::Secp256k1KeyPair;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let key = Secp256k1KeyPair::generate();                  // compressed
let full = Secp256k1KeyPair::generate_with(false);       // uncompressed

let public = key.public_key();                           // "0x02a1b2..."
let private = key.private_key().expect("this pair can sign");

let restored = Secp256k1KeyPair::from_keys(&public, &private)?;
let verifier = Secp256k1KeyPair::from_public(&public)?;
# let _ = (full, restored, verifier);
# Ok(())
# }
```

### secp256k1 is encoded nothing like the post-quantum keys

- **Keys are `0x`-prefixed hex, not base64.** The prefix is required rather
  than tolerated, because hex without it can decode as base64 into
  plausible-looking bytes of the wrong length.
- **Public keys have two valid lengths**, 33 compressed and 65 uncompressed,
  and the ledger accepts both. A length and a SEC1 point prefix that disagree
  are rejected by name.
- **Private scalars are always 32 bytes.** A leading zero byte occurs about
  once in 400 keys, and a value that dropped it is a different scalar.
- **Signatures are SHA-256 → ECDSA → DER**, and DER length varies.

### low-S, in both directions

**Signing** is RFC 6979 deterministic and low-S. That is not for the ledger,
which accepts either, but for `@noble/curves` — the reference for the
JavaScript side — and libsecp256k1, both of which reject high-S by default.

**Verification deliberately accepts high-S.** This is the one that bites in
Rust: `k256` rejects high-S outright, and measured against the published
vectors its unmodified path rejects **7 of 12 valid signatures**. The ledger
verifies through OpenSSL and produces high-S freely, so this SDK normalises
before verifying — `(r, s)` and `(r, n - s)` are the same signature, so
nothing is weakened.

Because signing is deterministic, this SDK's signatures are byte-identical to
`@noble/curves` for the same key and message, and the test suite asserts
exactly that against published reference bytes.

## Post-quantum support

**ML-DSA-65 is supported. Falcon-512 is not.**

Falcon identities work on the ledger and are supported by the JS, JVM and C#
SDKs. They are not supported in Rust because no pure-Rust implementation reads
the key encoding the ledger stores — `fn-dsa` cannot decode the ledger's Falcon
keys at all, which was established by trying it rather than by reading about
it. [`KeyError::FalconUnsupported`] is returned instead of a key the ledger
would silently reject as a bad signature.

```rust
use activeledger::KeyPair;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let key = KeyPair::generate()?;

// Base64, in exactly the encoding the ledger stores
let public = key.public_key();
let private = key.private_key().expect("this pair can sign");

// Round-trip a stored key
let restored = KeyPair::from_keys(&public, &private)?;

// Verification only - no private key, and sign() returns an error
let verifier = KeyPair::from_public(&public)?;
assert!(!verifier.can_sign());
# Ok(())
# }
```

Two things about these keys are worth knowing.

**Signing is hedged**, not deterministic: fresh entropy goes into every
signature, so signing the same message twice produces different bytes. This
matches the reference implementation. Never compare signatures for equality —
verify them.

**A key of the right length is always accepted.** An ML-DSA public key is a
seed plus packed 10-bit coefficients with no checksum, so nearly any 1952 bytes
decode to *some* key. There is nothing to validate against, and the failure
surfaces at verification rather than at construction.

## Transactions

```rust,no_run
# use activeledger::{KeyPair, Object, Transaction};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key = KeyPair::generate()?;
# let (stream_id, other_stream, some_stream) = ("a", "b", "c");
let tx = Transaction::builder()
    .namespace("default")
    .contract("mycontract")
    .entry("transfer")                                   // optional
    .input_with(stream_id, &key, Object::new().set("amount", 100))
    .output(other_stream)                                // optional
    .readonly("label", some_stream)                      // optional
    .build()?;
# Ok(())
# }
```

Every signer signs the *same* bytes: the canonical form of `$tx`. `$sigs` is
keyed by input stream id.

Onboarding differs in two ways that catch every port, so it has its own
constructor — `$selfsign` is true, and `$sigs` is keyed by the `$i` label
because no stream exists yet:

```rust,no_run
# use activeledger::{KeyPair, Transaction};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key = KeyPair::generate()?;
let tx = Transaction::onboard(&key, "identity")?;
# Ok(())
# }
```

To inspect exactly what was signed — the fastest way to diagnose a rejected
signature:

```rust,no_run
# use activeledger::{KeyPair, Transaction};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key = KeyPair::generate()?;
# let tx = Transaction::onboard(&key, "identity")?;
let signed: Vec<u8> = tx.signed_bytes()?;   // the $tx object alone
let envelope: String = tx.to_json()?;       // what gets submitted
# Ok(())
# }
```

## Reading state

There is no read API. A node's storage service listens only on that node's own
host, so reading state is a transaction like any other: name the streams in
`$r`, and the contract hands values back with `returnToRemote`.

```rust,no_run
# use activeledger::{Client, KeyPair, Transaction};
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
# let client = Client::new("http://localhost:5260");
# let key = KeyPair::generate()?;
# let (stream_id, stream_to_read) = ("a", "b");
let tx = Transaction::builder()
    .namespace("default")
    .contract("mycontract")
    .entry("read")
    .input(stream_id, &key)
    .readonly("target", stream_to_read)
    .build()?;

let response = client.submit(&tx).await?;

for value in response.responses() {
    println!("{}", value["balance"]);
}
# Ok(())
# }
```

`response.new_streams()` gives the ids of any streams the transaction created.

## Events (SSE)

Event streams are served by **Activecore**, which is a separate service on its
own port — not a path on the node. Pointing a subscription at a node returns
403, so the URL is supplied separately and subscribing without it returns an
error naming the missing URL rather than quietly producing an empty stream.

```rust,no_run
use activeledger::Client;
use futures_util::StreamExt;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::new("http://localhost:5260")
    .with_core("http://localhost:5261");

// Every stream change on the ledger
let mut stream = Box::pin(client.subscribe_to_activity(None).await?);
while let Some(event) = stream.next().await {
    println!("{}", event?.data);
}

// Changes to one stream
let mut stream = Box::pin(client.subscribe_to_activity(Some("streamid")).await?);

// Events a contract emitted: all, by contract, or one named event
let mut stream = Box::pin(client.subscribe_to_contract_events(None, None).await?);
let mut stream = Box::pin(client.subscribe_to_contract_events(Some("mycontract"), None).await?);
let mut stream = Box::pin(
    client.subscribe_to_contract_events(Some("mycontract"), Some("transfer")).await?,
);
# Ok(())
# }
```

**Activity and contract events are different feeds.** Activity fires for stream
changes, so it is what an ordinary transaction produces. Contract events carry
only what a contract explicitly emitted — subscribe there for a transaction
that emits nothing and you will correctly receive nothing, which looks exactly
like a broken subscription.

Each `Event` has `data`, plus `name` and `id` when the server sent them.
Multiple `data:` lines join with newlines, and `:` heartbeat comments are
ignored rather than delivered as empty events. Dropping the stream closes the
connection.

`Client::subscribe` takes a raw path or an absolute URL for anything not
covered above.

## Signing elsewhere

`Signer` is all the SDK needs, so keys can live in an HSM, a remote signing
service or a user's wallet:

```rust
use activeledger::{KeyError, KeyType, Signer};

struct HsmSigner;

impl Signer for HsmSigner {
    fn key_type(&self) -> KeyType {
        KeyType::MlDsa65
    }
    fn public_key(&self) -> String {
        // ...
        # String::new()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        // ...
        # let _ = message;
        # Ok(Vec::new())
    }
}
```

`sign` receives the canonical bytes of `$tx` and returns a raw signature; the
SDK base64-encodes it.

## Things that will bite you

**A rejected transaction is an HTTP 200.** The ledger answers 200 and reports
the problem in the body. Check `response.committed()` — code that treats the
HTTP status as success will report commits that never happened, and will keep
doing so until something downstream notices the data is missing.

**Every signature problem is reported as 1220 "Signature Incorrect".** A wrong
key type, a missing `type`, wrong-length key material and genuinely bad bytes
all produce that one message. `tx.signed_bytes()` is usually the quickest way
in.

**A missing `type` defaults to `rsa`.** The ledger then tries RSA verification
against whatever it was given. This SDK always sends the type explicitly.

**Namespaces are claimed permanently.** A test that registers a fixed namespace
passes once and fails every re-run against the same network, which reads like a
regression and is not one.

**Consensus is a majority.** When a submission returns, most nodes have
committed and the rest may still be writing. Reading immediately from a
specific node is a race.

## Canonical JSON

Signatures cover the exact bytes of `JSON.stringify($tx)` encoded as UTF-8 — no
hash prefix, no length prefix, no domain separator and **no key sorting**. A
signature over bytes that differ by a single escape is invalid.

`serde_json` cannot produce these bytes. Its map sorts keys unless the
crate-wide `preserve_order` feature is enabled — and enabling that from a
library would silently change `serde_json`'s behaviour throughout the
consumer's binary. It also writes `1.0` where JavaScript writes `1`. So this
crate owns the format, with its own insertion-ordered object:

```rust
use activeledger::{canonical, Object, Value};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let payload = Object::new()
    .set("zebra", 1)              // stays first - not sorted
    .set("alpha", "text")
    .set("nested", Object::new().set("flag", true));

let json = canonical::to_string(&Value::Object(payload.clone()))?;
let bytes = canonical::to_bytes(&Value::Object(payload))?;
assert!(json.starts_with(r#"{"zebra":1,"alpha":"text""#));
# Ok(())
# }
```

Numbers follow JavaScript: whole values print without a fractional part, so
`1.0` serialises as `1`. `NaN` and infinity are refused rather than silently
written as `null`. `Value::Integer` keeps 64-bit integers exact, which an
f64-only number type would not.

## Testing

```bash
cargo test
```

The live-network tests skip unless a ledger is configured. To run them, start a
network from an `activeledger` checkout:

```bash
npm run test:network:serve
```

then run with the URLs it prints:

```bash
AL_NODES=http://127.0.0.1:5510,http://127.0.0.1:5520 \
AL_STORAGE=http://127.0.0.1:5509,http://127.0.0.1:5519 \
cargo test
```

They onboard real post-quantum identities, verify what the ledger actually
recorded on every node, check that a tampered payload is rejected, and open a
real event stream.

## Migrating from 0.1

Version 2 is a rewrite, and it absorbs `SDK-Rust-Events` and
`SDK-Rust-TxBuilder` — both of those crates are no longer needed.

| 0.1 | 2.x |
|---|---|
| `activeledger::key::rsa` / `::ec` | `KeyPair` (ML-DSA-65) |
| `activeledger::connection::Connection` | `Client` |
| `activeledger-tx-builder` | `Transaction::builder()` |
| `activeledger-events` | `Client::subscribe_to_activity` / `subscribe_to_contract_events` |

The API is now async, and `openssl` is gone: the previous release vendored and
compiled OpenSSL, which made the crate need a C toolchain to build at all.

## Licence

MIT
