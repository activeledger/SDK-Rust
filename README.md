<a href="https://activeledger.io/">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/activeledger/activeledger/master/docs/assets/Asset-23-dark.png">
    <img src="https://raw.githubusercontent.com/activeledger/activeledger/master/docs/assets/Asset-23.png" alt="Activeledger" width="300"/>
  </picture>
</a>

[![crates.io](https://img.shields.io/crates/v/activeledger)](https://crates.io/crates/activeledger)
[![docs.rs](https://img.shields.io/docsrs/activeledger)](https://docs.rs/activeledger)
[![licence](https://img.shields.io/badge/licence-MIT-blue)](https://github.com/activeledger/SDK-Rust/blob/master/LICENSE)

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
```

`2.x` is a ground-up rewrite. The `0.1.x` releases on crates.io predate it and
share nothing with it but the name.

Verified: builds and derives keys from a clean project on stable.


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

## Seeds and recovery phrases

```rust
use activeledger::{KeyPair, secp256k1::Secp256k1KeyPair};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let seed = [0x11u8; 32];
let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow";

let pq = KeyPair::from_seed(&seed)?;                       // 32 bytes
let pq_recovered = KeyPair::from_phrase(phrase, "")?;      // BIP-39

let ec = Secp256k1KeyPair::from_seed(&seed, true)?;
let ec_recovered = Secp256k1KeyPair::from_phrase(phrase, "", true)?;
# let _ = (pq, pq_recovered, ec, ec_recovered);
# Ok(())
# }
```

The same seed gives the same identity in every Activeledger SDK, which is what
makes a seed the portable private-key format — it is how a private key moves
between languages. It matters most for PHP, whose ML-DSA-65 private key **is**
a 32-byte seed and which has no 4032-byte form at all.

A seed of the wrong length is **refused, not padded**: a padded seed is a
different identity, not a malformed one.

For `secp256k1` the seed **is** the private scalar, so it has to be a valid
one. A seed of zero, or one at or above the curve order, is refused rather
than reduced mod *n* — reducing produces a perfectly functional key belonging
to a different identity, and nothing downstream ever reports a problem.

The phrase is validated, wordlist **and** checksum. A mistyped phrase that is
not checked does not fail; it derives a valid key for an identity nobody owns,
and the only symptom is the ledger not recognising it.

`Secp256k1KeyPair::from_legacy_phrase` recovers a phrase made by the older
`@activeledger/sdk-bip39` package — recovery only, never for new keys.

### The derivation

| Type | Seed from the BIP-39 seed `S` |
| --- | --- |
| `secp256k1` | `HMAC-SHA512("Bitcoin seed", S)[0..32]` |
| `ml-dsa-65` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)` |
| `falcon-512` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)` |

`secp256k1` deliberately does not use HKDF: the JavaScript SDK shipped that
derivation before the post-quantum types existed, so phrases are already in
use, and changing it would hand those users a different key for a phrase that
used to work.

`recovery::derive_seed` implements all three — including `falcon-512`, which
this SDK cannot otherwise use, so a phrase here can still produce the seed for
a Falcon identity created elsewhere.

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

## Events (SSE) - deprecated

`Client::subscribe_to_activity`, `subscribe_to_contract_events`, `subscribe` and `with_core` are **deprecated** and will be removed in the next major version.

Events are no longer served by ActiveCore, which is itself deprecated and
should not be used. A node serves contract events from its own storage
service at `http://localhost:<storage port>/activeledgerevents/events`, and
that service must never be reachable beyond the node's host - so a client
SDK has nothing it should connect to.

To react to events, run your own server-sent events listener on the node's
host and relay what your application needs through your own backend. Each
event is an SSE frame whose `id` is `<milliseconds>-<counter>,<umid>` and
whose `data` is `{"name", "data", "phase", "contract"}`.
