# Activeledger - Rust SDK

<img src="https://www.activeledger.io/wp-content/uploads/2018/09/Asset-23.png" alt="Activeledger" width="300"/>

Activeledger is a powerful distributed ledger technology.
Think about it as a single ledger updated simultaneously in multiple locations.
As the data is written to a ledger, it is approved and confirmed by all other locations.

[GitHub](https://github.com/activeledger/activeledger)

[NPM](https://www.npmjs.com/package/@activeledger/activeledger)

---

This crate provides Rust developers the ability to easily integrate their applications
with Activeledger.

This crate gives you access to the core essentials needed to get started.
* Connection - To create a connection with an Activeledger node in a network.
* Keys - RSA and EC key generation with data signing abilities.

Integrating these into this crate makes it much quicker to bootstrap your DLT software, instead of
creating these functions yourself.

See the [Rust docs]() for more.

## Additional Activeledger crates
Adhearing to the Rust mentality of keeping things small we have created other crates that can be used in conjunction
with this one to add additional functionality.

These crates are:
* [active_events](https://github.com/activeledger/SDK-Rust-Events) - For working with server sent events. ([Crate](https://crates.io/crates/active_sse))
* [active_txbuilder](https://github.com/activeledger/SDK-Rust-TxBuilder) - To build transactions without worrying about the JSON. ([Crate](https://crates.io/crates/active_tx))

## Links
[Visit Activeledger.io](https://activeledger.io/)

[Read Activeledgers documentation](https://github.com/activeledger/activeledger/blob/master/docs/en-gb/README.md)

[Activeledger Developers portal](https://developers.activeledger.io)

[Activeledger on GitHub](https://github.com/activeledger/activeledger)

[Activeledger on NPM](https://www.npmjs.com/package/@activeledger/activeledger)

[This SDK on GitHub](https://github.com/activeledger/SDK-Rust)

[Report Issues](https://github.com/activeledger/SDK-Rust/issues)

## License

---

This project is licensed under the [MIT](https://github.com/activeledger/activeledger/blob/master/LICENSE) License
