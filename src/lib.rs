/*
 * MIT License (MIT)
 * Copyright (c) 2019 Activeledger
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

//! # Activeledger Rust SDK
//!
//! <img src="https://www.activeledger.io/wp-content/uploads/2018/09/Asset-23.png" alt="Activeledger" width="300"/>
//!
//! Activeledger is a powerful distributed ledger technology.
//! Think about it as a single ledger, which is updated simultaneously in multiple locations.
//! As the data is written to a ledger, it is approved and confirmed by all other locations.
//!
//! ## This Crate
//!
//! This crate provides Rust developers the ability to easily integrate their applications
//! with Activeledger.
//!
//! This crate gives you access to the core essentials needed to get started.
//! * Connection - Connect to an Activeledger node in a network.
//! * Keys - RSA and EC key generation with data signing abilities.
//!
//! Integrating these into this crate makes it much quicker to bootstrap your DLT software.
//!
//! ## Additional Activeledger crates
//! Adhearing to the Rust mentality of keeping things small we have created other crates that can be used in conjunction
//! with this one to add additional functionality.
//!
//! These crates are:
//! * [active_events](https://github.com/activeledger/SDK-Rust-Events) - For working with server sent events.
//! * [active_tx](https://github.com/activeledger/SDK-Rust-TxBuilder) - To build transactions without worrying about the JSON.
//!
//! ## Links
//!
//! [Activeledger](https://activeledger.io)
//!
//! [Activeledger Developers portal](https://developers.activeledger.io)
//!
//! [Activeledger on GitHub](https://github.com/activeledger/activeledger)
//!
//! [Activeledger on NPM](https://www.npmjs.com/package/@activeledger/activeledger)
//!
//! [This SDK on GitHub](https://github.com/activeledger/SDK-Rust)
//!
//! [Report Issues](https://github.com/activeledger/SDK-Rust/issues)

mod connection;
pub mod key;

pub use connection::{error, transaction::Transaction, Connection};
