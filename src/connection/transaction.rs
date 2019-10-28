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

/// Transaction struct
pub struct Transaction {
    data: String,
}

impl Transaction {
    /// Create a new transaction object
    ///
    /// Takes a JSON string
    ///
    /// The active_txbuilder crate can be used to generate the
    /// transaction data
    ///
    /// # Example
    /// ```
    /// # use activeledger::Transaction;
    /// let tx = Transaction::new("{TX DATA HERE}");
    /// ```
    /// ## Expected JSON structure
    /// ```JSON
    /// {
    ///     "$territoriality" : "" // Optional
    ///     "$tx" : {
    ///         "$namespace":"",
    ///         "$contract":"",
    ///         "$entry":"",
    ///         "$i":"",
    ///         "$o":"" // Optional
    ///         "$r":"" // Optional
    ///     },
    ///     "$selfsign" : true, // Optional
    ///     "$sigs" : {
    ///         "<identity>" : "<signature>"
    ///     }
    /// }
    /// ```
    /// More information about transaction data can be found in the Activeledger documentation [here.](https://github.com/activeledger/activeledger/blob/master/docs/en-gb/contracts/deployment/run.md)
    ///
    pub fn new(tx_data: &str) -> Transaction {
        Transaction {
            data: tx_data.to_string(),
        }
    }

    /// Get the transaction data
    ///
    /// Returns a string reference
    pub fn get_data(&self) -> &str {
        &self.data
    }
}
