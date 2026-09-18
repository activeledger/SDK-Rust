//! Building and signing transactions.

use base64::{engine::general_purpose::STANDARD, Engine};

use crate::canonical::{self, CanonicalError, Object, Value};
use crate::keys::{KeyError, Signer};

#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("namespace is required")]
    MissingNamespace,
    #[error("contract is required")]
    MissingContract,
    #[error("at least one input with a signing key is required")]
    MissingInput,
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    #[error(transparent)]
    Key(#[from] KeyError),
}

/// A signed transaction, ready to submit.
///
/// `body` is the `$tx` object. `sigs` maps a signer label to a base64
/// signature over the canonical bytes of `body` and NOTHING ELSE -- not the
/// envelope, not a hash of it, not a length-prefixed form.
#[derive(Debug, Clone)]
pub struct Transaction {
    body: Object,
    sigs: Vec<(String, String)>,
    self_sign: bool,
}

impl Transaction {
    /// The `$tx` object. These are the bytes that get signed.
    pub fn body(&self) -> &Object {
        &self.body
    }

    /// Base64 signatures, in the order their inputs were added.
    pub fn sigs(&self) -> &[(String, String)] {
        &self.sigs
    }

    pub fn is_self_signed(&self) -> bool {
        self.self_sign
    }

    /// The full envelope, as submitted.
    pub fn envelope(&self) -> Object {
        let mut envelope = Object::new().set("$tx", self.body.clone());
        if self.self_sign {
            envelope = envelope.set("$selfsign", true);
        }
        let mut sigs = Object::new();
        for (label, signature) in &self.sigs {
            sigs.insert(label.clone(), signature.clone());
        }
        envelope.set("$sigs", sigs)
    }

    /// The envelope serialised for submission.
    pub fn to_json(&self) -> Result<String, CanonicalError> {
        canonical::to_string(&Value::Object(self.envelope()))
    }

    /// The exact bytes that were signed. The fastest way to diagnose a 1220.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical::to_bytes(&Value::Object(self.body.clone()))
    }

    /// Builds the onboarding transaction for a new identity.
    ///
    /// Two things here are the most common first failure in any port, so
    /// they happen in one place rather than being left to a caller:
    /// `$selfsign` is true and `$sigs` is keyed by the `$i` LABEL rather
    /// than a stream id (there is no stream yet); and `type` is always
    /// present, because the ledger defaults a missing one to `rsa` and then
    /// attempts RSA verification against a base64 post-quantum blob.
    pub fn onboard(signer: &dyn Signer, label: &str) -> Result<Self, TransactionError> {
        let body = Object::new()
            .set("$namespace", "default")
            .set("$contract", "onboard")
            .set(
                "$i",
                Object::new().set(
                    label,
                    Object::new()
                        .set("type", signer.key_type().as_wire())
                        .set("publicKey", signer.public_key_base64()),
                ),
            )
            .set("$o", Object::new());

        let message = canonical::to_bytes(&Value::Object(body.clone()))?;
        let signature = STANDARD.encode(signer.sign(&message)?);

        Ok(Self {
            body,
            sigs: vec![(label.to_owned(), signature)],
            self_sign: true,
        })
    }

    pub fn builder() -> TransactionBuilder<'static> {
        TransactionBuilder::default()
    }
}

/// Builds an ordinary transaction.
///
/// Insertion order is preserved throughout, because the ledger does not
/// canonicalise key order and the signature covers the order actually
/// written.
#[derive(Default)]
pub struct TransactionBuilder<'a> {
    namespace: Option<String>,
    contract: Option<String>,
    entry: Option<String>,
    inputs: Object,
    outputs: Object,
    readonly: Object,
    signers: Vec<(String, &'a dyn Signer)>,
}

impl std::fmt::Debug for TransactionBuilder<'_> {
    /// Manual, because a `&dyn Signer` cannot be `Debug` without forcing
    /// every custom signer to implement it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionBuilder")
            .field("namespace", &self.namespace)
            .field("contract", &self.contract)
            .field("entry", &self.entry)
            .field("inputs", &self.inputs.keys())
            .field("outputs", &self.outputs.keys())
            .field("readonly", &self.readonly.keys())
            .finish()
    }
}

impl<'a> TransactionBuilder<'a> {
    pub fn namespace(mut self, value: impl Into<String>) -> Self {
        self.namespace = Some(value.into());
        self
    }

    pub fn contract(mut self, value: impl Into<String>) -> Self {
        self.contract = Some(value.into());
        self
    }

    /// Sets `$entry`, the contract entry point. Omitted when not set.
    pub fn entry(mut self, value: impl Into<String>) -> Self {
        self.entry = Some(value.into());
        self
    }

    /// Adds an input stream, its signing key and any payload fields.
    pub fn input(self, stream_id: impl Into<String>, signer: &'a dyn Signer) -> Self {
        self.input_with(stream_id, signer, Object::new())
    }

    /// Adds an input stream with payload fields.
    pub fn input_with(
        mut self,
        stream_id: impl Into<String>,
        signer: &'a dyn Signer,
        payload: Object,
    ) -> Self {
        let stream_id = stream_id.into();
        self.inputs.insert(stream_id.clone(), payload);
        match self.signers.iter_mut().find(|(id, _)| *id == stream_id) {
            Some(existing) => existing.1 = signer,
            None => self.signers.push((stream_id, signer)),
        }
        self
    }

    pub fn output(mut self, stream_id: impl Into<String>) -> Self {
        self.outputs.insert(stream_id.into(), Object::new());
        self
    }

    pub fn output_with(mut self, stream_id: impl Into<String>, payload: Object) -> Self {
        self.outputs.insert(stream_id.into(), payload);
        self
    }

    /// Adds a stream to `$r`, the read-only set.
    ///
    /// This is how state is read from Activeledger. There is no separate
    /// read API: a node's storage service listens only on its own host, so
    /// reading is a transaction like anything else. The contract receives
    /// the named streams and hands values back with `returnToRemote`.
    pub fn readonly(mut self, label: impl Into<String>, stream_id: impl Into<String>) -> Self {
        self.readonly.insert(label.into(), stream_id.into());
        self
    }

    /// Signs and returns the transaction.
    pub fn build(self) -> Result<Transaction, TransactionError> {
        let namespace = self.namespace.ok_or(TransactionError::MissingNamespace)?;
        let contract = self.contract.ok_or(TransactionError::MissingContract)?;
        if self.signers.is_empty() {
            return Err(TransactionError::MissingInput);
        }

        let mut body = Object::new();
        if let Some(entry) = self.entry {
            body.insert("$entry", entry);
        }
        body.insert("$namespace", namespace);
        body.insert("$contract", contract);
        body.insert("$i", self.inputs);
        if !self.outputs.is_empty() {
            body.insert("$o", self.outputs);
        }
        if !self.readonly.is_empty() {
            body.insert("$r", self.readonly);
        }

        let message = canonical::to_bytes(&Value::Object(body.clone()))?;
        let mut sigs = Vec::with_capacity(self.signers.len());
        for (label, signer) in self.signers {
            sigs.push((label, STANDARD.encode(signer.sign(&message)?)));
        }

        Ok(Transaction {
            body,
            sigs,
            self_sign: false,
        })
    }
}
