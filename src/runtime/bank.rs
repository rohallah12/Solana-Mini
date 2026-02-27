// ---------------------------------------------------------------------------
// Bank — pre-execution transaction validation.
//
// The Bank sits between the RPC and the SVM. It is the security layer that
// rejects invalid transactions BEFORE any execution begins.
//
// Responsibilities (subset implemented here):
//   1. Serialize the message into canonical bytes
//   2. Verify every required Ed25519 signature against those bytes
//
// Not yet implemented (future sessions):
//   - recent_blockhash validity (must appear in last ~150 slots)
//   - fee payer balance check  (must cover base fee before execution)
//   - account deduplication    (no duplicate keys in account_keys)
//
// Reference: https://github.com/anza-xyz/agave/blob/master/runtime/src/bank.rs
// ---------------------------------------------------------------------------

use ed25519_dalek::{Verifier, VerifyingKey};
use crate::types::transaction::{Message, Transaction};

// ---------------------------------------------------------------------------
// BankError
// ---------------------------------------------------------------------------
#[derive(Debug)]
pub enum BankError {
    /// The transaction declares N required signatures but fewer were provided.
    NotEnoughSignatures { expected: usize, got: usize },

    /// The public key at `index` is not a valid Ed25519 verifying key.
    InvalidPublicKey { index: usize },

    /// The signature at `index` did not verify against the message bytes.
    SignatureVerificationFailed { index: usize },
}

// ---------------------------------------------------------------------------
// verify_signatures — the main entry point called by the RPC before SVM.
//
// For each signer i in 0..num_required_signatures:
//   - pubkey    = message.account_keys[i]
//   - signature = transaction.signatures[i]
//   - verify that signature is a valid Ed25519 signature of
//     serialize_message(&transaction.message) under pubkey
// ---------------------------------------------------------------------------
pub fn verify_signatures(tx: &Transaction) -> Result<(), BankError> {
    let num_required = tx.message.header.num_required_signatures as usize;

    if tx.signatures.len() < num_required {
        return Err(BankError::NotEnoughSignatures {
            expected: num_required,
            got:      tx.signatures.len(),
        });
    }

    let message_bytes = serialize_message(&tx.message);

    for i in 0..num_required {
        let pubkey_bytes = &tx.message.account_keys[i].0;
        let sig_bytes    = &tx.signatures[i].0;

        let verifying_key = VerifyingKey::from_bytes(pubkey_bytes)
            .map_err(|_| BankError::InvalidPublicKey { index: i })?;

        let signature = ed25519_dalek::Signature::from_bytes(sig_bytes);

        verifying_key
            .verify(&message_bytes, &signature)
            .map_err(|_| BankError::SignatureVerificationFailed { index: i })?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// serialize_message — canonical byte encoding of a Message.
//
// This is what gets signed by the sender and verified by the Bank.
// Real Solana uses a compact binary encoding; we use a simple but
// deterministic layout:
//
//   [num_required_signatures:        u8]
//   [num_readonly_signed_accounts:   u8]
//   [num_readonly_unsigned_accounts: u8]
//   [num_account_keys:               u8]
//   [account_key_0:                  32 bytes]
//   ...
//   [recent_blockhash:               32 bytes]
//   [num_instructions:               u8]
//   for each instruction:
//     [program_id_index:   u8]
//     [num_accounts:       u8]
//     [accounts:           num_accounts bytes]
//     [data_len:           u16 LE]
//     [data:               data_len bytes]
// ---------------------------------------------------------------------------
pub fn serialize_message(msg: &Message) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header
    buf.push(msg.header.num_required_signatures);
    buf.push(msg.header.num_readonly_signed_accounts);
    buf.push(msg.header.num_readonly_unsigned_accounts);

    // Account keys
    buf.push(msg.account_keys.len() as u8);
    for key in &msg.account_keys {
        buf.extend_from_slice(&key.0);
    }

    // Recent blockhash
    buf.extend_from_slice(&msg.recent_blockhash.0);

    // Instructions
    buf.push(msg.instructions.len() as u8);
    for ix in &msg.instructions {
        buf.push(ix.program_id_index);
        buf.push(ix.accounts.len() as u8);
        buf.extend_from_slice(&ix.accounts);
        let data_len = ix.data.len() as u16;
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&ix.data);
    }

    buf
}
