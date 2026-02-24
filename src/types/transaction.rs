// ---------------------------------------------------------------------------
// Transaction types — modeled after Solana's transaction model.
//
// A Solana transaction has two top-level parts:
//   - A Message  : the payload (accounts, instructions, blockhash)
//   - Signatures : one Ed25519 signature per required signer
//
// The runtime only executes the Message. Signatures just prove that the
// required accounts have authorized it.
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/transaction/src/lib.rs
// ---------------------------------------------------------------------------

use crate::types::account::Pubkey;
use std::fmt;

// ---------------------------------------------------------------------------
// Signature — a 64-byte Ed25519 signature.
//
// Produced by signing the serialized Message bytes with the signer's
// private key. There is one signature per required signer, stored in the
// same order as the signers appear in Message.account_keys.
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/signature/src/lib.rs
// ---------------------------------------------------------------------------
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Signature(pub [u8; 64]);

impl Default for Signature {
    fn default() -> Self {
        Signature([0u8; 64])
    }
}

impl Signature {
    pub fn new(bytes: [u8; 64]) -> Self {
        Signature(bytes)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Sig({}..)",
            self.0[..4]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    }
}

// ---------------------------------------------------------------------------
// Hash — a 32-byte value used as the recent blockhash.
//
// The blockhash is a SHA-256 hash of a recent PoH entry. It serves two
// purposes:
//   1. Replay protection — the runtime rejects transactions whose blockhash
//      is older than ~150 slots (~60-90 seconds).
//   2. Time anchoring — ties the transaction to a specific point on-chain.
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/hash/src/lib.rs
// ---------------------------------------------------------------------------
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn new(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Hash({}..)",
            self.0[..4]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    }
}

// ---------------------------------------------------------------------------
// MessageHeader — describes the layout of Message.account_keys.
//
// account_keys is a flat sorted list. The header tells the runtime where
// each group ends:
//
//   [writable signers | readonly signers | writable non-signers | readonly non-signers]
//    <--------- num_required_signatures -------->
//                      <-- num_readonly_signed -->
//                                                                <-- num_readonly_unsigned -->
//
// Example from a simple SOL transfer:
//   num_required_signatures:        1  (Alice must sign)
//   num_readonly_signed_accounts:   0  (Alice is writable)
//   num_readonly_unsigned_accounts: 1  (SystemProgram is readonly)
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/message/src/lib.rs
// ---------------------------------------------------------------------------
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub struct MessageHeader {
    /// Number of accounts that must provide a signature.
    /// These are always the first N entries in account_keys.
    pub num_required_signatures: u8,

    /// Of those signers, how many are read-only (cannot be debited or
    /// have their data modified). These are the last M of the signers.
    pub num_readonly_signed_accounts: u8,

    /// Number of non-signer accounts that are read-only.
    /// These are the last K entries in account_keys.
    pub num_readonly_unsigned_accounts: u8,
}

// ---------------------------------------------------------------------------
// CompiledInstruction — a single instruction inside a Message.
//
// Instructions do not embed Pubkeys directly. Instead they hold indexes
// into Message.account_keys, which deduplicates keys across instructions.
//
// The runtime dispatches the instruction by:
//   1. Loading account_keys[program_id_index] as the program to call.
//   2. Loading account_keys[accounts[i]] for each account the program needs.
//   3. Passing `data` as the raw argument bytes to the program.
//
// What `data` means is entirely program-defined. Typically:
//   - First 1-8 bytes: a discriminator identifying which function to call.
//   - Remaining bytes: the serialized arguments (usually Borsh-encoded).
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/instruction/src/lib.rs
// ---------------------------------------------------------------------------
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompiledInstruction {
    /// Index into Message.account_keys identifying the program to invoke.
    pub program_id_index: u8,

    /// Ordered list of indexes into Message.account_keys.
    /// These are the accounts passed to the program, in the order the
    /// program expects them.
    pub accounts: Vec<u8>,

    /// Opaque byte payload passed to the program.
    /// The program decodes this however it likes (Borsh, custom encoding, etc).
    pub data: Vec<u8>,
}

impl CompiledInstruction {
    pub fn new(program_id_index: u8, accounts: Vec<u8>, data: Vec<u8>) -> Self {
        CompiledInstruction {
            program_id_index,
            accounts,
            data,
        }
    }
}

// ---------------------------------------------------------------------------
// Message — the payload that signers authorize.
//
// This is what gets serialized and signed. The signatures in Transaction
// cover these bytes. Nothing outside the Message is signed.
//
// Fields match what the Solana RPC returns under transaction.message:
//   accountKeys, header, recentBlockhash, instructions.
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/message/src/legacy.rs
// ---------------------------------------------------------------------------
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Message {
    /// Describes the signer/writable layout of account_keys (see MessageHeader).
    pub header: MessageHeader,

    /// Flat, deduplicated list of every account the transaction touches.
    ///
    /// Sorted order:
    ///   [writable signers | readonly signers | writable non-signers | readonly non-signers]
    ///
    /// Index 0 is always the fee payer (must be a writable signer).
    /// Programs being called appear here too (usually at the end, readonly).
    pub account_keys: Vec<Pubkey>,

    /// A recent blockhash. Expires after ~150 slots (~60-90 seconds).
    /// Prevents replay attacks and provides time ordering.
    pub recent_blockhash: Hash,

    /// The instructions to execute, in order.
    /// Each instruction references accounts and a program by index into
    /// account_keys rather than embedding Pubkeys directly.
    pub instructions: Vec<CompiledInstruction>,
}

impl Message {
    pub fn new(
        header: MessageHeader,
        account_keys: Vec<Pubkey>,
        recent_blockhash: Hash,
        instructions: Vec<CompiledInstruction>,
    ) -> Self {
        Message {
            header,
            account_keys,
            recent_blockhash,
            instructions,
        }
    }

    /// Returns true if the account at `index` is a signer.
    /// Signers are the first `num_required_signatures` entries in account_keys.
    pub fn is_signer(&self, index: usize) -> bool {
        index < self.header.num_required_signatures as usize
    }

    /// Returns true if the account at `index` is writable.
    ///
    /// An account is writable if it is NOT in either readonly group:
    ///   - readonly signers:   last num_readonly_signed of the signers
    ///   - readonly non-signers: last num_readonly_unsigned of the non-signers
    pub fn is_writable(&self, index: usize) -> bool {
        let num_signers = self.header.num_required_signatures as usize;
        let num_readonly_signed = self.header.num_readonly_signed_accounts as usize;
        let num_readonly_unsigned = self.header.num_readonly_unsigned_accounts as usize;
        let total = self.account_keys.len();

        if index < num_signers {
            // Signer — writable unless it falls in the readonly-signed tail.
            index < num_signers - num_readonly_signed
        } else {
            // Non-signer — writable unless it falls in the readonly-unsigned tail.
            index < total - num_readonly_unsigned
        }
    }
}

// ---------------------------------------------------------------------------
// Transaction — the complete unit submitted to the network.
//
// Wire format (compact-array encoding):
//   [num_signatures] [sig_0] ... [sig_n] [message]
//
// The signatures array is parallel to the first `num_required_signatures`
// entries in message.account_keys — signatures[i] is the signature from
// account_keys[i].
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/transaction/src/lib.rs
// ---------------------------------------------------------------------------
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Transaction {
    /// One Ed25519 signature per required signer.
    /// signatures[i] covers the serialized message bytes and was produced
    /// by the private key corresponding to message.account_keys[i].
    pub signatures: Vec<Signature>,

    /// The payload — accounts, instructions, and blockhash.
    /// This is what the signatures authorize.
    pub message: Message,
}

impl Transaction {
    pub fn new(message: Message, signatures: Vec<Signature>) -> Self {
        Transaction {
            signatures,
            message,
        }
    }

    /// The fee payer is always account_keys[0] — the first writable signer.
    /// It pays the transaction fee (5000 lamports per signature, typically).
    pub fn fee_payer(&self) -> Option<&Pubkey> {
        self.message.account_keys.first()
    }

    /// Returns the number of signatures the transaction requires,
    /// as declared in the message header.
    pub fn num_required_signatures(&self) -> u8 {
        self.message.header.num_required_signatures
    }

    /// Returns true if all required signature slots are filled.
    /// Does not verify the signatures cryptographically — just checks counts.
    pub fn is_signed(&self) -> bool {
        self.signatures.len() == self.message.header.num_required_signatures as usize
    }
}
