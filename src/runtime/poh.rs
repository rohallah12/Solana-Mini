// ---------------------------------------------------------------------------
// Proof of History — the Solana clock.
//
// PoH is a sequential SHA-256 hash chain. Because SHA-256 cannot be
// parallelised, anyone who wants to reproduce the chain must spend the
// same wall-clock time. That is the "proof" — it proves real time passed.
//
// Two operations:
//   tick()   — advance the chain N hashes, record a tick entry (no txs)
//   record() — mix a batch of transactions into the chain, record a tx entry
//
// Entry types (matching Solana spec):
//   Tick entry:   { num_hashes: N, hash: h, transactions: [] }
//   Record entry: { num_hashes: 1, hash: h, transactions: [tx, ...] }
//
// Hash mixing for record():
//   tx_hash  = SHA-256( sig_0 || sig_1 || ... )   — hash of all signatures
//   new_hash = SHA-256( current_hash || tx_hash )
//
//   Note: while the Bank layer (and real Ed25519 signing) is not yet built,
//   signatures are empty. We fall back to hashing the serialized account
//   keys as a stand-in so the chain stays deterministic and verifiable.
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/entry/src/entry.rs
// ---------------------------------------------------------------------------

use sha2::{Digest, Sha256};
use crate::types::transaction::Transaction;

// ---------------------------------------------------------------------------
// Entry — one record in the PoH ledger.
//
// Matches Solana's Entry struct exactly:
//   num_hashes:   how many SHA-256 iterations since the previous entry
//   hash:         the chain value at this entry
//   transactions: the batch of transactions stamped at this point in time
//                 empty for tick entries
// ---------------------------------------------------------------------------
#[derive(Clone, Debug)]
pub struct Entry {
    /// Number of hashes computed since the previous entry.
    /// For tick entries this is the configured hashes_per_tick.
    /// For record entries this is always 1 (the mixing hash).
    pub num_hashes: u64,

    /// The SHA-256 chain value at this point.
    pub hash: [u8; 32],

    /// Transactions stamped into this entry.
    /// Empty for tick entries. One or more for record entries.
    pub transactions: Vec<Transaction>,
}

// ---------------------------------------------------------------------------
// PohGenerator — the running hash chain.
// ---------------------------------------------------------------------------
pub struct PohGenerator {
    /// The current (latest) hash in the chain.
    current_hash: [u8; 32],

    /// Total hashes computed since the last recorded entry.
    num_hashes: u64,

    /// The complete ledger of entries produced so far.
    pub entries: Vec<Entry>,

    /// How many sequential hashes constitute one "tick".
    /// Real Solana: ~12,500 (calibrated to 6.25ms on validator hardware).
    /// We use a smaller number so output is human-readable.
    pub hashes_per_tick: u64,
}

impl PohGenerator {
    /// Create a new PoH chain starting from a seed (the genesis hash).
    pub fn new(seed: &[u8], hashes_per_tick: u64) -> Self {
        PohGenerator {
            current_hash: sha256(seed),
            num_hashes: 0,
            entries: vec![],
            hashes_per_tick,
        }
    }

    // -----------------------------------------------------------------------
    // tick — advance the chain by one full tick (hashes_per_tick hashes).
    //
    // Produces a tick entry with no transactions. This is how PoH proves
    // that time passed even when no transactions arrived.
    // -----------------------------------------------------------------------
    pub fn tick(&mut self) {
        for _ in 0..self.hashes_per_tick {
            self.current_hash = sha256(&self.current_hash);
            self.num_hashes += 1;
        }

        self.entries.push(Entry {
            num_hashes: self.num_hashes,
            hash: self.current_hash,
            transactions: vec![],
        });

        // Reset counter — num_hashes in each entry is relative to the
        // previous entry, not the chain origin.
        self.num_hashes = 0;
    }

    // -----------------------------------------------------------------------
    // record — stamp a batch of transactions into the chain.
    //
    // Computes one additional hash mixing in the transaction data, then
    // records an entry containing the transactions.
    //
    // Hash mixing (Solana spec):
    //   tx_hash  = SHA-256( all_signature_bytes_concatenated )
    //   new_hash = SHA-256( current_hash || tx_hash )
    // -----------------------------------------------------------------------
    pub fn record(&mut self, transactions: Vec<Transaction>) {
        let tx_hash = hash_transactions(&transactions);

        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(&self.current_hash);
        input.extend_from_slice(&tx_hash);
        self.current_hash = sha256(&input);
        self.num_hashes += 1;

        let num_hashes = self.num_hashes;
        self.entries.push(Entry {
            num_hashes,
            hash: self.current_hash,
            transactions,
        });

        self.num_hashes = 0;
    }

    /// The latest hash in the chain — used as the recent_blockhash for
    /// incoming transactions.
    pub fn last_hash(&self) -> [u8; 32] {
        self.current_hash
    }
}

// ---------------------------------------------------------------------------
// hash_transactions — compute the hash mixed into PoH for a tx batch.
//
// Real Solana hashes all signature bytes concatenated.
// While the Bank / Ed25519 signing layer is not yet built, transactions
// carry no real signatures, so we hash the account_keys bytes instead
// as a deterministic stand-in.
// ---------------------------------------------------------------------------
fn hash_transactions(transactions: &[Transaction]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for tx in transactions {
        if !tx.signatures.is_empty() {
            // Real path: hash signature bytes.
            for sig in &tx.signatures {
                hasher.update(sig.0);
            }
        } else {
            // Stand-in path (no Bank yet): hash account key bytes.
            for key in &tx.message.account_keys {
                hasher.update(key.0);
            }
        }
    }
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// verify — replay the chain from a seed and confirm every entry is valid.
//
// This can be parallelised in real Solana (each segment between entries
// is independent once you know the start hash). We keep it sequential.
// ---------------------------------------------------------------------------
pub fn verify(seed: &[u8], entries: &[Entry]) -> bool {
    let mut current_hash = sha256(seed);

    for entry in entries {
        if entry.transactions.is_empty() {
            // Tick entry: plain sequential hashes.
            for _ in 0..entry.num_hashes {
                current_hash = sha256(&current_hash);
            }
        } else {
            // Record entry: (num_hashes - 1) plain hashes + 1 mixing hash.
            for _ in 0..entry.num_hashes.saturating_sub(1) {
                current_hash = sha256(&current_hash);
            }
            let tx_hash = hash_transactions(&entry.transactions);
            let mut input = Vec::with_capacity(64);
            input.extend_from_slice(&current_hash);
            input.extend_from_slice(&tx_hash);
            current_hash = sha256(&input);
        }

        if current_hash != entry.hash {
            return false;
        }
    }

    true
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
