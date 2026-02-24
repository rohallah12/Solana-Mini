// ---------------------------------------------------------------------------
// AccountsDB — the accounts state store.
//
// This is a map from Pubkey → AccountSharedData representing the current
// state of every account on the chain. It is the single source of truth
// for all account balances, program data, and on-chain state.
//
// In real Solana, AccountsDB is extremely complex — it uses memory-mapped
// files, multiple storage tiers, snapshots, and append-only writes for
// performance. Here we model the essential interface: load and store.
//
// Reference: https://github.com/anza-xyz/agave/blob/master/accounts-db/src/accounts_db.rs
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use crate::types::account::{AccountSharedData, Pubkey};

// ---------------------------------------------------------------------------
// AccountsDB — the state store.
//
// Internally just a HashMap. The key insight is that every account —
// wallets, programs, token accounts, sysvars — lives in this one map.
// There is no separate "program store" or "wallet store"; everything is
// an account identified by its Pubkey.
// ---------------------------------------------------------------------------
pub struct AccountsDB {
    accounts: HashMap<Pubkey, AccountSharedData>,
}

impl AccountsDB {
    /// Create an empty AccountsDB.
    pub fn new() -> Self {
        AccountsDB {
            accounts: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Core operations
    // -----------------------------------------------------------------------

    /// Load an account by address.
    ///
    /// Returns None if the account does not exist. In Solana, a missing
    /// account and a zeroed-out account are treated the same way —
    /// neither has lamports or data.
    pub fn load(&self, pubkey: &Pubkey) -> Option<&AccountSharedData> {
        self.accounts.get(pubkey)
    }

    /// Store an account at the given address, replacing any existing state.
    ///
    /// This is the only way state changes enter the DB. In real Solana,
    /// stores are append-only (old versions are kept for snapshots and
    /// historical queries). Here we overwrite for simplicity.
    pub fn store(&mut self, pubkey: Pubkey, account: AccountSharedData) {
        self.accounts.insert(pubkey, account);
    }

    /// Remove an account from the DB.
    ///
    /// In Solana, an account is "deleted" by zeroing its lamports and data.
    /// The runtime then garbage-collects it. We expose an explicit delete
    /// here for clarity.
    pub fn delete(&mut self, pubkey: &Pubkey) {
        self.accounts.remove(pubkey);
    }

    // -----------------------------------------------------------------------
    // Inspection helpers
    // -----------------------------------------------------------------------

    /// Returns true if an account exists at this address.
    pub fn contains(&self, pubkey: &Pubkey) -> bool {
        self.accounts.contains_key(pubkey)
    }

    /// Total number of accounts currently stored.
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
}
