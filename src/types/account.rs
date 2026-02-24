// ---------------------------------------------------------------------------
// Account types — modeled after Solana's account model.
//
// In Solana, EVERYTHING is an account. Programs, wallets, token balances,
// NFT metadata — all stored as accounts. Each account lives at an address
// (a 32-byte public key) and is owned by a program.
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/account/src/lib.rs
// ---------------------------------------------------------------------------

use std::fmt;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Pubkey — a 32-byte address (Ed25519 public key).
//
// In Solana this is just a wrapper around [u8; 32].
// Every account, program, and signer is identified by one.
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/address/src/lib.rs
// ---------------------------------------------------------------------------
#[derive(Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    /// Create a new Pubkey from a 32-byte array.
    pub fn new(bytes: [u8; 32]) -> Self {
        Pubkey(bytes)
    }

    /// A convenience for creating test keys from a single byte.
    /// e.g. Pubkey::from_byte(1) → [1, 0, 0, ..., 0]
    pub fn from_byte(b: u8) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        Pubkey(bytes)
    }

    /// The all-zeros pubkey — used as the "system program" address in Solana.
    /// Accounts owned by Pubkey::default() are "system accounts" (plain wallets).
    pub fn is_default(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show first 4 bytes in hex for readability, like "Pubkey(aabbccdd...)"
        write!(
            f,
            "Pubkey({}..)",
            self.0[..4]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        )
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Full hex representation
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Epoch — a u64 representing a time period in the validator schedule.
//
// In Solana, an epoch = 432,000 slots (~2-3 days).
// Used for rent collection and leader scheduling.
// ---------------------------------------------------------------------------
pub type Epoch = u64;

// ---------------------------------------------------------------------------
// Lamports — the smallest unit of SOL.
//
// 1 SOL = 1,000,000,000 lamports (10^9).
// Like satoshis to bitcoin, or wei to ether.
// ---------------------------------------------------------------------------
pub type Lamports = u64;

// ---------------------------------------------------------------------------
// Account — the owned version.
//
// This is the "simple" account struct. It owns its data directly via Vec<u8>.
// Used for serialization, RPC responses, and when you need a self-contained
// copy of an account.
//
// In Solana, every account on-chain has these 5 fields:
//
//   lamports:   the balance in lamports (1 SOL = 10^9 lamports)
//   data:       arbitrary byte array — programs store their state here
//   owner:      the program that owns this account (only the owner can modify it)
//   executable: if true, this account contains a program (BPF bytecode)
//   rent_epoch: the epoch at which rent was last collected
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/account/src/lib.rs
// ---------------------------------------------------------------------------
#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct Account {
    /// Balance in lamports. Every account must hold enough lamports to be
    /// "rent-exempt" (currently ~0.00089 SOL per byte), or it gets garbage
    /// collected by the runtime.
    pub lamports: Lamports,

    /// Arbitrary data stored in this account. For a wallet, this is empty.
    /// For a token account, this holds the token balance, mint, owner, etc.
    /// For a program, this holds the compiled BPF bytecode.
    /// Max size: 10 MB.
    pub data: Vec<u8>,

    /// The program that owns this account.
    ///
    /// Only the owner program can:
    ///   - Modify the account's data
    ///   - Debit lamports from the account
    ///
    /// For plain wallets, owner = SystemProgram (Pubkey::default()).
    /// For SPL token accounts, owner = TokenProgram.
    /// For program accounts, owner = BPF Loader.
    pub owner: Pubkey,

    /// If true, this account's data is a program (BPF bytecode) and the
    /// runtime will execute it when invoked. Once set to true, it's
    /// permanent — programs are immutable (unless upgradeable).
    pub executable: bool,

    /// The epoch at which this account will next owe rent.
    /// Most accounts are now rent-exempt (hold enough lamports to cover
    /// rent forever), so this field is largely vestigial.
    pub rent_epoch: Epoch,
}

impl Account {
    /// Create a new account with the given lamports and owner.
    /// This is the most common way to create a plain wallet account.
    pub fn new(lamports: Lamports, owner: Pubkey) -> Self {
        Account {
            lamports,
            data: vec![],
            owner,
            executable: false,
            rent_epoch: 0,
        }
    }

    /// Create a new account with data space pre-allocated.
    /// Used when creating accounts that will hold program state.
    pub fn new_with_data(lamports: Lamports, data_len: usize, owner: Pubkey) -> Self {
        Account {
            lamports,
            data: vec![0; data_len],
            owner,
            executable: false,
            rent_epoch: 0,
        }
    }

    /// Convert to the shared (Arc-backed) version.
    pub fn to_shared(self) -> AccountSharedData {
        AccountSharedData {
            lamports: self.lamports,
            data: Arc::new(self.data),
            owner: self.owner,
            executable: self.executable,
            rent_epoch: self.rent_epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// AccountSharedData — the reference-counted version.
//
// Same fields as Account, but the data is wrapped in Arc<Vec<u8>>.
// This enables cheap cloning and copy-on-write semantics.
//
// The runtime uses this internally because accounts get passed around a lot
// during transaction execution (read by multiple instructions, cached in
// the accounts DB, etc.). Cloning a Vec<u8> for a 10MB account every time
// would be expensive — Arc makes it a pointer copy instead.
//
// When a program actually modifies the data, Arc::make_mut() triggers a
// copy-on-write: only then is the data duplicated.
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/account/src/lib.rs
// ---------------------------------------------------------------------------
#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct AccountSharedData {
    lamports: Lamports,
    data: Arc<Vec<u8>>,
    owner: Pubkey,
    executable: bool,
    rent_epoch: Epoch,
}

impl AccountSharedData {
    pub fn new(lamports: Lamports, data_len: usize, owner: Pubkey) -> Self {
        AccountSharedData {
            lamports,
            data: Arc::new(vec![0; data_len]),
            owner,
            executable: false,
            rent_epoch: 0,
        }
    }

    // --- Getters ---

    pub fn lamports(&self) -> Lamports {
        self.lamports
    }

    /// Returns a read-only reference to the data.
    /// Cheap — no copying, just borrows through the Arc.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn owner(&self) -> &Pubkey {
        &self.owner
    }

    pub fn executable(&self) -> bool {
        self.executable
    }

    pub fn rent_epoch(&self) -> Epoch {
        self.rent_epoch
    }

    // --- Setters ---

    pub fn set_lamports(&mut self, lamports: Lamports) {
        self.lamports = lamports;
    }

    /// Returns a mutable reference to the data.
    /// This triggers copy-on-write via Arc::make_mut — if other clones
    /// exist, the data is duplicated here so we don't corrupt them.
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        Arc::make_mut(&mut self.data)
    }

    pub fn set_owner(&mut self, owner: Pubkey) {
        self.owner = owner;
    }

    pub fn set_executable(&mut self, executable: bool) {
        self.executable = executable;
    }

    pub fn set_rent_epoch(&mut self, rent_epoch: Epoch) {
        self.rent_epoch = rent_epoch;
    }

    /// Convert to the owned version (copies the data out of the Arc).
    pub fn to_account(&self) -> Account {
        Account {
            lamports: self.lamports,
            data: (*self.data).clone(),
            owner: self.owner,
            executable: self.executable,
            rent_epoch: self.rent_epoch,
        }
    }
}
