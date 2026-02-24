// ---------------------------------------------------------------------------
// SystemProgram — the most fundamental built-in program on Solana.
//
// Lives at the all-zeros address: 11111111111111111111111111111111
// It is NOT stored as BPF bytecode on-chain. The SVM has a hard-coded
// special case: if program_id == SYSTEM_PROGRAM_ID, call this module
// directly instead of executing bytecode.
//
// It is the ONLY program that can:
//   1. Create new accounts (allocate space, assign an owner)
//   2. Transfer lamports out of accounts it owns (plain wallets)
//
// All other programs must own the accounts they modify. SystemProgram
// owns all plain wallets (accounts whose owner field == SYSTEM_PROGRAM_ID).
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/system-program/src/lib.rs
// ---------------------------------------------------------------------------

use crate::types::account::{AccountSharedData, Pubkey};

// The canonical address of the SystemProgram: all 32 bytes are zero.
// On real Solana this displays as "11111111111111111111111111111111" in base58.
pub const SYSTEM_PROGRAM_ID: Pubkey = Pubkey([0u8; 32]);

// ---------------------------------------------------------------------------
// Instruction — the set of operations SystemProgram supports.
//
// The SVM decodes the raw `data: Vec<u8>` bytes from a CompiledInstruction
// into this enum before calling process(). The discriminator is the first
// 4 bytes, little-endian u32.
//
// We implement only the three most essential instructions:
//   CreateAccount (0), Transfer (2), Assign (8)
//
// Reference: https://github.com/anza-xyz/solana-sdk/blob/master/system-interface/src/instruction.rs
// ---------------------------------------------------------------------------
#[derive(Debug, PartialEq)]
pub enum SystemInstruction {
    /// Create a new account.
    ///
    /// Accounts expected:
    ///   [0] funder     — writable, signer. Pays the lamports.
    ///   [1] new account — writable, signer. The address being created.
    ///
    /// Data layout (52 bytes):
    ///   [0..4]   discriminator = 0  (u32 LE)
    ///   [4..12]  lamports           (u64 LE) — initial balance, must cover rent-exemption
    ///   [12..20] space              (u64 LE) — bytes to allocate for account data
    ///   [20..52] owner              ([u8;32]) — program that will own the new account
    CreateAccount {
        lamports: u64,
        space: u64,
        owner: Pubkey,
    },

    /// Transfer lamports from one system-owned account to another.
    ///
    /// Accounts expected:
    ///   [0] from — writable, signer. Must be owned by SystemProgram.
    ///   [1] to   — writable.
    ///
    /// Data layout (12 bytes):
    ///   [0..4]  discriminator = 2  (u32 LE)
    ///   [4..12] lamports           (u64 LE)
    Transfer { lamports: u64 },

    /// Change the owner of a system-owned account.
    ///
    /// Accounts expected:
    ///   [0] account — writable, signer. Must currently be owned by SystemProgram.
    ///
    /// Data layout (36 bytes):
    ///   [0..4]  discriminator = 8  (u32 LE)
    ///   [4..36] owner              ([u8;32]) — the new owner program
    Assign { owner: Pubkey },
}

// ---------------------------------------------------------------------------
// Error — reasons an instruction can fail.
// ---------------------------------------------------------------------------
#[derive(Debug, PartialEq)]
pub enum SystemProgramError {
    /// Instruction data is too short or malformed.
    InvalidInstructionData,
    /// The discriminator does not match any known instruction.
    UnknownInstruction(u32),
    /// The from/source account does not have enough lamports.
    InsufficientFunds,
    /// Tried to create an account that already has lamports or data.
    AccountAlreadyInUse,
    /// The account being debited is not owned by SystemProgram.
    /// Only the owner can debit an account.
    AccountNotOwnedBySystem,
    /// Wrong number of accounts passed to this instruction.
    NotEnoughAccounts,
}

// ---------------------------------------------------------------------------
// Decode — parse raw instruction bytes into a SystemInstruction.
// ---------------------------------------------------------------------------
pub fn decode(data: &[u8]) -> Result<SystemInstruction, SystemProgramError> {
    if data.len() < 4 {
        return Err(SystemProgramError::InvalidInstructionData);
    }

    // First 4 bytes are the discriminator (little-endian u32).
    let discriminator = u32::from_le_bytes(data[0..4].try_into().unwrap());

    match discriminator {
        // CreateAccount — discriminator 0
        0 => {
            if data.len() < 52 {
                return Err(SystemProgramError::InvalidInstructionData);
            }
            let lamports = u64::from_le_bytes(data[4..12].try_into().unwrap());
            let space    = u64::from_le_bytes(data[12..20].try_into().unwrap());
            let owner    = Pubkey(data[20..52].try_into().unwrap());
            Ok(SystemInstruction::CreateAccount { lamports, space, owner })
        }

        // Transfer — discriminator 2
        2 => {
            if data.len() < 12 {
                return Err(SystemProgramError::InvalidInstructionData);
            }
            let lamports = u64::from_le_bytes(data[4..12].try_into().unwrap());
            Ok(SystemInstruction::Transfer { lamports })
        }

        // Assign — discriminator 8
        8 => {
            if data.len() < 36 {
                return Err(SystemProgramError::InvalidInstructionData);
            }
            let owner = Pubkey(data[4..36].try_into().unwrap());
            Ok(SystemInstruction::Assign { owner })
        }

        other => Err(SystemProgramError::UnknownInstruction(other)),
    }
}

// ---------------------------------------------------------------------------
// Process — execute a decoded instruction against a slice of loaded accounts.
//
// The SVM calls this after it has already:
//   - Verified signatures
//   - Loaded accounts from AccountsDB into `accounts`
//
// `accounts` is a mutable slice of the accounts listed in the instruction,
// in the same order as instruction.accounts[]. The SVM will write any
// mutations back to AccountsDB after this returns Ok.
// ---------------------------------------------------------------------------
pub fn process(
    instruction: &SystemInstruction,
    accounts: &mut [AccountSharedData],
) -> Result<(), SystemProgramError> {
    match instruction {
        // -------------------------------------------------------------------
        // CreateAccount
        // -------------------------------------------------------------------
        SystemInstruction::CreateAccount { lamports, space, owner } => {
            if accounts.len() < 2 {
                return Err(SystemProgramError::NotEnoughAccounts);
            }

            // The new account must not already be in use.
            // An account is "in use" if it already has lamports or data.
            let new_account = &accounts[1];
            if new_account.lamports() > 0 || !new_account.data().is_empty() {
                return Err(SystemProgramError::AccountAlreadyInUse);
            }

            // Funder must be owned by SystemProgram (only owner can debit).
            let funder = &accounts[0];
            if funder.owner() != &SYSTEM_PROGRAM_ID {
                return Err(SystemProgramError::AccountNotOwnedBySystem);
            }

            // Funder must have enough lamports.
            if funder.lamports() < *lamports {
                return Err(SystemProgramError::InsufficientFunds);
            }

            // Debit funder.
            let funder_lamports = accounts[0].lamports() - lamports;
            accounts[0].set_lamports(funder_lamports);

            // Initialize the new account.
            accounts[1].set_lamports(*lamports);
            accounts[1].set_owner(*owner);
            accounts[1].data_mut().resize(*space as usize, 0);

            Ok(())
        }

        // -------------------------------------------------------------------
        // Transfer
        // -------------------------------------------------------------------
        SystemInstruction::Transfer { lamports } => {
            if accounts.len() < 2 {
                return Err(SystemProgramError::NotEnoughAccounts);
            }

            // Source must be owned by SystemProgram.
            if accounts[0].owner() != &SYSTEM_PROGRAM_ID {
                return Err(SystemProgramError::AccountNotOwnedBySystem);
            }

            // Source must have enough lamports.
            if accounts[0].lamports() < *lamports {
                return Err(SystemProgramError::InsufficientFunds);
            }

            let from_lamports = accounts[0].lamports() - lamports;
            let to_lamports   = accounts[1].lamports() + lamports;

            accounts[0].set_lamports(from_lamports);
            accounts[1].set_lamports(to_lamports);

            Ok(())
        }

        // -------------------------------------------------------------------
        // Assign
        // -------------------------------------------------------------------
        SystemInstruction::Assign { owner } => {
            if accounts.len() < 1 {
                return Err(SystemProgramError::NotEnoughAccounts);
            }

            // Only SystemProgram can reassign accounts it owns.
            if accounts[0].owner() != &SYSTEM_PROGRAM_ID {
                return Err(SystemProgramError::AccountNotOwnedBySystem);
            }

            accounts[0].set_owner(*owner);

            Ok(())
        }
    }
}
