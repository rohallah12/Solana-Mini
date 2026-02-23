// ---------------------------------------------------------------------------
// SVM — Solana Virtual Machine (simplified).
//
// The SVM is the pure execution engine. It takes a Transaction whose
// accounts are already identified, loads them from AccountsDB into a
// local working set, dispatches each instruction to the right program,
// and — only if every instruction succeeds — commits the modified
// accounts back to AccountsDB.
//
// It knows nothing about slots, fees, blockhashes, or signatures.
// All of that is the Bank's responsibility (next layer up).
//
// The two-track dispatch mirrors real Solana:
//   - known native program ID  → call hardcoded Rust function directly
//   - unknown program ID       → BPF execution (not yet implemented)
//
// Reference: https://github.com/anza-xyz/agave/tree/master/svm
// ---------------------------------------------------------------------------

use crate::account::AccountSharedData;
use crate::accounts_db::AccountsDB;
use crate::system_program::{self, SYSTEM_PROGRAM_ID};
use crate::transaction::Transaction;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------
#[derive(Debug, PartialEq)]
pub enum SvmError {
    /// An instruction referenced an account index that is out of bounds
    /// in message.account_keys.
    InvalidAccountIndex { instruction: usize, index: u8 },

    /// The program this instruction targets is not a known native program.
    /// BPF execution is not yet implemented.
    UnknownProgram { instruction: usize },

    /// A SystemProgram instruction failed.
    SystemProgram {
        instruction: usize,
        error: system_program::SystemProgramError,
    },
}

// ---------------------------------------------------------------------------
// execute — run a transaction against the accounts DB.
//
// Steps:
//   1. Load every account in message.account_keys from AccountsDB into a
//      local working set (Vec<AccountSharedData>). Accounts that don't
//      exist yet are initialised as empty — the SystemProgram's
//      CreateAccount instruction will populate them.
//
//   2. For each instruction:
//        a. Pull the accounts it needs out of the working set by index
//           into a temporary Vec.
//        b. Dispatch to the appropriate native program.
//        c. On success, write the (possibly mutated) temporary accounts
//           back into the working set at their original positions.
//        d. On failure, return immediately — nothing is committed.
//
//   3. If all instructions succeeded, store every account in the working
//      set back to AccountsDB. This is the commit point.
//      On failure the function already returned, so AccountsDB is untouched.
// ---------------------------------------------------------------------------
pub fn execute(tx: &Transaction, accounts_db: &mut AccountsDB) -> Result<(), SvmError> {
    let message = &tx.message;

    // ------------------------------------------------------------------
    // Step 1 — load accounts into a local working set.
    //
    // We work on this local copy throughout execution. AccountsDB is not
    // touched again until the final commit.
    // ------------------------------------------------------------------
    let mut working_set: Vec<AccountSharedData> = message
        .account_keys
        .iter()
        .map(|pubkey| {
            accounts_db
                .load(pubkey)
                .cloned()
                .unwrap_or_default()
        })
        .collect();

    // ------------------------------------------------------------------
    // Step 2 — execute each instruction.
    // ------------------------------------------------------------------
    for (ix_index, instruction) in message.instructions.iter().enumerate() {
        // Resolve the program ID.
        let program_id_index = instruction.program_id_index as usize;
        let program_id = message
            .account_keys
            .get(program_id_index)
            .ok_or(SvmError::InvalidAccountIndex {
                instruction: ix_index,
                index: instruction.program_id_index,
            })?;

        // Build a temporary Vec of the accounts this instruction operates on,
        // cloned out of the working set. This lets us pass a plain
        // &mut [AccountSharedData] to the program without borrow-checker issues.
        let mut ix_accounts: Vec<AccountSharedData> = instruction
            .accounts
            .iter()
            .enumerate()
            .map(|(pos, &account_index)| {
                working_set
                    .get(account_index as usize)
                    .cloned()
                    .ok_or(SvmError::InvalidAccountIndex {
                        instruction: ix_index,
                        index: account_index,
                    })
            })
            .collect::<Result<_, _>>()?;

        // Dispatch to the correct program.
        if program_id == &SYSTEM_PROGRAM_ID {
            let decoded = system_program::decode(&instruction.data).map_err(|e| {
                SvmError::SystemProgram {
                    instruction: ix_index,
                    error: e,
                }
            })?;

            system_program::process(&decoded, &mut ix_accounts).map_err(|e| {
                SvmError::SystemProgram {
                    instruction: ix_index,
                    error: e,
                }
            })?;
        } else {
            // TODO: BPF execution via EbpfVm
            return Err(SvmError::UnknownProgram { instruction: ix_index });
        }

        // Write the (possibly mutated) instruction accounts back into the
        // working set at their original positions.
        for (pos, &account_index) in instruction.accounts.iter().enumerate() {
            working_set[account_index as usize] = ix_accounts[pos].clone();
        }
    }

    // ------------------------------------------------------------------
    // Step 3 — commit. All instructions succeeded; persist the working
    // set back to AccountsDB.
    // ------------------------------------------------------------------
    for (pubkey, account) in message.account_keys.iter().zip(working_set) {
        accounts_db.store(*pubkey, account);
    }

    Ok(())
}
