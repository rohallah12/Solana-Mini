mod types;
mod runtime;
mod programs;

use types::account::{AccountSharedData, Pubkey};
use runtime::accounts_db::AccountsDB;
use runtime::svm;
use programs::system::SYSTEM_PROGRAM_ID;
use types::transaction::{CompiledInstruction, Hash, Message, MessageHeader, Transaction};
use sha2::{Digest, Sha256};
use std::time::Instant;

// ---------------------------------------------------------------------------
// A single entry in the Proof of History chain.
//
// Each entry records:
//   - `hash`       : the SHA-256 output at this point in the chain
//   - `num_hashes` : how many sequential hashes were computed since the
//                    start of the chain (proves that CPU time was spent)
//   - `data`       : an optional payload (e.g. a transaction) that was
//                    "mixed in" to the hash at this point
// ---------------------------------------------------------------------------
#[derive(Clone, Debug)]
struct PohEntry {
    hash: [u8; 32],
    num_hashes: u64,
    data: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// The PoH generator – it continuously hashes to produce a verifiable
// sequence that proves the passage of time.
// ---------------------------------------------------------------------------
struct PohGenerator {
    // The running hash state – each new hash feeds the previous one.
    current_hash: [u8; 32],
    // How many hashes have been computed since the last recorded entry.
    num_hashes: u64,
    // The full ledger of recorded entries.
    entries: Vec<PohEntry>,
}

impl PohGenerator {
    /// Create a new PoH chain starting from a seed value.
    /// The seed is the "genesis" – the very first input to the hash chain.
    fn new(seed: &[u8]) -> Self {
        let hash = sha256(seed);
        PohGenerator {
            current_hash: hash,
            num_hashes: 0,
            entries: vec![],
        }
    }

    /// Advance the hash chain by `count` sequential hashes.
    ///
    /// This is the core "clock tick" of PoH.  Each iteration feeds the
    /// previous hash back into SHA-256, forming an unbreakable chain:
    ///
    ///   h(n+1) = SHA-256( h(n) )
    ///
    /// Because SHA-256 cannot be parallelised, anyone who wants to reproduce
    /// this sequence must spend the same amount of wall-clock time.  That is
    /// the "proof" that real time has passed.
    fn tick(&mut self, count: u64) {
        for _ in 0..count {
            self.current_hash = sha256(&self.current_hash);
            self.num_hashes += 1;
        }

        // Record the tick as an entry (no attached data).
        self.entries.push(PohEntry {
            hash: self.current_hash,
            num_hashes: self.num_hashes,
            data: None,
        });
    }

    /// Mix external data (e.g. a transaction) into the hash chain.
    ///
    /// The data is concatenated with the current hash and then hashed:
    ///
    ///   h(n+1) = SHA-256( h(n) || data )
    ///
    /// This binds the data to a specific position in the sequence, giving it
    /// a provable timestamp relative to every other entry in the chain.
    fn record(&mut self, data: &[u8]) {
        let mut input = Vec::with_capacity(32 + data.len());
        input.extend_from_slice(&self.current_hash);
        input.extend_from_slice(data);

        self.current_hash = sha256(&input);
        self.num_hashes += 1;

        self.entries.push(PohEntry {
            hash: self.current_hash,
            num_hashes: self.num_hashes,
            data: Some(data.to_vec()),
        });
    }
}

// ---------------------------------------------------------------------------
// Verifier – replays the hash chain and checks that every entry is correct.
//
// Crucially, verification can be split across multiple CPU cores because
// each segment between entries is independent once you know the start hash.
// (We keep it single-threaded here for simplicity.)
// ---------------------------------------------------------------------------
fn verify(seed: &[u8], entries: &[PohEntry]) -> bool {
    let mut current_hash = sha256(seed);
    let mut prev_num_hashes: u64 = 0;

    for entry in entries {
        // Figure out how many plain ticks happened between the previous
        // entry and this one.
        let ticks = entry.num_hashes - prev_num_hashes;

        match &entry.data {
            // Entry carries data – all ticks except the last are plain
            // hashes; the final hash mixes in the data.
            Some(data) => {
                for _ in 0..ticks - 1 {
                    current_hash = sha256(&current_hash);
                }
                let mut input = Vec::with_capacity(32 + data.len());
                input.extend_from_slice(&current_hash);
                input.extend_from_slice(data);
                current_hash = sha256(&input);
            }
            // Pure tick – just sequential hashes.
            None => {
                for _ in 0..ticks {
                    current_hash = sha256(&current_hash);
                }
            }
        }

        // If the recomputed hash doesn't match, the chain is invalid.
        if current_hash != entry.hash {
            return false;
        }

        prev_num_hashes = entry.num_hashes;
    }

    true
}

/// Plain SHA-256 helper.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// SVM transfer demo
//
// Demonstrates the full pipeline for a SOL transfer without the Bank layer:
//   AccountsDB  →  Transaction  →  SVM  →  SystemProgram  →  AccountsDB
//
// The Bank (signature verification, fee collection, blockhash check) is
// intentionally skipped here — it will be added in the next session.
// ---------------------------------------------------------------------------
fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / 1_000_000_000.0
}

fn print_balances(label: &str, db: &AccountsDB, keys: &[Pubkey]) {
    println!("  {}:", label);
    for key in keys {
        let lamports = db.load(key).map(|a| a.lamports()).unwrap_or(0);
        println!("    {:?}  {:.9} SOL", key, lamports_to_sol(lamports));
    }
}

fn demo_svm_transfer() {
    println!("=== SVM Transfer Demo ===\n");

    // --- Addresses ---
    let alice  = Pubkey::from_byte(1);
    let bob    = Pubkey::from_byte(2);
    let system = SYSTEM_PROGRAM_ID;

    // --- Set up AccountsDB ---
    // Alice is pre-funded (simulates a genesis airdrop).
    // Bob does not exist yet — his account will be created by the transfer.
    let mut db = AccountsDB::new();
    db.store(alice, AccountSharedData::new(5_000_000_000, 0, system));

    println!("  Balances before:");
    println!("    {:?}  {:.9} SOL  (funded)", alice, lamports_to_sol(5_000_000_000));
    println!("    {:?}  {:.9} SOL  (does not exist yet)\n", bob, lamports_to_sol(0));

    // --- Build the Transfer instruction data ---
    // SystemProgram::Transfer data layout (12 bytes):
    //   [0..4]  discriminator = 2  (u32 LE)
    //   [4..12] lamports           (u64 LE)
    let transfer_lamports: u64 = 1_000_000_000; // 1 SOL
    let mut ix_data = Vec::with_capacity(12);
    ix_data.extend_from_slice(&2u32.to_le_bytes());           // discriminator
    ix_data.extend_from_slice(&transfer_lamports.to_le_bytes()); // amount

    // --- Build the Transaction ---
    //
    // account_keys layout:
    //   [0] alice  — writable signer  (fee payer + source)
    //   [1] bob    — writable         (destination)
    //   [2] system — readonly         (program being called)
    //
    // header encodes these three groups:
    //   num_required_signatures:        1  (alice)
    //   num_readonly_signed_accounts:   0  (alice is writable)
    //   num_readonly_unsigned_accounts: 1  (system)
    let header = MessageHeader {
        num_required_signatures:        1,
        num_readonly_signed_accounts:   0,
        num_readonly_unsigned_accounts: 1,
    };

    let instruction = CompiledInstruction::new(
        2,          // program_id_index → account_keys[2] = SystemProgram
        vec![0, 1], // accounts         → [alice, bob]
        ix_data,
    );

    let message = Message::new(
        header,
        vec![alice, bob, system],
        Hash::default(), // blockhash — Bank would validate this; skipped here
        vec![instruction],
    );

    // NOTE: signatures are empty — the Bank would verify them before calling
    // the SVM. We call the SVM directly here to focus on execution.
    let tx = Transaction::new(message, vec![]);

    println!("  Transaction:");
    println!("    program       : SystemProgram (11111...1)");
    println!("    instruction   : Transfer");
    println!("    from          : {:?}", alice);
    println!("    to            : {:?}", bob);
    println!("    amount        : {:.9} SOL", lamports_to_sol(transfer_lamports));
    println!("    (Bank skipped — no signature verification or fee collection)\n");

    // --- Execute via SVM ---
    print!("  Executing via SVM ... ");
    match svm::execute(&tx, &mut db) {
        Ok(()) => println!("Ok\n"),
        Err(e) => {
            println!("FAILED: {:?}\n", e);
            return;
        }
    }

    // --- Print results ---
    println!("  Balances after:");
    println!("    {:?}  {:.9} SOL", alice, lamports_to_sol(db.load(&alice).unwrap().lamports()));
    println!("    {:?}  {:.9} SOL\n", bob,   lamports_to_sol(db.load(&bob).unwrap().lamports()));

    // --- Failure demo: try to overdraft Alice ---
    println!("  Overdraft attempt (transfer 999 SOL Alice → Bob) ...");
    let mut ix_data_overdraft = Vec::with_capacity(12);
    ix_data_overdraft.extend_from_slice(&2u32.to_le_bytes());
    ix_data_overdraft.extend_from_slice(&999_000_000_000u64.to_le_bytes());

    let ix_overdraft = CompiledInstruction::new(2, vec![0, 1], ix_data_overdraft);
    let msg_overdraft = Message::new(
        MessageHeader { num_required_signatures: 1, num_readonly_signed_accounts: 0, num_readonly_unsigned_accounts: 1 },
        vec![alice, bob, system],
        Hash::default(),
        vec![ix_overdraft],
    );
    let tx_overdraft = Transaction::new(msg_overdraft, vec![]);

    match svm::execute(&tx_overdraft, &mut db) {
        Ok(())  => println!("  Result: Ok  (unexpected!)"),
        Err(e)  => println!("  Result: Err({:?})  ✓ rejected correctly\n", e),
    }

    println!("  Balances unchanged after failed tx:");
    println!("    {:?}  {:.9} SOL", alice, lamports_to_sol(db.load(&alice).unwrap().lamports()));
    println!("    {:?}  {:.9} SOL\n", bob,   lamports_to_sol(db.load(&bob).unwrap().lamports()));
}

// ---------------------------------------------------------------------------
// Demo
// ---------------------------------------------------------------------------
fn main() {
    let seed = b"solana-genesis";

    println!("=== Proof of History Engine ===\n");

    // --- Generate the PoH sequence ---
    let mut poh = PohGenerator::new(seed);

    let gen_start = Instant::now();

    // Simulate passage of time (800 sequential hashes).
    poh.tick(800);

    // A "transaction" arrives and gets stamped into the chain.
    poh.record(b"Alice sends 5 SOL to Bob");

    // More time passes (600 hashes).
    poh.tick(600);

    // Another transaction.
    poh.record(b"Bob sends 2 SOL to Charlie");

    // Final tick (400 hashes).
    poh.tick(400);

    let gen_elapsed = gen_start.elapsed();

    // --- Print the ledger ---
    for (i, entry) in poh.entries.iter().enumerate() {
        let data_str = match &entry.data {
            Some(d) => format!("\"{}\"", String::from_utf8_lossy(d)),
            None => "-- tick --".to_string(),
        };
        println!(
            "Entry {}: hashes={:<6} data={:<35} hash={}",
            i,
            entry.num_hashes,
            data_str,
            hex::encode(entry.hash)
        );
    }

    println!("\nGeneration took:   {:?}", gen_elapsed);

    // --- Verify the chain ---
    let ver_start = Instant::now();
    let valid = verify(seed, &poh.entries);
    let ver_elapsed = ver_start.elapsed();

    println!("Verification took: {:?}", ver_elapsed);
    println!("Chain valid: {}\n", valid);

    // --- Tamper demo: modify data and show verification fails ---
    println!("=== Tampering Demo ===\n");
    let mut tampered = poh.entries.clone();
    tampered[1].data = Some(b"Alice sends 999 SOL to Bob".to_vec());

    let tampered_valid = verify(seed, &tampered);
    println!(
        "Tampered chain valid: {}  (expected: false)\n",
        tampered_valid
    );

    demo_svm_transfer();
}
