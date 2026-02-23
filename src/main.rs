mod account;
mod accounts_db;
mod svm;
mod system_program;
mod transaction;

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
}
