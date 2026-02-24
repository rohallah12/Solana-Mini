// ---------------------------------------------------------------------------
// RPC server — minimal HTTP endpoint for submitting transactions.
//
// Listens on 0.0.0.0:8080. One endpoint:
//
//   POST /transfer
//   Body: { "from": <u8>, "to": <u8>, "lamports": <u64> }
//
//   "from" and "to" are the single-byte shorthand for Pubkey::from_byte().
//   No signatures yet — the Bank layer (next session) will add that.
//
// On each request:
//   1. Parse JSON body
//   2. Build a Transaction (SystemProgram::Transfer)
//   3. Execute via SVM against the shared AccountsDB
//   4. Record the transaction into the shared PoH chain
//   5. Log everything to the terminal and return JSON response
//
// State is shared between the PoH ticker thread and this server thread
// via Arc<Mutex<>>.
// ---------------------------------------------------------------------------

use std::io::Read;
use std::sync::{Arc, Mutex};

use tiny_http::{Method, Response, Server};

use crate::programs::system::SYSTEM_PROGRAM_ID;
use crate::runtime::accounts_db::AccountsDB;
use crate::runtime::poh::PohGenerator;
use crate::runtime::svm;
use crate::types::account::{AccountSharedData, Pubkey};
use crate::types::transaction::{CompiledInstruction, Hash, Message, MessageHeader, Transaction};

// ---------------------------------------------------------------------------
// Shared state passed into the server.
// ---------------------------------------------------------------------------
pub struct NodeState {
    pub db:          Arc<Mutex<AccountsDB>>,
    pub poh:         Arc<Mutex<PohGenerator>>,
    pub log_entries: bool,
}

// ---------------------------------------------------------------------------
// start — blocking entry point called from main().
//
// Spawns the PoH ticker on a background thread, then runs the HTTP server
// on the current thread.
// ---------------------------------------------------------------------------
pub fn start(log_entries: bool) {
    // --- Genesis: pre-fund a handful of accounts so you can transfer immediately ---
    let mut db = AccountsDB::new();
    for byte in 1..=5u8 {
        let key = Pubkey::from_byte(byte);
        db.store(key, AccountSharedData::new(100_000_000_000, 0, SYSTEM_PROGRAM_ID));
        println!("[genesis] funded {:?} with 100 SOL", key);
    }

    let state = Arc::new(NodeState {
        db:          Arc::new(Mutex::new(db)),
        poh:         Arc::new(Mutex::new(PohGenerator::new(b"solana-genesis", 100))),
        log_entries,
    });

    // --- PoH ticker thread ---
    // Ticks continuously at hashes_per_tick=100.
    // Prints each tick entry so you can see the clock running.
    let poh_ref      = Arc::clone(&state.poh);
    let log_entries_ = log_entries;
    std::thread::spawn(move || {
        loop {
            {
                let mut poh = poh_ref.lock().unwrap();
                poh.tick();
                let idx   = poh.entries.len() - 1;
                let entry = &poh.entries[idx];
                if log_entries_ {
                    print_entry(idx, entry);
                } else {
                    println!(
                        "[poh] tick  hashes={:<6} hash={}",
                        entry.num_hashes,
                        hex::encode(&entry.hash[..8])
                    );
                }
            }
            // Sleep between ticks so the terminal stays readable.
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    });

    // --- HTTP server ---
    let server = Server::http("0.0.0.0:8080").expect("failed to bind port 8080");
    println!("\n[rpc] listening on http://0.0.0.0:8080");
    println!("[rpc] POST /transfer  body: {{\"from\":1,\"to\":2,\"lamports\":1000000000}}\n");

    for mut request in server.incoming_requests() {
        let response = match (request.method(), request.url()) {
            (Method::Post, "/transfer") => handle_transfer(&mut request, &state),
            _ => json_response(404, r#"{"error":"not found"}"#),
        };
        let _ = request.respond(response);
    }
}

// ---------------------------------------------------------------------------
// handle_transfer — parse, execute, record, respond.
// ---------------------------------------------------------------------------
fn handle_transfer(
    request: &mut tiny_http::Request,
    state: &Arc<NodeState>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    // --- 1. Read and parse body ---
    let mut body = String::new();
    if request.as_reader().read_to_string(&mut body).is_err() {
        return json_response(400, r#"{"error":"could not read body"}"#);
    }

    let parsed: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v)  => v,
        Err(e) => return json_response(400, &format!("{{\"error\":\"{}\"}}", e)),
    };

    let from_byte = match parsed["from"].as_u64().and_then(|v| u8::try_from(v).ok()) {
        Some(b) => b,
        None    => return json_response(400, r#"{"error":"\"from\" must be a u8"}"#),
    };
    let to_byte = match parsed["to"].as_u64().and_then(|v| u8::try_from(v).ok()) {
        Some(b) => b,
        None    => return json_response(400, r#"{"error":"\"to\" must be a u8"}"#),
    };
    let lamports = match parsed["lamports"].as_u64() {
        Some(l) => l,
        None    => return json_response(400, r#"{"error":"\"lamports\" must be a u64"}"#),
    };

    let from   = Pubkey::from_byte(from_byte);
    let to     = Pubkey::from_byte(to_byte);
    let system = SYSTEM_PROGRAM_ID;

    println!("[rpc] transfer request: {:?} → {:?}  {} lamports", from, to, lamports);

    // --- 2. Build the Transaction ---
    // SystemProgram::Transfer data: [discriminator=2 u32LE | lamports u64LE]
    let mut ix_data = Vec::with_capacity(12);
    ix_data.extend_from_slice(&2u32.to_le_bytes());
    ix_data.extend_from_slice(&lamports.to_le_bytes());

    // Fetch current PoH hash to use as recent_blockhash.
    let recent_blockhash = {
        let poh = state.poh.lock().unwrap();
        Hash::new(poh.last_hash())
    };

    let tx = Transaction::new(
        Message::new(
            MessageHeader {
                num_required_signatures:        1,
                num_readonly_signed_accounts:   0,
                num_readonly_unsigned_accounts: 1,
            },
            vec![from, to, system],
            recent_blockhash,
            vec![CompiledInstruction::new(2, vec![0, 1], ix_data)],
        ),
        vec![], // signatures — Bank will verify these in a future session
    );

    // --- 3. Execute via SVM ---
    let result = {
        let mut db = state.db.lock().unwrap();

        let from_before = db.load(&from).map(|a| a.lamports()).unwrap_or(0);
        let to_before   = db.load(&to).map(|a| a.lamports()).unwrap_or(0);

        println!(
            "[svm]  before: {:?}={} lamports  {:?}={} lamports",
            from, from_before, to, to_before
        );

        match svm::execute(&tx, &mut db) {
            Ok(()) => {
                let from_after = db.load(&from).map(|a| a.lamports()).unwrap_or(0);
                let to_after   = db.load(&to).map(|a| a.lamports()).unwrap_or(0);
                println!(
                    "[svm]  after:  {:?}={} lamports  {:?}={} lamports",
                    from, from_after, to, to_after
                );
                Ok(())
            }
            Err(e) => {
                println!("[svm]  failed: {:?}", e);
                Err(format!("{:?}", e))
            }
        }
    };

    // --- 4. Record into PoH (only on success) ---
    let entry_hash = match &result {
        Ok(()) => {
            let mut poh = state.poh.lock().unwrap();
            poh.record(vec![tx]);
            let idx   = poh.entries.len() - 1;
            let entry = &poh.entries[idx];
            let hash_hex = hex::encode(entry.hash);
            if state.log_entries {
                print_entry(idx, entry);
            } else {
                println!(
                    "[poh]  record hashes={:<6} hash={} txs=1",
                    entry.num_hashes,
                    hex::encode(&entry.hash[..8])
                );
            }
            hash_hex
        }
        Err(_) => String::new(),
    };

    // --- 5. Respond ---
    match result {
        Ok(()) => json_response(200, &format!(
            r#"{{"ok":true,"entry_hash":"{}"}}"#,
            entry_hash
        )),
        Err(e) => json_response(400, &format!(
            r#"{{"ok":false,"error":"{}"}}"#,
            e
        )),
    }
}

// ---------------------------------------------------------------------------
// print_entry — full entry dump, shown when --log-entries is passed.
// ---------------------------------------------------------------------------
fn print_entry(idx: usize, entry: &crate::runtime::poh::Entry) {
    let kind = if entry.transactions.is_empty() { "TICK  " } else { "RECORD" };
    println!(
        "[entry #{:<4}] {}  hashes={:<6}  hash={}",
        idx,
        kind,
        entry.num_hashes,
        hex::encode(entry.hash),
    );
    for (ti, tx) in entry.transactions.iter().enumerate() {
        println!("  tx[{}]:", ti);
        println!("    account_keys ({}):", tx.message.account_keys.len());
        for (i, key) in tx.message.account_keys.iter().enumerate() {
            let writable = tx.message.is_writable(i);
            let signer   = tx.message.is_signer(i);
            println!(
                "      [{}] {:?}  writable={}  signer={}",
                i, key, writable, signer
            );
        }
        for (ii, ix) in tx.message.instructions.iter().enumerate() {
            println!(
                "    ix[{}]: program_id_index={}  accounts={:?}  data={} bytes",
                ii,
                ix.program_id_index,
                ix.accounts,
                ix.data.len(),
            );
        }
    }
}

fn json_response(code: u32, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body)
        .with_status_code(code)
        .with_header(
            "Content-Type: application/json".parse::<tiny_http::Header>().unwrap()
        )
}
