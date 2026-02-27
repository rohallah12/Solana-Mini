// ---------------------------------------------------------------------------
// RPC server — minimal HTTP endpoint for submitting transactions.
//
// Listens on 0.0.0.0:8080. One endpoint:
//
//   POST /transfer
//   Body: { "from": <u8>, "to": <u8>, "lamports": <u64> }
//
//   "from" and "to" are single-byte genesis account identifiers (1–5).
//   The server holds the signing keys for those accounts and signs the
//   transaction on their behalf before passing it to the Bank for
//   signature verification.
//
// On each request:
//   1. Parse JSON body
//   2. Build a Transaction (SystemProgram::Transfer)
//   3. Sign the message with the sender's Ed25519 key
//   4. Bank::verify_signatures (rejects if signature is invalid)
//   5. SVM::execute (load, dispatch, commit)
//   6. Record into PoH chain on success
//   7. Log and return JSON response
//
// State is shared between the PoH ticker thread and this server thread
// via Arc<Mutex<>>.
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use tiny_http::{Method, Response, Server};

use crate::programs::system::SYSTEM_PROGRAM_ID;
use crate::runtime::accounts_db::AccountsDB;
use crate::runtime::bank;
use crate::runtime::poh::PohGenerator;
use crate::runtime::svm;
use crate::types::account::{AccountSharedData, Pubkey};
use crate::types::transaction::{
    CompiledInstruction, Hash, Message, MessageHeader, Signature, Transaction,
};

// ---------------------------------------------------------------------------
// Shared state.
//
// keypairs maps the u8 genesis identifier (1–5) to:
//   - the actual Ed25519-derived Pubkey stored in AccountsDB
//   - the SigningKey used to sign transactions on behalf of that account
// ---------------------------------------------------------------------------
pub struct NodeState {
    pub db:          Arc<Mutex<AccountsDB>>,
    pub poh:         Arc<Mutex<PohGenerator>>,
    pub keypairs:    HashMap<u8, (Pubkey, SigningKey)>,
    pub log_entries: bool,
}

// ---------------------------------------------------------------------------
// start — blocking entry point called from main().
// ---------------------------------------------------------------------------
pub fn start(log_entries: bool) {
    // --- Genesis ---
    // For each identifier byte b, we derive a deterministic Ed25519 keypair
    // by using [b; 32] as the signing key seed. The actual Pubkey stored in
    // AccountsDB is the Ed25519 verifying key (32 bytes), NOT from_byte(b).
    let mut db       = AccountsDB::new();
    let mut keypairs = HashMap::new();

    for b in 1..=5u8 {
        let seed: [u8; 32]  = [b; 32];
        let signing_key      = SigningKey::from_bytes(&seed);
        let pubkey           = Pubkey(signing_key.verifying_key().to_bytes());

        db.store(pubkey, AccountSharedData::new(100_000_000_000, 0, SYSTEM_PROGRAM_ID));
        println!("[genesis] account {} → {:?}  (100 SOL)", b, pubkey);

        keypairs.insert(b, (pubkey, signing_key));
    }

    let state = Arc::new(NodeState {
        db:  Arc::new(Mutex::new(db)),
        poh: Arc::new(Mutex::new(PohGenerator::new(b"solana-genesis", 100))),
        keypairs,
        log_entries,
    });

    // --- PoH ticker thread ---
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
// handle_transfer
// ---------------------------------------------------------------------------
fn handle_transfer(
    request: &mut tiny_http::Request,
    state: &Arc<NodeState>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    // --- 1. Parse body ---
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
        None    => return json_response(400, r#"{"error":"\"from\" must be a u8 (1-5)"}"#),
    };
    let to_byte = match parsed["to"].as_u64().and_then(|v| u8::try_from(v).ok()) {
        Some(b) => b,
        None    => return json_response(400, r#"{"error":"\"to\" must be a u8 (1-5)"}"#),
    };
    let lamports = match parsed["lamports"].as_u64() {
        Some(l) => l,
        None    => return json_response(400, r#"{"error":"\"lamports\" must be a u64"}"#),
    };

    // Resolve byte identifiers → actual Ed25519 pubkeys.
    let (from, signing_key) = match state.keypairs.get(&from_byte) {
        Some((pk, sk)) => (*pk, sk),
        None => return json_response(400, r#"{"error":"\"from\" is not a known genesis account"}"#),
    };
    let to = match state.keypairs.get(&to_byte) {
        Some((pk, _)) => *pk,
        None => return json_response(400, r#"{"error":"\"to\" is not a known genesis account"}"#),
    };
    let system = SYSTEM_PROGRAM_ID;

    println!("[rpc] transfer  {} → {}  {} lamports", from_byte, to_byte, lamports);

    // --- 2. Build unsigned Transaction ---
    let mut ix_data = Vec::with_capacity(12);
    ix_data.extend_from_slice(&2u32.to_le_bytes());
    ix_data.extend_from_slice(&lamports.to_le_bytes());

    let recent_blockhash = {
        let poh = state.poh.lock().unwrap();
        Hash::new(poh.last_hash())
    };

    let message = Message::new(
        MessageHeader {
            num_required_signatures:        1,
            num_readonly_signed_accounts:   0,
            num_readonly_unsigned_accounts: 1,
        },
        vec![from, to, system],
        recent_blockhash,
        vec![CompiledInstruction::new(2, vec![0, 1], ix_data)],
    );

    // --- 3. Sign the message ---
    // serialize_message() produces the canonical bytes that the Bank will
    // verify. The sender's Ed25519 private key signs those bytes.
    let message_bytes = bank::serialize_message(&message);
    let dalek_sig     = signing_key.sign(&message_bytes);
    let signature     = Signature(dalek_sig.to_bytes());

    println!("[bank] signed   sig={}", hex::encode(&signature.0[..8]));

    let tx = Transaction::new(message, vec![signature]);

    // --- 4. Bank: verify signatures ---
    if let Err(e) = bank::verify_signatures(&tx) {
        println!("[bank] rejected: {:?}", e);
        return json_response(400, &format!(r#"{{"ok":false,"error":"{:?}"}}"#, e));
    }
    println!("[bank] verified  ✓");

    // --- 5. SVM: execute ---
    let result = {
        let mut db = state.db.lock().unwrap();

        let from_before = db.load(&from).map(|a| a.lamports()).unwrap_or(0);
        let to_before   = db.load(&to).map(|a| a.lamports()).unwrap_or(0);
        println!("[svm]  before: {}={} lamports  {}={} lamports",
            from_byte, from_before, to_byte, to_before);

        match svm::execute(&tx, &mut db) {
            Ok(()) => {
                let from_after = db.load(&from).map(|a| a.lamports()).unwrap_or(0);
                let to_after   = db.load(&to).map(|a| a.lamports()).unwrap_or(0);
                println!("[svm]  after:  {}={} lamports  {}={} lamports",
                    from_byte, from_after, to_byte, to_after);
                Ok(())
            }
            Err(e) => {
                println!("[svm]  failed: {:?}", e);
                Err(format!("{:?}", e))
            }
        }
    };

    // --- 6. Record into PoH on success ---
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
                println!("[poh]  record hashes={:<6} hash={} txs=1",
                    entry.num_hashes, hex::encode(&entry.hash[..8]));
            }
            hash_hex
        }
        Err(_) => String::new(),
    };

    // --- 7. Respond ---
    match result {
        Ok(())  => json_response(200, &format!(r#"{{"ok":true,"entry_hash":"{}"}}"#, entry_hash)),
        Err(e)  => json_response(400, &format!(r#"{{"ok":false,"error":"{}"}}"#, e)),
    }
}

// ---------------------------------------------------------------------------
// print_entry
// ---------------------------------------------------------------------------
fn print_entry(idx: usize, entry: &crate::runtime::poh::Entry) {
    let kind = if entry.transactions.is_empty() { "TICK  " } else { "RECORD" };
    println!(
        "[entry #{:<4}] {}  hashes={:<6}  hash={}",
        idx, kind, entry.num_hashes, hex::encode(entry.hash),
    );
    for (ti, tx) in entry.transactions.iter().enumerate() {
        println!("  tx[{}]:", ti);
        println!("    account_keys ({}):", tx.message.account_keys.len());
        for (i, key) in tx.message.account_keys.iter().enumerate() {
            println!("      [{}] {:?}  writable={}  signer={}",
                i, key, tx.message.is_writable(i), tx.message.is_signer(i));
        }
        for (ii, ix) in tx.message.instructions.iter().enumerate() {
            println!("    ix[{}]: program_id_index={}  accounts={:?}  data={} bytes",
                ii, ix.program_id_index, ix.accounts, ix.data.len());
        }
    }
}

fn json_response(code: u32, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body)
        .with_status_code(code)
        .with_header("Content-Type: application/json".parse::<tiny_http::Header>().unwrap())
}
