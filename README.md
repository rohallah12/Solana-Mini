# Solana Mini — vibecoded chain in progress

A ground-up Rust implementation of core Solana internals, built step by step
to understand how the real thing works. Not production code — the goal is
clarity over completeness.

---

## Running

```bash
# Start the node (compact output)
cargo run

# Start with full entry dumps on every tick and record
cargo run -- --log-entries
```

### Send a transfer

```bash
curl --noproxy "*" -X POST http://localhost:8080/transfer \
  -H "Content-Type: application/json" \
  -d '{"from": 1, "to": 2, "lamports": 1000000000}'
```

`from` and `to` are single-byte account identifiers (1–5). Accounts 1–5 are
pre-funded with 100 SOL each at genesis.

**Response:**
```json
{ "ok": true, "entry_hash": "81c4ae8ab96f3283..." }
```

---

## File structure

```
src/
  main.rs
  types/
    account.rs       — Pubkey, Account, AccountSharedData
    transaction.rs   — Signature, Hash, MessageHeader, CompiledInstruction,
                       Message, Transaction
  runtime/
    accounts_db.rs   — AccountsDB (Pubkey → AccountSharedData state store)
    poh.rs           — PoH generator, Entry, verify()
    svm.rs           — SVM (transaction execution engine)
    rpc.rs           — HTTP server, shared node state
  programs/
    system.rs        — SystemProgram (Transfer, CreateAccount, Assign)
```

---

## Architecture

### The account model

Every piece of state on Solana — wallets, programs, token balances — is an
account. There is no separate "program store" or "balance sheet". One flat map.

```
AccountsDB
┌─────────────────────────────────────────────────────┐
│  Pubkey  →  AccountSharedData                        │
│                                                      │
│  [0x01..]  lamports: 5_000_000_000                   │
│            data:     []                              │
│            owner:    SystemProgram                   │
│            executable: false                         │
│                                                      │
│  [0x00..]  lamports: 1          ← SystemProgram      │
│            data:     []           itself is an       │
│            owner:    NativeLoader  account too       │
│            executable: true                          │
└─────────────────────────────────────────────────────┘
```

---

### Proof of History

PoH is a sequential SHA-256 hash chain that proves real time passed. It runs
continuously on a background thread, ticking at a fixed rate. Transactions are
"mixed in" to the chain when they are confirmed, giving them a verifiable
timestamp.

```
PoH chain
  │
  ├── tick()    →  Entry { num_hashes: 100, hash: h, transactions: [] }
  ├── tick()    →  Entry { num_hashes: 100, hash: h, transactions: [] }
  ├── record()  →  Entry { num_hashes: 1,   hash: h, transactions: [tx] }
  │                 hash = SHA256(prev_hash || SHA256(all_sig_bytes))
  ├── tick()    →  Entry { num_hashes: 100, hash: h, transactions: [] }
  └── ...
```

**Hash mixing (Solana spec):**
```
tx_hash  = SHA256( sig_0 || sig_1 || ... )
new_hash = SHA256( current_hash || tx_hash )
```

**hashes_per_tick:** Real Solana uses ~12,500 (calibrated to 6.25ms on
validator hardware, 64 ticks per slot, 400ms per slot). We use 100 so output
stays readable.

---

### Transaction structure

```
Transaction
├── signatures: Vec<[u8;64]>       one Ed25519 sig per required signer
└── message: Message
    ├── header: MessageHeader
    │     num_required_signatures:        u8   ← how many must sign
    │     num_readonly_signed_accounts:   u8
    │     num_readonly_unsigned_accounts: u8
    │
    ├── account_keys: Vec<Pubkey>   flat deduplicated list, sorted:
    │     [writable signers | readonly signers | writable non-signers | readonly non-signers]
    │      index 0 = fee payer (always writable signer)
    │
    ├── recent_blockhash: Hash      set to latest PoH hash on arrival
    │
    └── instructions: Vec<CompiledInstruction>
          ├── program_id_index: u8   → index into account_keys
          ├── accounts: Vec<u8>      → indexes into account_keys
          └── data: Vec<u8>          → [discriminator | serialized args]
```

---

### Full node pipeline

```
  curl POST /transfer
        │
  ┌─────▼──────────────────────────────────────────┐
  │  RPC server  (runtime/rpc.rs)                   │
  │  • parse JSON body                              │
  │  • build Transaction                            │
  │  • stamp recent_blockhash = poh.last_hash()     │
  └─────────────────┬──────────────────────────────┘
                    │
  ┌─────────────────▼──────────────────────────────┐
  │  BANK  ← not yet built                          │
  │  • verify Ed25519 signatures                    │
  │  • validate recent_blockhash                    │
  │  • collect tx fee from fee payer                │
  └─────────────────┬──────────────────────────────┘
                    │
  ┌─────────────────▼──────────────────────────────┐
  │  SVM  (runtime/svm.rs)                          │
  │  1. load account_keys → local working set       │
  │  2. for each instruction:                       │
  │       program_id == SystemProgram?              │
  │         → system::decode(data)                  │
  │         → system::process(&mut accounts)        │
  │       unknown program_id?                       │
  │         → EbpfVm (TODO)                         │
  │  3. all ok  → commit working set to AccountsDB  │
  │     any err → discard, AccountsDB untouched     │
  └─────────────────┬──────────────────────────────┘
                    │
  ┌─────────────────▼──────────────────────────────┐
  │  AccountsDB  (runtime/accounts_db.rs)           │
  │  HashMap<Pubkey, AccountSharedData>             │
  └─────────────────────────────────────────────────┘
                    │  on success
  ┌─────────────────▼──────────────────────────────┐
  │  PoH record  (runtime/poh.rs)                   │
  │  new_hash = SHA256(current || SHA256(sigs))     │
  │  Entry { num_hashes: 1, hash, transactions }    │
  └─────────────────────────────────────────────────┘
```

---

### SystemProgram dispatch

```
instruction.data bytes
        │
        ▼
  decode(data)
        │
        ├── [0,0,0,0 | lamports | space | owner]  →  CreateAccount
        ├── [2,0,0,0 | lamports]                  →  Transfer
        └── [8,0,0,0 | owner]                     →  Assign
                │
                ▼
         process(ix, &mut accounts)
                │
                ├── Transfer:      debit accounts[0], credit accounts[1]
                ├── CreateAccount: debit funder, init accounts[1]
                └── Assign:        set accounts[0].owner
```

---

### Program ownership chain

```
NativeLoader  (hardcoded root)
  └── owns ──► SystemProgram   [0x00..00]   executable: true
  └── owns ──► BPF Loader v3               executable: true

BPF Loader v3
  └── owns ──► your program                executable: true
  └── owns ──► any deployed program

SystemProgram
  └── owns ──► plain wallets               executable: false
```

The `owner` field determines **how** the SVM executes a program:
- `owner == NativeLoader` → call hardcoded Rust function
- `owner == BpfLoader`    → run bytecode through EbpfVm (rbpf)

---

## Progress

| Component | Status | Description |
|---|---|---|
| `types/account.rs` | done | Pubkey, Account, AccountSharedData |
| `types/transaction.rs` | done | Message, Transaction, CompiledInstruction |
| `runtime/accounts_db.rs` | done | HashMap state store |
| `runtime/poh.rs` | done | Hash chain, Entry with Vec\<Transaction\>, verify() |
| `programs/system.rs` | done | Transfer, CreateAccount, Assign |
| `runtime/svm.rs` | done | Load → dispatch → commit |
| `runtime/rpc.rs` | done | HTTP POST /transfer, PoH ticker thread |
| `runtime/bank.rs` | next | Signature verification, fee collection, blockhash validation |
| EbpfVm / BPF loader | later | Execute arbitrary on-chain programs |
| Blockstore | later | Append-only ledger, slot/block structure |
| Gossip / TPU | later | Networking layer |
