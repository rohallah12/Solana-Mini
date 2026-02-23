# Solana Mini — vibecoded chain in progress

A ground-up Rust implementation of core Solana internals, built step by step
to understand how the real thing works. Not production code — the goal is
clarity over completeness.

---

## What's been built so far

```
src/
  account.rs        — Pubkey, Account, AccountSharedData
  accounts_db.rs    — AccountsDB (the state store)
  system_program.rs — SystemProgram (Transfer, CreateAccount, Assign)
  svm.rs            — SVM (transaction execution engine)
  transaction.rs    — Signature, Hash, MessageHeader, CompiledInstruction,
                      Message, Transaction
  main.rs           — PoH engine + end-to-end transfer demo
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
    ├── recent_blockhash: Hash      replay protection, expires ~90s
    │
    └── instructions: Vec<CompiledInstruction>
          ├── program_id_index: u8   → index into account_keys
          ├── accounts: Vec<u8>      → indexes into account_keys
          └── data: Vec<u8>          → [discriminator | serialized args]
```

---

### The execution pipeline

```
                         ┌─────────────────────────────────┐
                         │             BANK                 │  ← next session
                         │  • validate blockhash            │
                         │  • verify Ed25519 signatures     │
                         │  • check fee payer balance       │
                         │  • collect tx fee                │
                         └────────────────┬────────────────┘
                                          │
                         ┌────────────────▼────────────────┐
                         │              SVM                 │
                         │                                  │
                         │  1. load account_keys → working  │
                         │     set from AccountsDB          │
                         │                                  │
                         │  2. for each instruction:        │
                         │     ┌──────────────────────┐     │
                         │     │  program_id dispatch  │     │
                         │     │                      │     │
                         │     │  known native ID?    │     │
                         │     │  └─► SystemProgram   │     │
                         │     │                      │     │
                         │     │  unknown ID?         │     │
                         │     │  └─► EbpfVm (TODO)   │     │
                         │     └──────────────────────┘     │
                         │                                  │
                         │  3. all ok → commit to DB        │
                         │     any fail → discard all       │
                         └────────────────┬────────────────┘
                                          │
                         ┌────────────────▼────────────────┐
                         │           AccountsDB             │
                         │    HashMap<Pubkey, Account>      │
                         └─────────────────────────────────┘
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

## What's next

| Component | Status | Description |
|---|---|---|
| `account.rs` | done | Pubkey, Account, AccountSharedData |
| `transaction.rs` | done | Message, Transaction, CompiledInstruction |
| `accounts_db.rs` | done | HashMap state store |
| `system_program.rs` | done | Transfer, CreateAccount, Assign |
| `svm.rs` | done | Load → dispatch → commit |
| `bank.rs` | next | Signature verification, fee collection, blockhash validation |
| `EbpfVm` / BPF loader | later | Execute arbitrary on-chain programs |
| `Blockstore` | later | Append-only ledger, slot/block structure |
| `Gossip / TPU` | later | Networking layer |
