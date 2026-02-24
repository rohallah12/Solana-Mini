mod types;
mod runtime;
mod programs;

fn main() {
    // Pass --log-entries to print full entry details on every tick and record.
    // Usage: cargo run -- --log-entries
    let log_entries = std::env::args().any(|a| a == "--log-entries");
    runtime::rpc::start(log_entries);
}
