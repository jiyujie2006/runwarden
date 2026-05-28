use std::process::ExitCode;

const CONTRACTS: &[&str] = &[
    "provider-call.schema.json",
    "provider-outcome.schema.json",
    "provider-contract.schema.json",
    "provider-manifest.schema.json",
    "operation-result.schema.json",
    "approval-record.schema.json",
    "trace-event.schema.json",
    "assessment-manifest.schema.json",
    "session-manifest.schema.json",
    "artifact-manifest.schema.json",
    "report.schema.json",
];

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") | Some("version") => {
            println!("runwarden-kernel {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("contracts") => {
            for contract in CONTRACTS {
                println!("{contract}");
            }
            ExitCode::SUCCESS
        }
        Some("schema-dir") => {
            println!("schemas");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: runwarden-kernel <contracts|schema-dir|--version>");
            ExitCode::from(2)
        }
    }
}
