use std::process::Command;

#[test]
fn kernel_named_binary_reports_contract_surface() {
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden-kernel"))
        .arg("contracts")
        .output()
        .expect("run kernel binary");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("provider-call.schema.json"));
    assert!(stdout.contains("provider-outcome.schema.json"));
    assert!(stdout.contains("approval-record.schema.json"));
}
