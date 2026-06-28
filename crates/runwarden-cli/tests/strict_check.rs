use std::process::Command;

#[test]
fn strict_check_validates_contest_repo_contracts() {
    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .args(["check", "--strict"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run strict check");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("contest scenario corpus present"));
    assert!(stdout.contains("lean MCP/CLI reference docs present"));
    assert!(stdout.contains("static WebUI package present"));
    assert!(stdout.contains("contest gate scripts present"));
}
