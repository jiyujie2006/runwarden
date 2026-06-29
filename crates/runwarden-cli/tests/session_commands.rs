use std::{fs, process::Command};

use tempfile::tempdir;

fn manifest_toml() -> &'static str {
    r#"
    version = "0.1"
    name = "contest-red-team"
    mode = "offline"
    provider_allowlist = [
      "runwarden.input.inspect",
      "external.api.request"
    ]

    [[roots]]
    name = "workspace"
    path = "/srv/runwarden/demo"

    [actor]
    id = "agent-1"

    [authorization]
    id = "authz-active"
    state = "active"

    [active_assessment]
    enabled = true
    "#
}

#[test]
fn session_create_persists_manifest_backed_session() {
    let dir = tempdir().expect("tempdir");
    let manifest_path = dir.path().join("assessment.toml");
    fs::write(&manifest_path, manifest_toml()).expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["session", "create", "--manifest"])
        .arg(&manifest_path)
        .args(["--session", "contest_ops", "--json"])
        .output()
        .expect("run session create");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(r#""session_id": "contest_ops""#));
    assert!(stdout.contains(r#""authz_id": "authz-active""#));
    assert!(
        dir.path()
            .join(".runwarden/sessions/contest_ops.json")
            .exists()
    );
}

#[test]
fn session_inspect_and_provider_list_read_persisted_session() {
    let dir = tempdir().expect("tempdir");
    let manifest_path = dir.path().join("assessment.toml");
    fs::write(&manifest_path, manifest_toml()).expect("write manifest");
    let create = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["session", "create", "--manifest"])
        .arg(&manifest_path)
        .args(["--session", "contest_ops", "--json"])
        .output()
        .expect("run session create");
    assert!(create.status.success());

    let inspect = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["session", "inspect", "--session", "contest_ops", "--json"])
        .output()
        .expect("run session inspect");
    assert!(inspect.status.success());
    let inspect_stdout = String::from_utf8(inspect.stdout).expect("utf8 stdout");
    assert!(inspect_stdout.contains(r#""actor_id": "agent-1""#));

    let provider_list = Command::new(env!("CARGO_BIN_EXE_runwarden"))
        .current_dir(dir.path())
        .args(["provider", "list", "--session", "contest_ops", "--json"])
        .output()
        .expect("run provider list");
    assert!(provider_list.status.success());
    let list_stdout = String::from_utf8(provider_list.stdout).expect("utf8 stdout");
    assert!(list_stdout.contains("runwarden.input.inspect"));
    assert!(list_stdout.contains("external.api.request"));
}
