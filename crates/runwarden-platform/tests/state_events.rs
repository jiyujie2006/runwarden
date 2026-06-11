use std::fs;
use std::sync::{Mutex, OnceLock};

use runwarden_platform::{PlatformEvent, RunwardenPlatform};
use serde_json::json;

#[test]
fn platform_state_creates_layout_and_appends_jsonl_events() {
    let workspace = tempfile::tempdir().expect("temp workspace");
    let platform = RunwardenPlatform::open(workspace.path()).expect("open platform");

    platform.state().ensure_layout().expect("ensure layout");
    assert!(workspace.path().join(".runwarden").is_dir());
    for dir in [
        platform.state().sessions_dir(),
        platform.state().approvals_dir(),
        platform.state().provider_calls_dir(),
        platform.state().provider_catalog_dir(),
        platform.state().traces_dir(),
        platform.state().artifacts_dir(),
    ] {
        assert!(dir.is_dir(), "layout directory exists: {}", dir.display());
    }

    platform
        .state()
        .append_event(&PlatformEvent::new(
            "platform.state.opened",
            json!({"workspace": "temp"}),
        ))
        .expect("append first event");
    platform
        .state()
        .append_event(&PlatformEvent::new(
            "platform.state.layout_ready",
            json!({"created": true}),
        ))
        .expect("append second event");

    let events_path = workspace.path().join(".runwarden/events.jsonl");
    let events = fs::read_to_string(events_path).expect("read events");
    let lines = events.lines().collect::<Vec<_>>();

    assert_eq!(lines.len(), 2);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(lines[0]).expect("first json")["event_type"],
        "platform.state.opened"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(lines[1]).expect("second json")["event_type"],
        "platform.state.layout_ready"
    );
    assert!(events.ends_with('\n'));
}

#[test]
fn platform_open_absolutizes_relative_workspace_root() {
    let _cwd_guard = cwd_lock().lock().expect("cwd lock");
    let _restore_cwd = CwdRestore::capture();
    let parent = tempfile::tempdir().expect("parent temp workspace");
    let workspace = parent.path().join("workspace");
    let drift_parent = tempfile::tempdir().expect("drift parent");
    let drift_workspace = drift_parent.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    fs::create_dir(&drift_workspace).expect("drift workspace");

    std::env::set_current_dir(parent.path()).expect("set parent cwd");
    let platform = RunwardenPlatform::open("workspace").expect("open relative platform");
    std::env::set_current_dir(drift_parent.path()).expect("set drift cwd");

    platform.state().ensure_layout().expect("ensure layout");
    platform
        .state()
        .append_event(&PlatformEvent::new("platform.cwd_drift", json!({})))
        .expect("append event after cwd drift");

    assert!(workspace.join(".runwarden/events.jsonl").is_file());
    assert!(!drift_workspace.join(".runwarden/events.jsonl").exists());
}

#[test]
fn platform_rejects_artifact_output_paths_outside_workspace() {
    let workspace = tempfile::tempdir().expect("temp workspace");
    let outside = tempfile::tempdir().expect("outside dir");
    let platform = RunwardenPlatform::open(workspace.path()).expect("open platform");

    assert!(platform.validate_artifact_output_path("artifacts").is_ok());
    assert!(
        platform
            .validate_artifact_output_path(outside.path().join("artifacts"))
            .is_err(),
        "absolute artifact output paths must be rejected"
    );
    assert!(
        platform
            .validate_artifact_output_path("../artifact-traversal")
            .is_err(),
        "parent traversal must be rejected"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let link_path = workspace.path().join("artifact-link");
        symlink(outside.path(), &link_path).expect("symlink");

        assert!(
            platform
                .validate_artifact_output_path("artifact-link/reports")
                .is_err(),
            "artifact output paths must reject symlink escapes"
        );
    }
}

#[cfg(unix)]
#[test]
fn platform_rejects_symlinked_state_directory_before_layout_write() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().expect("temp workspace");
    let outside = tempfile::tempdir().expect("outside dir");
    symlink(outside.path(), workspace.path().join(".runwarden")).expect("symlink state dir");
    let platform = RunwardenPlatform::open(workspace.path()).expect("open platform");

    assert!(
        platform.state().ensure_layout().is_err(),
        "symlinked state directory must be rejected"
    );
    assert!(!outside.path().join("sessions").exists());
}

#[cfg(unix)]
#[test]
fn platform_rejects_symlinked_events_file_before_append_write() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().expect("temp workspace");
    let outside = tempfile::tempdir().expect("outside dir");
    let outside_events = outside.path().join("events.jsonl");
    fs::create_dir(workspace.path().join(".runwarden")).expect("state dir");
    symlink(
        &outside_events,
        workspace.path().join(".runwarden/events.jsonl"),
    )
    .expect("symlink events file");
    let platform = RunwardenPlatform::open(workspace.path()).expect("open platform");

    assert!(
        platform
            .state()
            .append_event(&PlatformEvent::new("platform.symlink", json!({})))
            .is_err(),
        "symlinked event log must be rejected"
    );
    assert!(!outside_events.exists());
}

fn cwd_lock() -> &'static Mutex<()> {
    static CWD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    CWD_LOCK.get_or_init(|| Mutex::new(()))
}

struct CwdRestore {
    original: std::path::PathBuf,
}

impl CwdRestore {
    fn capture() -> Self {
        Self {
            original: std::env::current_dir().expect("current dir"),
        }
    }
}

impl Drop for CwdRestore {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.original).expect("restore cwd");
    }
}
