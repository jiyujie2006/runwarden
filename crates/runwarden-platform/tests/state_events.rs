use std::fs;

use runwarden_platform::{PlatformEvent, RunwardenPlatform};
use serde_json::json;

#[test]
fn platform_state_creates_layout_and_appends_jsonl_events() {
    let workspace = tempfile::tempdir().expect("temp workspace");
    let platform = RunwardenPlatform::open(workspace.path()).expect("open platform");

    platform.state().ensure_layout().expect("ensure layout");
    assert!(workspace.path().join(".runwarden").is_dir());

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
