use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use runwarden_api::{
    LocalApiRequest, LocalApiRouter, LocalApiSecurity, LocalApiServerConfig, serve_next_request,
    serve_one_request,
};
use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord};
use runwarden_kernel::evidence::TraceEvent;
use runwarden_kernel::evidence::hex_sha256;
use serde_json::{Value, json};

fn router() -> LocalApiRouter {
    LocalApiRouter::new(LocalApiSecurity::new(
        "launch-secret",
        ["127.0.0.1:0"],
        ["http://127.0.0.1:0"],
    ))
}

fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn authed(method: &str, path: &str) -> LocalApiRequest {
    LocalApiRequest::new(method, path)
        .header("Host", "127.0.0.1:0")
        .header("Origin", "http://127.0.0.1:0")
        .bearer_token("launch-secret")
}

fn manifest_body(session_id: &str, provider_allowlist: &[&str]) -> Value {
    let allowlist = provider_allowlist
        .iter()
        .map(|provider| format!("\"{provider}\""))
        .collect::<Vec<_>>()
        .join(", ");
    json!({
        "session_id": session_id,
        "manifest_toml": format!(
            r#"
version = "1"
name = "local api replay test"
mode = "audit"
provider_allowlist = [{allowlist}]

[active_assessment]
enabled = true
"#
        )
    })
}

fn manifest_body_with_root(
    session_id: &str,
    provider_allowlist: &[&str],
    root_path: &str,
) -> Value {
    let mut body = manifest_body(session_id, provider_allowlist);
    let allowlist = provider_allowlist
        .iter()
        .map(|provider| format!("\"{provider}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let root_path = toml_basic_string(root_path);
    body["manifest_toml"] = json!(format!(
        r#"
version = "1"
name = "local api root resolution test"
mode = "audit"
provider_allowlist = [{allowlist}]

[[roots]]
name = "evidence"
path = {root_path}

[active_assessment]
enabled = true
"#
    ));
    body
}

fn toml_basic_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04X}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

fn trace_event() -> TraceEvent {
    TraceEvent::sealed(
        "obs_1".to_string(),
        "provider_completed".to_string(),
        Some("runwarden.evidence.inspect".to_string()),
        json!({"ok": true}),
        None,
    )
}

fn approved_call_binding(
    session_id: &str,
    provider: &str,
    action: &str,
    arguments: &Value,
) -> ApprovalBinding {
    ApprovalBinding {
        session_id: session_id.to_string(),
        provider: provider.to_string(),
        action: action.to_string(),
        argument_hash: hex_sha256(&serde_json::to_vec(arguments).expect("arguments serialize")),
        authz_id: None,
        actor_id: None,
    }
}

fn approved_record(
    approval_id: &str,
    session_id: &str,
    provider: &str,
    action: &str,
    arguments: &Value,
) -> ApprovalRecord {
    let mut approval = ApprovalRecord::new(
        approval_id,
        approved_call_binding(session_id, provider, action, arguments),
    );
    approval
        .approve("reviewer-alice", "reviewed exact provider call")
        .expect("approval can be approved");
    approval
}

fn pending_record(approval_id: &str) -> ApprovalRecord {
    ApprovalRecord::new(
        approval_id,
        ApprovalBinding {
            session_id: "session-1".to_string(),
            provider: "runwarden.report.render".to_string(),
            action: "render".to_string(),
            argument_hash: "arg_hash_1".to_string(),
            authz_id: Some("authz-1".to_string()),
            actor_id: Some("agent-1".to_string()),
        },
    )
}

#[test]
fn local_api_router_serves_sdk_provider_list_endpoint_without_security_decisions() {
    let request = authed("GET", "/providers");

    let mut router = router();
    let response = router.handle(request, None);

    assert_eq!(response.status, 200);
    assert_eq!(response.body["operation"]["ok"], true);
    assert_eq!(
        response.body["operation"]["data"]["providers"][0],
        "runwarden.input.inspect"
    );
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn local_api_router_covers_webui_and_sdk_endpoint_surface() {
    let mut router = router();
    for (method, path) in [
        ("GET", "/dashboard"),
        ("GET", "/agent-boundary"),
        ("GET", "/providers"),
        ("GET", "/providers/runwarden.report.render/status"),
        ("POST", "/provider-calls"),
        ("POST", "/sessions"),
        ("POST", "/trace/export"),
        ("GET", "/audit/summary"),
        ("GET", "/accountability/summary"),
        ("POST", "/reports/lint"),
        ("POST", "/reports/render"),
        ("POST", "/reports/preview"),
        ("POST", "/artifacts/verify"),
        ("POST", "/artifacts/token"),
        ("GET", "/artifacts/download"),
        ("POST", "/artifacts/submission"),
        ("POST", "/eval/agent-native"),
        ("POST", "/release/smoke"),
        ("POST", "/ui/launch"),
        ("POST", "/agent/config/check"),
    ] {
        let request = authed(method, path);

        let response = router.handle(request, Some(serde_json::json!({})));

        assert_ne!(response.status, 404, "{method} {path} should be routed");
        assert!(
            response.body["side_effect_executed"].as_bool().is_some(),
            "{method} {path} should declare side effect state"
        );
    }
}

#[test]
fn local_api_ui_launch_writes_full_reviewer_console_contract() {
    let artifacts = format!("target/local-api-ui-{}", uuid::Uuid::now_v7().simple());
    let artifact_path = workspace_root().join(&artifacts);
    let _ = fs::remove_dir_all(&artifact_path);
    let mut router = router();

    let response = router.handle(
        authed("POST", "/ui/launch"),
        Some(json!({
            "bind": "127.0.0.1",
            "port": 8092,
            "artifacts_path": artifacts
        })),
    );

    assert_eq!(response.status, 200);
    let html =
        fs::read_to_string(artifact_path.join("reviewer-console.html")).expect("read ui bundle");
    let script =
        fs::read_to_string(artifact_path.join("reviewer-console.js")).expect("read ui script");
    assert!(
        response.body["operation"]["data"]["script_path"]
            .as_str()
            .expect("script path")
            .ends_with("reviewer-console.js")
    );
    let launch_url = response.body["operation"]["data"]["launch_url"]
        .as_str()
        .expect("launch url");
    assert!(launch_url.starts_with("file:///"), "{launch_url}");
    assert!(
        launch_url.ends_with("/reviewer-console.html"),
        "{launch_url}"
    );
    #[cfg(windows)]
    {
        assert!(!launch_url.contains("%5C"), "{launch_url}");
        assert!(!launch_url.contains("%3A"), "{launch_url}");
        assert!(!launch_url.contains("\\\\"), "{launch_url}");
    }
    assert!(html.contains("data-local-api-url=\"http://127.0.0.1:8092\""));
    assert!(html.contains("aria-label=\"Runwarden sections\""));
    assert!(html.contains("class=\"nav-brand\""));
    assert!(html.contains("class=\"command-bar\""));
    assert!(html.contains("Trusted side effects"));
    assert!(html.contains("role=\"status\""));
    assert!(html.contains("Agent Boundary"));
    assert!(html.contains("Provider Registry"));
    assert!(html.contains("Approval Queue"));
    assert!(html.contains("Trace Explorer"));
    assert!(html.contains("Accountability"));
    assert!(html.contains("Reports"));
    assert!(html.contains("Artifacts"));
    assert!(html.contains("Assurance"));
    assert!(html.contains("href=\"#assurance\""));
    assert!(html.contains("Settings"));
    assert!(html.contains("class=\"state-badge\""));
    assert!(html.contains("class=\"module-head\""));
    assert!(html.contains("0 pending"));
    assert_eq!(html.matches("No actions waiting for review").count(), 1);
    assert!(html.contains("repeating-linear-gradient"));
    assert!(!html.contains("radial-gradient"));
    assert!(!html.contains("4vw"));
    assert!(html.contains("@media (max-width: 768px)"));
    assert!(html.contains("position: sticky"));
    assert!(html.contains("<script src=\"reviewer-console.js\" defer></script>"));
    assert!(!html.contains("data-action=\"approve\""));
    assert!(!html.contains("data-action=\"deny\""));
    assert!(!html.contains("<script>"));
    assert!(script.contains("fetch(`${apiRoot}/approvals/"));
    assert!(script.contains("selectApproval(row)"));
    let _ = fs::remove_dir_all(&artifact_path);
}

#[test]
fn local_api_ui_launch_renders_pending_approval_controls() {
    let artifacts = format!(
        "target/local-api-ui-approval-{}",
        uuid::Uuid::now_v7().simple()
    );
    let artifact_path = workspace_root().join(&artifacts);
    let _ = fs::remove_dir_all(&artifact_path);
    let mut security =
        LocalApiSecurity::new("launch-secret", ["127.0.0.1:0"], ["http://127.0.0.1:0"]);
    security.insert_approval(pending_record("approval-ui-1"));
    let mut router = LocalApiRouter::new(security);

    let response = router.handle(
        authed("POST", "/ui/launch"),
        Some(json!({
            "bind": "127.0.0.1",
            "port": 8092,
            "artifacts_path": artifacts
        })),
    );

    assert_eq!(response.status, 200);
    let html =
        fs::read_to_string(artifact_path.join("reviewer-console.html")).expect("read ui bundle");
    assert!(html.contains("approval-ui-1"));
    assert!(html.contains("runwarden.report.render"));
    assert!(html.contains("arg_hash_1"));
    assert!(html.contains("class=\"risk-chip\""));
    assert!(html.contains("1 pending"));
    assert!(html.contains("is-selected"));
    assert!(html.contains("role=\"list\""));
    assert!(html.contains("role=\"listitem\""));
    assert!(html.contains("aria-current=\"true\""));
    assert!(html.contains("aria-controls=\"approval-details\""));
    assert!(html.contains("data-provider=\"runwarden.report.render\""));
    assert!(html.contains("data-detail-fields"));
    assert!(html.contains("class=\"approval-decision-form\""));
    assert!(html.contains("id=\"local-api-token\""));
    assert!(html.contains("data-action=\"approve\""));
    assert!(html.contains("data-action=\"deny\""));
    assert!(html.contains("<textarea"));
    assert!(!html.contains("No actions waiting for review"));
    let _ = fs::remove_dir_all(&artifact_path);
}

#[test]
fn local_api_ui_launch_escapes_bind_before_writing_html() {
    let artifacts = format!("target/local-api-ui-xss-{}", uuid::Uuid::now_v7().simple());
    let artifact_path = workspace_root().join(&artifacts);
    let _ = fs::remove_dir_all(&artifact_path);
    let mut router = router();

    let response = router.handle(
        authed("POST", "/ui/launch"),
        Some(json!({
            "bind": "<img src=x onerror=alert(1)>",
            "port": 8092,
            "artifacts_path": artifacts
        })),
    );

    assert_eq!(response.status, 200);
    let html =
        fs::read_to_string(artifact_path.join("reviewer-console.html")).expect("read ui bundle");
    assert!(!html.contains("<img src=x onerror=alert(1)>"));
    assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
    let _ = fs::remove_dir_all(&artifact_path);
}

#[test]
fn local_api_ui_launch_rejects_absolute_artifacts_path_before_writing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifacts = dir.path().join("outside-artifacts");
    let mut router = router();

    let response = router.handle(
        authed("POST", "/ui/launch"),
        Some(json!({
            "bind": "127.0.0.1",
            "port": 8092,
            "artifacts_path": artifacts.to_string_lossy()
        })),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.body["side_effect_executed"], false);
    assert!(!artifacts.join("reviewer-console.html").exists());
}

#[cfg(unix)]
#[test]
fn local_api_ui_launch_rejects_symlink_artifacts_path_before_writing() {
    use std::os::unix::fs::symlink;

    let outside = tempfile::tempdir().expect("tempdir");
    let artifacts = format!("target/local-api-ui-link-{}", uuid::Uuid::now_v7().simple());
    let link_path = workspace_root().join(&artifacts);
    let _ = fs::remove_file(&link_path);
    let _ = fs::remove_dir_all(&link_path);
    symlink(outside.path(), &link_path).expect("symlink");
    let mut router = router();

    let response = router.handle(
        authed("POST", "/ui/launch"),
        Some(json!({
            "bind": "127.0.0.1",
            "port": 8092,
            "artifacts_path": artifacts
        })),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.body["side_effect_executed"], false);
    assert!(!outside.path().join("reviewer-console.html").exists());
    let _ = fs::remove_file(&link_path);
}

#[test]
fn local_api_artifact_submission_rejects_parent_output_path_before_writing() {
    let mut router = router();

    let response = router.handle(
        authed("POST", "/artifacts/submission"),
        Some(json!({
            "output_path": "../runwarden-outside-artifacts",
            "full": false
        })),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn local_api_ui_launch_rejects_unauthenticated_before_writing_bundle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let artifacts = dir.path().join("artifacts");
    let mut router = router();
    let request = LocalApiRequest::new("POST", "/ui/launch")
        .header("Host", "127.0.0.1:0")
        .header("Origin", "http://127.0.0.1:0");

    let response = router.handle(
        request,
        Some(json!({
            "bind": "127.0.0.1",
            "port": 8092,
            "artifacts_path": artifacts.to_string_lossy()
        })),
    );

    assert_eq!(response.status, 401);
    assert_eq!(response.body["side_effect_executed"], false);
    assert!(!artifacts.join("reviewer-console.html").exists());
}

#[test]
fn local_api_artifact_submission_rejects_unauthenticated_before_writing_bundle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let output = dir.path().join("submission");
    let mut router = router();
    let request = LocalApiRequest::new("POST", "/artifacts/submission")
        .header("Host", "127.0.0.1:0")
        .header("Origin", "http://127.0.0.1:0");

    let response = router.handle(
        request,
        Some(json!({
            "output_path": output.to_string_lossy(),
            "full": true
        })),
    );

    assert_eq!(response.status, 401);
    assert_eq!(response.body["side_effect_executed"], false);
    assert!(!output.exists());
}

#[test]
fn local_api_trace_export_rejects_unauthenticated_before_reading_trace_path() {
    let mut router = router();
    let request = LocalApiRequest::new("POST", "/trace/export")
        .header("Host", "127.0.0.1:0")
        .header("Origin", "http://127.0.0.1:0");

    let response = router.handle(
        request,
        Some(json!({
            "trace_path": "/definitely/not/a/trace.json"
        })),
    );

    assert_eq!(response.status, 401);
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn local_api_preflight_allows_browser_json_sdk_calls_without_bearer_token() {
    let mut router = router();
    let response = router.handle(
        LocalApiRequest::new("OPTIONS", "/sessions")
            .header("Host", "127.0.0.1:0")
            .header("Origin", "http://127.0.0.1:0")
            .header("Access-Control-Request-Method", "POST")
            .header(
                "Access-Control-Request-Headers",
                "authorization, content-type",
            ),
        None,
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.body["preflight"], true);
    assert_eq!(
        response.headers.get("access-control-allow-origin"),
        Some(&"http://127.0.0.1:0".to_string())
    );
    assert!(
        response
            .headers
            .get("access-control-allow-headers")
            .expect("allow headers")
            .contains("authorization")
    );
}

#[test]
fn local_api_router_rejects_endpoint_without_launch_token_before_side_effects() {
    let mut router = router();
    let request = LocalApiRequest::new("POST", "/provider-calls")
        .header("Host", "127.0.0.1:0")
        .header("Origin", "http://127.0.0.1:0");

    let response = router.handle(request, Some(serde_json::json!({})));

    assert_eq!(response.status, 401);
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn local_api_report_lint_returns_real_citation_failure_instead_of_placeholder_ok() {
    let mut router = router();
    let trace = vec![TraceEvent::sealed(
        "obs_1".to_string(),
        "provider_completed".to_string(),
        Some("runwarden.evidence.inspect".to_string()),
        serde_json::json!({"ok": true}),
        None,
    )];
    let body = serde_json::json!({
        "report": {
            "claims": [
                {
                    "id": "finding-1",
                    "text": "Shell command was denied",
                    "obs_refs": []
                }
            ]
        },
        "trace": trace
    });

    let response = router.handle(authed("POST", "/reports/lint"), Some(body));

    assert_eq!(response.status, 422);
    assert_eq!(response.body["operation"]["ok"], false);
    assert_eq!(
        response.body["operation"]["error"]["kind"],
        "report_citation_invalid"
    );
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn local_api_artifact_token_route_issues_single_use_token_for_specific_artifact() {
    let mut router = router();

    let response = router.handle(
        authed("POST", "/artifacts/token"),
        Some(serde_json::json!({ "artifact_id": "artifact-1" })),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.body["operation"]["ok"], true);
    assert_eq!(
        response.body["operation"]["data"]["artifact_id"],
        "artifact-1"
    );
    assert_eq!(response.body["operation"]["data"]["issued"], true);
    assert!(
        response.body["operation"]["data"]["token"]
            .as_str()
            .expect("token")
            .len()
            >= 48
    );
}

#[test]
fn local_api_artifact_download_route_consumes_issued_token_once() {
    let mut router = router();
    let issued = router.handle(
        authed("POST", "/artifacts/token"),
        Some(serde_json::json!({ "artifact_id": "artifact-1" })),
    );
    let token = issued.body["operation"]["data"]["token"]
        .as_str()
        .expect("token");

    let first = router.handle(
        authed("GET", &format!("/artifacts/download?token={token}")),
        None,
    );
    let replay = router.handle(
        authed("GET", &format!("/artifacts/download?token={token}")),
        None,
    );

    assert_eq!(first.status, 200);
    assert_eq!(first.body["artifact_id"], "artifact-1");
    assert_eq!(first.body["token_consumed"], true);
    assert_eq!(replay.status, 403);
    assert_eq!(replay.body["side_effect_executed"], false);
}

#[test]
fn local_api_trace_export_rejects_tampered_hash_chain_before_export() {
    let mut events = vec![trace_event()];
    events[0].payload = json!({"ok": false, "tampered": true});
    let mut router = router();

    let response = router.handle(
        authed("POST", "/trace/export"),
        Some(json!({ "trace": events })),
    );

    assert_eq!(response.status, 422);
    assert_eq!(
        response.body["operation"]["error"]["kind"],
        "trace_tampered"
    );
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn local_api_report_render_rejects_uncited_claim_before_artifact_write() {
    let mut router = router();
    let response = router.handle(
        authed("POST", "/reports/preview"),
        Some(json!({
            "report": {
                "claims": [
                    {"id": "finding-1", "text": "uncited finding", "obs_refs": []}
                ]
            },
            "trace": [trace_event()],
            "format": "html"
        })),
    );

    assert_eq!(response.status, 422);
    assert_eq!(
        response.body["operation"]["error"]["kind"],
        "report_citation_invalid"
    );
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn local_api_report_render_enqueues_pending_approval_before_rendering() {
    let session_id = "report_render_session";
    let provider = "runwarden.report.render";
    let mut router = router();
    let create_session = router.handle(
        authed("POST", "/sessions"),
        Some(manifest_body(session_id, &[provider])),
    );
    assert_eq!(create_session.status, 200);

    let body = json!({
            "session_id": session_id,
            "report": {
                "claims": [
                    {"id": "finding-1", "text": "Evidence inspection completed", "obs_refs": ["obs_1"]}
                ]
            },
            "trace": [trace_event()],
            "format": "markdown"
    });

    let response = router.handle(authed("POST", "/reports/render"), Some(body.clone()));
    let approval_id = response.body["operation"]["data"]["outcome"]["envelope"]["approval_id"]
        .as_str()
        .expect("approval id")
        .to_string();
    let queue = router.handle(authed("GET", "/approvals"), None);

    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["operation"]["data"]["outcome"]["decision"],
        "requires_review"
    );
    assert_eq!(
        response.body["operation"]["data"]["outcome"]["execution_status"],
        "not_executed"
    );
    assert!(response.body["operation"]["data"]["rendered"].is_null());
    assert_eq!(response.body["side_effect_executed"], false);
    assert_eq!(queue.body["approvals"][0]["approval_id"], approval_id);
    assert_eq!(queue.body["approvals"][0]["state"], "pending");

    let approve = router.handle(
        authed("POST", &format!("/approvals/{approval_id}/approve")),
        Some(json!({
            "reviewer": "reviewer-alice",
            "reason": "cited report render reviewed"
        })),
    );
    let mut approved_body = body.clone();
    approved_body["approval_id"] = json!(approval_id);
    let rendered = router.handle(authed("POST", "/reports/render"), Some(approved_body));
    let queue_after_render = router.handle(authed("GET", "/approvals"), None);
    let repeated = router.handle(authed("POST", "/reports/render"), Some(body));
    let queue_after_repeated = router.handle(authed("GET", "/approvals"), None);

    assert_eq!(approve.status, 200);
    assert_eq!(rendered.status, 200);
    assert_eq!(rendered.body["operation"]["ok"], true);
    assert_eq!(rendered.body["operation"]["data"]["preview"], false);
    assert_eq!(rendered.body["side_effect_executed"], false);
    assert_eq!(
        queue_after_render.body["approvals"]
            .as_array()
            .expect("approval array")
            .len(),
        0
    );
    assert_eq!(
        repeated.body["operation"]["data"]["outcome"]["decision"],
        "requires_review"
    );
    assert_eq!(
        queue_after_repeated.body["approvals"][0]["approval_id"],
        approval_id
    );
    assert_eq!(
        queue_after_repeated.body["approvals"][0]["state"],
        "pending"
    );
}

#[test]
fn local_api_artifact_verify_returns_denial_for_manifest_mismatch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut router = router();
    let response = router.handle(
        authed("POST", "/artifacts/verify"),
        Some(json!({
            "artifacts_path": dir.path().to_string_lossy(),
            "manifest": {
                "schema_version": "0.1",
                "artifacts": [
                    {
                        "artifact_id": "missing",
                        "relative_path": "missing.txt",
                        "sha256": "not-a-real-digest",
                        "redaction_sidecar_path": "missing.txt.redaction.json",
                        "redaction_sidecar_sha256": "not-a-real-digest",
                        "obs_refs": []
                    }
                ]
            }
        })),
    );

    assert_eq!(response.status, 422);
    assert_eq!(
        response.body["operation"]["error"]["kind"],
        "artifact_invalid"
    );
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn local_api_provider_call_persists_approval_consumption_and_rejects_replay() {
    let session_id = "report_session";
    let provider = "runwarden.report.render";
    let action = "render";
    let arguments = json!({
        "report": {
            "claims": [
                {"id": "finding-1", "text": "Evidence inspection completed", "obs_refs": ["obs_1"]}
            ]
        },
        "trace": [trace_event()],
        "format": "markdown"
    });
    let mut security =
        LocalApiSecurity::new("launch-secret", ["127.0.0.1:0"], ["http://127.0.0.1:0"]);
    security.insert_approval(approved_record(
        "approval-1",
        session_id,
        provider,
        action,
        &arguments,
    ));
    let mut router = LocalApiRouter::new(security);
    let create_session = router.handle(
        authed("POST", "/sessions"),
        Some(manifest_body(session_id, &[provider])),
    );
    assert_eq!(create_session.status, 200);
    let body = json!({
        "session_id": session_id,
        "provider": provider,
        "action": action,
        "arguments": arguments,
        "approval_id": "approval-1"
    });

    let first = router.handle(authed("POST", "/provider-calls"), Some(body.clone()));
    let replay = router.handle(authed("POST", "/provider-calls"), Some(body));

    assert_eq!(
        first.body["operation"]["data"]["outcome"]["decision"],
        "allowed"
    );
    assert_eq!(
        replay.body["operation"]["data"]["outcome"]["decision"],
        "denied"
    );
    assert_eq!(
        replay.body["operation"]["data"]["outcome"]["envelope"]["error_kind"],
        "approval_consumed"
    );
}

#[test]
fn local_api_provider_call_enqueues_pending_approval_when_review_required() {
    let session_id = "review_session";
    let provider = "runwarden.report.render";
    let action = "render";
    let arguments = json!({
        "report": {
            "claims": [
                {"id": "finding-1", "text": "Evidence inspection completed", "obs_refs": ["obs_1"]}
            ]
        },
        "trace": [trace_event()],
        "format": "markdown"
    });
    let mut router = router();
    let create_session = router.handle(
        authed("POST", "/sessions"),
        Some(manifest_body(session_id, &[provider])),
    );
    assert_eq!(create_session.status, 200);

    let response = router.handle(
        authed("POST", "/provider-calls"),
        Some(json!({
            "session_id": session_id,
            "provider": provider,
            "action": action,
            "arguments": arguments
        })),
    );
    let approval_id = response.body["operation"]["data"]["outcome"]["envelope"]["approval_id"]
        .as_str()
        .expect("approval id")
        .to_string();
    let queue = router.handle(authed("GET", "/approvals"), None);

    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["operation"]["data"]["outcome"]["decision"],
        "requires_review"
    );
    assert_eq!(response.body["side_effect_executed"], false);
    assert_eq!(queue.body["approvals"][0]["approval_id"], approval_id);
    assert_eq!(queue.body["approvals"][0]["state"], "pending");
}

#[test]
fn local_api_external_provider_without_adapter_is_incomplete_not_completed() {
    let session_id = "external_session";
    let provider = "external.shell.command";
    let action = "execute";
    let arguments = json!({
        "executable": "git",
        "args": ["status", "--short"]
    });
    let mut security =
        LocalApiSecurity::new("launch-secret", ["127.0.0.1:0"], ["http://127.0.0.1:0"]);
    security.insert_approval(approved_record(
        "approval-1",
        session_id,
        provider,
        action,
        &arguments,
    ));
    let mut router = LocalApiRouter::new(security);
    let create_session = router.handle(
        authed("POST", "/sessions"),
        Some(manifest_body(session_id, &[provider])),
    );
    assert_eq!(create_session.status, 200);

    let response = router.handle(
        authed("POST", "/provider-calls"),
        Some(json!({
            "session_id": session_id,
            "provider": provider,
            "action": action,
            "arguments": arguments,
            "approval_id": "approval-1"
        })),
    );

    assert_eq!(
        response.body["operation"]["data"]["outcome"]["execution_status"],
        "incomplete"
    );
    assert_eq!(
        response.body["operation"]["data"]["outcome"]["output"]["external_adapter_required"],
        true
    );
    assert_eq!(response.body["side_effect_executed"], false);
}

#[test]
fn local_api_provider_call_resolves_scoped_root_names_before_execution() {
    let dir = tempfile::tempdir().expect("tempdir");
    let evidence_root = dir.path().join("evidence");
    fs::create_dir(&evidence_root).expect("evidence root");
    fs::write(evidence_root.join("finding.txt"), "evidence").expect("write evidence");
    let session_id = "evidence_session";
    let provider = "runwarden.evidence.inspect";
    let mut router = router();
    let create_session = router.handle(
        authed("POST", "/sessions"),
        Some(manifest_body_with_root(
            session_id,
            &[provider],
            &evidence_root.to_string_lossy(),
        )),
    );
    assert_eq!(create_session.status, 200);

    let response = router.handle(
        authed("POST", "/provider-calls"),
        Some(json!({
            "session_id": session_id,
            "provider": provider,
            "action": "inspect",
            "arguments": {
                "root": "evidence"
            }
        })),
    );

    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["operation"]["data"]["outcome"]["decision"],
        "allowed"
    );
    assert_eq!(
        response.body["operation"]["data"]["outcome"]["output"]["files"][0]["relative_path"],
        "finding.txt"
    );
    assert_eq!(
        response.body["operation"]["data"]["outcome"]["envelope"]["side_effect_executed"],
        true
    );
    assert_eq!(response.body["side_effect_executed"], true);
}

#[test]
fn local_api_provider_call_resolves_relative_paths_against_scoped_root_before_reading() {
    let dir = tempfile::tempdir().expect("tempdir");
    let evidence_root = dir.path().join("evidence");
    fs::create_dir(&evidence_root).expect("evidence root");
    fs::write(evidence_root.join("Cargo.toml"), "safe scoped content").expect("write evidence");
    let session_id = "relative_path_session";
    let provider = "runwarden.input.inspect";
    let mut router = router();
    let create_session = router.handle(
        authed("POST", "/sessions"),
        Some(manifest_body_with_root(
            session_id,
            &[provider],
            &evidence_root.to_string_lossy(),
        )),
    );
    assert_eq!(create_session.status, 200);

    let response = router.handle(
        authed("POST", "/provider-calls"),
        Some(json!({
            "session_id": session_id,
            "provider": provider,
            "action": "inspect",
            "arguments": {
                "root": "evidence",
                "input_path": "Cargo.toml"
            }
        })),
    );

    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["operation"]["data"]["outcome"]["decision"],
        "allowed"
    );
    assert_eq!(
        response.body["operation"]["data"]["outcome"]["output"]["normalized_segments"][0]["text"],
        "safe scoped content"
    );
}

#[test]
fn local_api_provider_call_applies_trace_export_query_arguments() {
    let session_id = "trace_export_session";
    let provider = "runwarden.trace.export";
    let first = trace_event();
    let second = TraceEvent::sealed(
        "obs_2".to_string(),
        "provider_completed".to_string(),
        Some("runwarden.report.lint".to_string()),
        json!({"ok": true}),
        Some(first.event_hash.clone()),
    );
    let arguments = json!({
        "trace": [first, second],
        "provider": "runwarden.report.lint",
        "limit": 10
    });
    let mut security =
        LocalApiSecurity::new("launch-secret", ["127.0.0.1:0"], ["http://127.0.0.1:0"]);
    security.insert_approval(approved_record(
        "approval-1",
        session_id,
        provider,
        "export",
        &arguments,
    ));
    let mut router = LocalApiRouter::new(security);
    let create_session = router.handle(
        authed("POST", "/sessions"),
        Some(manifest_body(session_id, &[provider])),
    );
    assert_eq!(create_session.status, 200);

    let response = router.handle(
        authed("POST", "/provider-calls"),
        Some(json!({
            "session_id": session_id,
            "provider": provider,
            "action": "export",
            "arguments": arguments,
            "approval_id": "approval-1"
        })),
    );

    assert_eq!(response.status, 200);
    assert_eq!(
        response.body["operation"]["data"]["outcome"]["decision"],
        "allowed"
    );
    assert_eq!(
        response.body["operation"]["data"]["outcome"]["output"]["page"]["total_matching"],
        1
    );
    assert_eq!(
        response.body["operation"]["data"]["outcome"]["output"]["page"]["events"][0]["obs_id"],
        "obs_2"
    );
}

#[test]
fn local_api_server_accepts_one_http_request_on_loopback() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = thread::spawn(move || {
        serve_one_request(
            listener,
            LocalApiServerConfig {
                launch_token: "launch-secret".to_string(),
                allowed_host: addr.to_string(),
                allowed_origin: format!("http://{addr}"),
            },
        )
        .expect("serve one request");
    });

    let mut stream = TcpStream::connect(addr).expect("connect");
    write!(
        stream,
        "GET /providers HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nAuthorization: Bearer launch-secret\r\nAccept: application/json\r\n\r\n"
    )
    .expect("write request");

    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    handle.join().expect("server thread");

    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("runwarden.input.inspect"));
    assert!(response.contains("\"side_effect_executed\":false"));
}

#[test]
fn local_api_server_preserves_state_across_requests_and_reads_split_body() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = thread::spawn(move || {
        let mut router = LocalApiRouter::from_config(LocalApiServerConfig {
            launch_token: "launch-secret".to_string(),
            allowed_host: addr.to_string(),
            allowed_origin: format!("http://{addr}"),
        });
        serve_next_request(&listener, &mut router).expect("serve session create");
        serve_next_request(&listener, &mut router).expect("serve provider list");
    });
    let body = manifest_body("session-1", &["runwarden.input.inspect"]).to_string();
    let head = format!(
        "POST /sessions HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nAuthorization: Bearer launch-secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    let mut stream = TcpStream::connect(addr).expect("connect first");
    stream.write_all(head.as_bytes()).expect("write head");
    thread::sleep(Duration::from_millis(25));
    stream.write_all(body.as_bytes()).expect("write body");
    let mut first_response = String::new();
    stream
        .read_to_string(&mut first_response)
        .expect("read first response");

    let mut stream = TcpStream::connect(addr).expect("connect second");
    write!(
        stream,
        "GET /providers?session=session-1 HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nAuthorization: Bearer launch-secret\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )
    .expect("write second request");
    let mut second_response = String::new();
    stream
        .read_to_string(&mut second_response)
        .expect("read second response");
    handle.join().expect("server thread");

    assert!(
        first_response.starts_with("HTTP/1.1 200 OK"),
        "{first_response}"
    );
    assert!(
        second_response.starts_with("HTTP/1.1 200 OK"),
        "{second_response}"
    );
    assert!(second_response.contains("runwarden.input.inspect"));
}

#[test]
fn local_api_server_rejects_oversized_body_before_buffering() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let handle = thread::spawn(move || {
        serve_one_request(
            listener,
            LocalApiServerConfig {
                launch_token: "launch-secret".to_string(),
                allowed_host: addr.to_string(),
                allowed_origin: format!("http://{addr}"),
            },
        )
    });
    let mut stream = TcpStream::connect(addr).expect("connect");
    let request = format!(
        "POST /sessions HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nAuthorization: Bearer launch-secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        1_048_577
    );
    stream.write_all(request.as_bytes()).expect("write request");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("shutdown write");

    let result = handle.join().expect("server thread");

    assert!(result.is_err());
}
