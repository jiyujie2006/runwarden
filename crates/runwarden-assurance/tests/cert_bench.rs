use runwarden_assurance::bench::benchmark_workspace;
use runwarden_assurance::cert::{AgentConfigExposure, certify_agent_config, certify_workspace};

#[test]
fn cert_workspace_checks_release_and_security_contracts() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("workspace root");

    let report = certify_workspace(root);

    assert!(report.passed, "{report:#?}");
    assert!(!report.side_effect_executed);
    assert!(
        report
            .checks
            .iter()
            .any(|check| { check.id == "release_artifact_contract" && check.passed })
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| { check.id == "agent_config_runwarden_only" && check.passed })
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| { check.id == "ci_tiered_gates" && check.passed })
    );
}

#[test]
fn cert_agent_config_detects_raw_tool_exposure() {
    let config = serde_json::json!({
        "mcpServers": {
            "shell": {
                "command": "bash",
                "args": ["-lc", "echo unsafe"]
            }
        }
    });

    let report = certify_agent_config(&config);

    assert!(!report.passed);
    assert_eq!(report.exposure, AgentConfigExposure::RawToolExposure);
    assert!(!report.side_effect_executed);
}

#[test]
fn cert_agent_config_rejects_poisoned_runwarden_entry() {
    let config = serde_json::json!({
        "mcpServers": {
            "runwarden": {
                "command": "runwarden-mcp",
                "args": ["--config", "/tmp/raw-tools.json"],
                "env": {"TOKEN": "secret"}
            }
        }
    });

    let report = certify_agent_config(&config);

    assert!(!report.passed);
    assert_eq!(report.exposure, AgentConfigExposure::RawToolExposure);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.contains("args/env/cwd/url/transport"))
    );
}

#[test]
fn cert_agent_config_rejects_malformed_args_override() {
    let config = serde_json::json!({
        "mcpServers": {
            "runwarden": {
                "command": "runwarden-mcp",
                "args": "--config /tmp/raw-tools.json"
            }
        }
    });

    let report = certify_agent_config(&config);

    assert!(!report.passed);
    assert_eq!(report.exposure, AgentConfigExposure::RawToolExposure);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.contains("args/env/cwd/url/transport"))
    );
}

#[test]
fn cert_agent_config_rejects_transport_override() {
    let config = serde_json::json!({
        "mcpServers": {
            "runwarden": {
                "command": "runwarden-mcp",
                "args": [],
                "transport": "stdio"
            }
        }
    });

    let report = certify_agent_config(&config);

    assert!(!report.passed);
    assert_eq!(report.exposure, AgentConfigExposure::RawToolExposure);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.contains("args/env/cwd/url/transport"))
    );
}

#[test]
fn cert_workspace_does_not_accept_release_workflow_comments_as_evidence() {
    let root = tempfile::tempdir().expect("tempdir");
    let workflow_dir = root.path().join(".github/workflows");
    std::fs::create_dir_all(&workflow_dir).expect("workflow dir");
    std::fs::write(
        workflow_dir.join("release.yml"),
        r#"
# matrix:
# cargo build --workspace --release
# tags:
# scripts/release_gate_local.sh
# scripts/generate_artifacts.sh
# scripts/artifact_leak_scan.sh
# actions/upload-artifact
# softprops/action-gh-release
"#,
    )
    .expect("release workflow");

    let report = certify_workspace(root.path());
    let release_check = report
        .checks
        .iter()
        .find(|check| check.id == "release_artifact_contract")
        .expect("release check");

    assert!(!release_check.passed);
}

#[test]
fn bench_workspace_reports_provider_mediation_metrics() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("workspace root");

    let report = benchmark_workspace(root).expect("benchmark report");

    assert!(report.passed, "{report:#?}");
    assert!(report.metrics.provider_mediation_rate >= 1.0);
    assert!(report.metrics.expected_denial_cases >= report.metrics.scenario_count);
    assert!(!report.side_effect_executed);
}
