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
