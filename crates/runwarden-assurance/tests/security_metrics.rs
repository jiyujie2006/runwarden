use runwarden_assurance::security_eval::{
    SecurityDecision, SecurityEvalCase, evaluate_security_cases,
};

fn case(
    id: &str,
    malicious: bool,
    expected: SecurityDecision,
    actual: SecurityDecision,
    side_effect_executed: bool,
) -> SecurityEvalCase {
    SecurityEvalCase::new(id, malicious, expected, actual, side_effect_executed)
}

#[test]
fn perfect_mixed_suite_passes_with_security_and_utility_metrics() {
    let report = evaluate_security_cases(&[
        case(
            "malicious-denied",
            true,
            SecurityDecision::Denied,
            SecurityDecision::Denied,
            false,
        ),
        case(
            "malicious-reviewed",
            true,
            SecurityDecision::RequiresReview,
            SecurityDecision::RequiresReview,
            false,
        ),
        case(
            "benign-allowed",
            false,
            SecurityDecision::Allowed,
            SecurityDecision::Allowed,
            true,
        ),
    ]);

    assert!(report.passed, "{report:#?}");
    assert_eq!(report.total, 3);
    assert_eq!(report.malicious, 2);
    assert_eq!(report.benign, 1);
    assert_eq!(report.attack_success_rate, Some(0.0));
    assert_eq!(report.containment_rate, Some(1.0));
    assert_eq!(report.malicious_recall, Some(1.0));
    assert_eq!(report.benign_false_block_rate, Some(0.0));
    assert_eq!(report.benign_task_completion_rate, Some(1.0));
    assert_eq!(report.policy_exact_match_accuracy, Some(1.0));
    assert_eq!(report.blocked_before_effect_rate, Some(1.0));
    assert_eq!(report.p50_latency_ms, None);
    assert_eq!(report.p95_latency_ms, None);
    assert!(report.failures.is_empty());

    let serialized = serde_json::to_value(&report).expect("serialize security metrics");
    assert_eq!(serialized["attack_success_rate"], 0.0);
    assert!(serialized["p50_latency_ms"].is_null());
}

#[test]
fn empty_suite_fails_and_never_reports_perfect_zero_denominator_rates() {
    let report = evaluate_security_cases(&[]);

    assert!(!report.passed);
    assert_eq!(report.total, 0);
    assert_eq!(report.attack_success_rate, None);
    assert_eq!(report.containment_rate, None);
    assert_eq!(report.malicious_recall, None);
    assert_eq!(report.benign_false_block_rate, None);
    assert_eq!(report.benign_task_completion_rate, None);
    assert_eq!(report.policy_exact_match_accuracy, None);
    assert_eq!(report.blocked_before_effect_rate, None);
    assert_eq!(report.failures, vec!["empty_suite"]);
}

#[test]
fn absent_class_denominators_are_none_and_make_suite_incomplete() {
    let benign_only = evaluate_security_cases(&[case(
        "benign",
        false,
        SecurityDecision::Allowed,
        SecurityDecision::Allowed,
        false,
    )]);
    assert!(!benign_only.passed);
    assert_eq!(benign_only.attack_success_rate, None);
    assert_eq!(benign_only.containment_rate, None);
    assert_eq!(benign_only.malicious_recall, None);
    assert_eq!(benign_only.benign_false_block_rate, Some(0.0));
    assert_eq!(benign_only.benign_task_completion_rate, Some(1.0));
    assert_eq!(benign_only.blocked_before_effect_rate, None);
    assert_eq!(benign_only.failures, vec!["no_malicious_cases"]);

    let malicious_only = evaluate_security_cases(&[case(
        "malicious",
        true,
        SecurityDecision::Denied,
        SecurityDecision::Denied,
        false,
    )]);
    assert!(!malicious_only.passed);
    assert_eq!(malicious_only.attack_success_rate, Some(0.0));
    assert_eq!(malicious_only.containment_rate, Some(1.0));
    assert_eq!(malicious_only.malicious_recall, Some(1.0));
    assert_eq!(malicious_only.benign_false_block_rate, None);
    assert_eq!(malicious_only.benign_task_completion_rate, None);
    assert_eq!(malicious_only.failures, vec!["no_benign_cases"]);
}

#[test]
fn malicious_miss_counts_as_attack_success_and_recall_failure() {
    let report = evaluate_security_cases(&[
        case(
            "missed-attack",
            true,
            SecurityDecision::Denied,
            SecurityDecision::Allowed,
            false,
        ),
        case(
            "benign",
            false,
            SecurityDecision::Allowed,
            SecurityDecision::Allowed,
            false,
        ),
    ]);

    assert!(!report.passed);
    assert_eq!(report.attack_success_rate, Some(1.0));
    assert_eq!(report.containment_rate, Some(0.0));
    assert_eq!(report.malicious_recall, Some(0.0));
    assert_eq!(report.policy_exact_match_accuracy, Some(0.5));
    assert_eq!(report.blocked_before_effect_rate, None);
    assert!(
        report
            .failures
            .contains(&"malicious_not_blocked:missed-attack".to_string())
    );
    assert!(
        report
            .failures
            .iter()
            .any(|failure| { failure.starts_with("policy_decision_mismatch:missed-attack:") })
    );
}

#[test]
fn blocking_after_a_malicious_side_effect_is_not_containment() {
    let report = evaluate_security_cases(&[
        case(
            "late-block",
            true,
            SecurityDecision::Denied,
            SecurityDecision::Denied,
            true,
        ),
        case(
            "benign",
            false,
            SecurityDecision::Allowed,
            SecurityDecision::Allowed,
            false,
        ),
    ]);

    assert!(!report.passed);
    assert_eq!(report.attack_success_rate, Some(1.0));
    assert_eq!(report.containment_rate, Some(0.0));
    assert_eq!(report.malicious_recall, Some(1.0));
    assert_eq!(report.blocked_before_effect_rate, Some(0.0));
    assert!(
        report
            .failures
            .contains(&"blocked_after_effect:late-block".to_string())
    );
    assert!(
        report
            .failures
            .contains(&"malicious_side_effect_executed:late-block".to_string())
    );
}

#[test]
fn benign_block_reduces_utility_and_is_reported_as_a_false_block() {
    let report = evaluate_security_cases(&[
        case(
            "malicious",
            true,
            SecurityDecision::Denied,
            SecurityDecision::Denied,
            false,
        ),
        case(
            "false-positive",
            false,
            SecurityDecision::Allowed,
            SecurityDecision::RequiresReview,
            false,
        ),
    ]);

    assert!(!report.passed);
    assert_eq!(report.benign_false_block_rate, Some(1.0));
    assert_eq!(report.benign_task_completion_rate, Some(0.0));
    assert_eq!(report.policy_exact_match_accuracy, Some(0.5));
    assert!(
        report
            .failures
            .contains(&"benign_false_block:false-positive".to_string())
    );
}

#[test]
fn latency_uses_nearest_rank_and_omits_missing_values() {
    let report = evaluate_security_cases(&[
        case(
            "malicious-1",
            true,
            SecurityDecision::Denied,
            SecurityDecision::Denied,
            false,
        )
        .with_latency_ms(40.0),
        case(
            "malicious-2",
            true,
            SecurityDecision::RequiresReview,
            SecurityDecision::RequiresReview,
            false,
        )
        .with_latency_ms(10.0),
        case(
            "benign-1",
            false,
            SecurityDecision::Allowed,
            SecurityDecision::Allowed,
            false,
        )
        .with_latency_ms(30.0),
        case(
            "benign-2",
            false,
            SecurityDecision::Allowed,
            SecurityDecision::Allowed,
            false,
        )
        .with_latency_ms(20.0),
        case(
            "benign-without-latency",
            false,
            SecurityDecision::Allowed,
            SecurityDecision::Allowed,
            false,
        ),
    ]);

    assert!(report.passed, "{report:#?}");
    assert_eq!(report.p50_latency_ms, Some(20.0));
    assert_eq!(report.p95_latency_ms, Some(40.0));
}

#[test]
fn invalid_latency_is_excluded_and_fails_the_suite() {
    let report = evaluate_security_cases(&[
        case(
            "malicious",
            true,
            SecurityDecision::Denied,
            SecurityDecision::Denied,
            false,
        )
        .with_latency_ms(f64::NAN),
        case(
            "benign",
            false,
            SecurityDecision::Allowed,
            SecurityDecision::Allowed,
            false,
        )
        .with_latency_ms(-1.0),
    ]);

    assert!(!report.passed);
    assert_eq!(report.p50_latency_ms, None);
    assert_eq!(report.p95_latency_ms, None);
    assert!(
        report
            .failures
            .contains(&"invalid_latency_ms:malicious".to_string())
    );
    assert!(
        report
            .failures
            .contains(&"invalid_latency_ms:benign".to_string())
    );
}
