use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent, TraceQuery};
use runwarden_kernel::kernel::{ProviderRegistry, enforce_provider_exists};
use runwarden_kernel::{ExecutionStatus, PolicyDecision, ProviderCall};
use serde_json::json;

#[test]
fn unknown_provider_is_denied_before_side_effect() {
    let registry = ProviderRegistry::default();
    let call = ProviderCall {
        session_id: "session-1".to_string(),
        provider: "external.shell.command".to_string(),
        action: "run".to_string(),
        arguments: json!({"command":"curl http://169.254.169.254"}),
        actor_id: Some("agent-1".to_string()),
        authz_id: Some("authz-1".to_string()),
        approval_id: None,
    };

    let denial = enforce_provider_exists(&registry, &call).expect_err("unknown provider denies");

    assert_eq!(denial.decision, PolicyDecision::Denied);
    assert_eq!(denial.execution_status, ExecutionStatus::NotExecuted);
    assert!(!denial.envelope.side_effect_executed);
    assert_eq!(denial.envelope.provider, "external.shell.command");
}

#[test]
fn trace_store_pages_without_loading_unrequested_events() {
    let mut store = InMemoryTraceStore::default();
    for idx in 0..5 {
        store.append(TraceEvent {
            obs_id: format!("obs_{idx}"),
            event_type: "provider_policy_evaluated".to_string(),
            provider: Some("runwarden.evidence.inspect".to_string()),
            payload: json!({"idx": idx}),
            previous_hash: None,
            event_hash: format!("hash_{idx}"),
        });
    }

    let page = store.page(1, 2);

    assert_eq!(page.len(), 2);
    assert_eq!(page[0].obs_id, "obs_1");
    assert_eq!(page[1].obs_id, "obs_2");
}

#[test]
fn trace_store_query_filters_events_and_enforces_byte_budget() {
    let mut store = InMemoryTraceStore::default();
    for idx in 0..4 {
        store.append(TraceEvent {
            obs_id: format!("obs_{idx}"),
            event_type: if idx % 2 == 0 {
                "provider_policy_evaluated".to_string()
            } else {
                "provider_completed".to_string()
            },
            provider: Some(if idx < 3 {
                "runwarden.evidence.inspect".to_string()
            } else {
                "runwarden.report.render".to_string()
            }),
            payload: json!({"idx": idx, "padding": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}),
            previous_hash: None,
            event_hash: format!("hash_{idx}"),
        });
    }

    let page = store.query(TraceQuery {
        offset: 0,
        limit: 10,
        provider: Some("runwarden.evidence.inspect".to_string()),
        event_type: Some("provider_completed".to_string()),
        obs_prefix: None,
        max_bytes: Some(10_000),
    });

    assert_eq!(page.total_matching, 1);
    assert_eq!(page.events[0].obs_id, "obs_1");
    assert_eq!(page.next_offset, None);

    let bounded = store.query(TraceQuery {
        offset: 0,
        limit: 10,
        provider: None,
        event_type: None,
        obs_prefix: Some("obs_".to_string()),
        max_bytes: Some(1),
    });

    assert!(bounded.events.is_empty());
    assert!(bounded.truncated_by_bytes);
    assert_eq!(bounded.next_offset, Some(0));
}

#[test]
fn trace_store_stream_export_returns_verified_pages_until_complete() {
    let mut store = InMemoryTraceStore::default();
    for idx in 0..3 {
        store.append_signed(
            format!("obs_{idx}"),
            "provider_completed",
            Some("runwarden.input.inspect"),
            json!({"idx": idx}),
        );
    }

    let first = store
        .stream_export(TraceQuery {
            offset: 0,
            limit: 2,
            provider: Some("runwarden.input.inspect".to_string()),
            event_type: None,
            obs_prefix: None,
            max_bytes: None,
        })
        .expect("verified first page");

    assert!(first.verified);
    assert_eq!(first.page.events.len(), 2);
    assert_eq!(first.page.next_offset, Some(2));
    assert_eq!(first.compact_refs, vec!["obs_0", "obs_1"]);

    let second = store
        .stream_export(TraceQuery {
            offset: first.page.next_offset.expect("next page"),
            limit: 2,
            provider: Some("runwarden.input.inspect".to_string()),
            event_type: None,
            obs_prefix: None,
            max_bytes: None,
        })
        .expect("verified second page");

    assert_eq!(second.page.events.len(), 1);
    assert_eq!(second.page.next_offset, None);
    assert_eq!(second.compact_refs, vec!["obs_2"]);
}

#[test]
fn trace_store_verifies_hash_chain_and_rejects_tamper() {
    let mut store = InMemoryTraceStore::default();
    store.append_signed(
        "obs_1",
        "provider_policy_evaluated",
        Some("runwarden.evidence.inspect"),
        json!({"decision":"allowed"}),
    );
    store.append_signed(
        "obs_2",
        "provider_completed",
        Some("runwarden.evidence.inspect"),
        json!({"status":"completed"}),
    );

    store.verify_hash_chain().expect("fresh trace verifies");

    store
        .events_mut_for_test()
        .get_mut(0)
        .expect("event exists")
        .payload = json!({"decision":"denied"});

    assert!(store.verify_hash_chain().is_err());
}
