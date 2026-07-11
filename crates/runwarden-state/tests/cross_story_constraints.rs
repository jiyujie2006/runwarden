use runwarden_state::StateStore;
use rusqlite::{Connection, Error, Result, ffi, params};

fn assert_constraint(result: Result<usize>, expected_extended_code: i32) {
    match result.expect_err("insert unexpectedly satisfied the migration constraint") {
        Error::SqliteFailure(error, _) => assert_eq!(
            error.extended_code, expected_extended_code,
            "unexpected SQLite constraint: {error:?}"
        ),
        other => panic!("expected a SQLite constraint failure, got {other:?}"),
    }
}

fn open_seeded() -> (tempfile::TempDir, Connection) {
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    drop(StateStore::open(&state_dir).unwrap());

    // Migration-level adversarial assertions deliberately use the known test
    // database path. Production code does not expose a raw-SQL escape hatch.
    let connection = Connection::open(state_dir.join("runwarden.db")).unwrap();
    connection
        .pragma_update(None, "foreign_keys", true)
        .unwrap();
    connection
        .execute_batch(
            r#"
            INSERT INTO stories (
                story_id, schema_version, title, scenario_id, run_mode,
                enforcement_mode, status, evidence_status, safe_story_json,
                created_at, updated_at
            ) VALUES
                ('story-a', '1.0.0', 'A', 'scenario', 'deterministic', 'enforced', 'running', 'pending', '{}', 't', 't'),
                ('story-b', '1.0.0', 'B', 'scenario', 'deterministic', 'enforced', 'running', 'pending', '{}', 't', 't');

            INSERT INTO sessions (
                session_id, story_id, authority_json, policy_snapshot_hash,
                expires_at, active
            ) VALUES
                ('session-a',  'story-a', '{}', 'policy-a',  't', 1),
                ('session-a2', 'story-a', '{}', 'policy-a2', 't', 1),
                ('session-b',  'story-b', '{}', 'policy-b',  't', 1);

            INSERT INTO operations (
                operation_id, story_id, session_id, invocation_key, provider,
                action, argument_hash, redacted_arguments_json,
                private_arguments_json, policy_snapshot_hash, state,
                side_effect_state, created_at, updated_at
            ) VALUES
                ('operation-a',  'story-a', 'session-a',  'invoke-a',  'provider', 'action', 'args', '{}', x'7b7d', 'policy-a',  'proposed', 'not_attempted', 't', 't'),
                ('operation-a2', 'story-a', 'session-a2', 'invoke-a2', 'provider', 'action', 'args', '{}', x'7b7d', 'policy-a2', 'proposed', 'not_attempted', 't', 't'),
                ('operation-b',  'story-b', 'session-b',  'invoke-b',  'provider', 'action', 'args', '{}', x'7b7d', 'policy-b',  'proposed', 'not_attempted', 't', 't');

            INSERT INTO events (
                story_id, sequence, obs_id, event_id, session_id, operation_id,
                event_type, redacted_payload_json, event_hash, recorded_at
            ) VALUES
                ('story-a', 1, 'obs-a', 'event-a', 'session-a', 'operation-a', 'observed', '{}', 'event-hash-a', 't'),
                ('story-b', 1, 'obs-b', 'event-b', 'session-b', 'operation-b', 'observed', '{}', 'event-hash-b', 't');
            "#,
        )
        .unwrap();

    (temp, connection)
}

fn insert_operation(
    connection: &Connection,
    operation_id: &str,
    policy_decision: Option<&str>,
    state: &str,
    side_effect_state: &str,
) -> Result<usize> {
    connection.execute(
        r#"INSERT INTO operations (
            operation_id, story_id, session_id, invocation_key, provider,
            action, argument_hash, redacted_arguments_json,
            private_arguments_json, policy_snapshot_hash, policy_decision,
            state, side_effect_state, created_at, updated_at
        ) VALUES (?1, 'story-a', 'session-a', ?1, 'provider', 'action',
            'args', '{}', x'7b7d', 'policy-a', ?2, ?3, ?4, 't', 't')"#,
        params![operation_id, policy_decision, state, side_effect_state],
    )
}

#[test]
fn every_story_scoped_relationship_rejects_mismatched_tuples() {
    let (_temp, connection) = open_seeded();

    assert_constraint(
        connection.execute(
            "INSERT INTO active_instances VALUES (1, 'instance', 'story-b', 'session-a', 1, 'host', 'token', 't')",
            [],
        ),
        ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
    );
    assert_constraint(
        connection.execute(
            "INSERT INTO budget_usage (story_id, session_id) VALUES ('story-b', 'session-a')",
            [],
        ),
        ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
    );
    assert_constraint(
        connection.execute(
            "INSERT INTO budget_reservations VALUES ('lease', 'story-b', 'session-a', '{}', 'reserved', 't', 't')",
            [],
        ),
        ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO operations (
                operation_id, story_id, session_id, invocation_key, provider,
                action, argument_hash, redacted_arguments_json,
                private_arguments_json, policy_snapshot_hash, state,
                side_effect_state, created_at, updated_at
            ) VALUES ('operation-cross', 'story-b', 'session-a', 'invoke-cross',
                'provider', 'action', 'args', '{}', x'7b7d', 'policy',
                'proposed', 'not_attempted', 't', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
    );
    assert_constraint(
        connection.execute(
            "INSERT INTO resource_claims VALUES ('story-b', 'operation-a', '{}', 'hash')",
            [],
        ),
        ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
    );
    assert_constraint(
        connection.execute(
            "INSERT INTO policy_checks VALUES ('story-b', 'operation-a', 1, '{}')",
            [],
        ),
        ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
    );

    // These same-story/different-session cases prove that approvals and
    // events bind all three operation identity components, not merely story
    // and operation.
    assert_constraint(
        connection.execute(
            r#"INSERT INTO approvals (
                approval_id, story_id, session_id, operation_id, binding_json,
                binding_hash, state, expires_at, created_at, updated_at
            ) VALUES ('approval-cross-session', 'story-a', 'session-a2',
                'operation-a', '{"maximum_consumptions":1}', 'hash',
                'pending', 't', 't', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO events (
                story_id, sequence, obs_id, event_id, session_id, operation_id,
                event_type, redacted_payload_json, event_hash, recorded_at
            ) VALUES ('story-a', 2, 'obs-cross-session', 'event-cross-session',
                'session-a2', 'operation-a', 'observed', '{}', 'hash', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO approvals (
                approval_id, story_id, session_id, operation_id, binding_json,
                binding_hash, state, expires_at, created_at, updated_at
            ) VALUES ('approval-cross-story', 'story-b', 'session-b',
                'operation-a', '{"maximum_consumptions":1}', 'hash',
                'pending', 't', 't', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO events (
                story_id, sequence, obs_id, event_id, session_id, operation_id,
                event_type, redacted_payload_json, event_hash, recorded_at
            ) VALUES ('story-b', 2, 'obs-cross-story', 'event-cross-story',
                'session-b', 'operation-a', 'observed', '{}', 'hash', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
    );

    // A frame must bind the exact event hash as well as story and sequence.
    assert_constraint(
        connection.execute(
            r#"INSERT INTO story_frames (
                story_id, sequence, story_version, event_hash, snapshot_hash,
                frame_hash, safe_story_json, recorded_at
            ) VALUES ('story-a', 1, 0, 'wrong-event-hash', 'snapshot',
                'frame-wrong-hash', '{}', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO story_frames (
                story_id, sequence, story_version, event_hash, snapshot_hash,
                frame_hash, safe_story_json, recorded_at
            ) VALUES ('story-b', 1, 0, 'event-hash-a', 'snapshot',
                'frame-cross-story', '{}', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_FOREIGNKEY,
    );

    let violations: i64 = connection
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(violations, 0);
}

#[test]
fn every_json_column_rejects_malformed_json() {
    let (_temp, connection) = open_seeded();

    let malformed_story = connection.execute(
        r#"INSERT INTO stories (
            story_id, schema_version, title, scenario_id, run_mode,
            enforcement_mode, status, evidence_status, safe_story_json,
            created_at, updated_at
        ) VALUES ('bad-story', '1.0.0', 'bad', 'scenario', 'deterministic', 'enforced',
            'running', 'pending', '{', 't', 't')"#,
        [],
    );
    assert_constraint(malformed_story, ffi::SQLITE_CONSTRAINT_CHECK);
    assert_constraint(
        connection.execute(
            r#"INSERT INTO sessions (
                session_id, story_id, authority_json, policy_snapshot_hash,
                expires_at, active
            ) VALUES ('bad-session', 'story-a', '{', 'policy', 't', 1)"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    assert_constraint(
        connection.execute(
            "INSERT INTO budget_reservations VALUES ('bad-json-lease', 'story-a', 'session-a', '{', 'reserved', 't', 't')",
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );

    for (operation_id, invocation_key, redacted, private, result) in [
        ("bad-redacted", "bad-redacted", "{", b"{}".as_slice(), None),
        ("bad-private", "bad-private", "{}", b"{".as_slice(), None),
        (
            "bad-result",
            "bad-result",
            "{}",
            b"{}".as_slice(),
            Some("{"),
        ),
    ] {
        assert_constraint(
            connection.execute(
                r#"INSERT INTO operations (
                    operation_id, story_id, session_id, invocation_key,
                    provider, action, argument_hash, redacted_arguments_json,
                    private_arguments_json, policy_snapshot_hash, state,
                    side_effect_state, provider_result_json, created_at,
                    updated_at
                ) VALUES (?1, 'story-a', 'session-a', ?2, 'provider', 'action',
                    'args', ?3, ?4, 'policy-a', 'proposed', 'not_attempted', ?5, 't', 't')"#,
                params![operation_id, invocation_key, redacted, private, result],
            ),
            ffi::SQLITE_CONSTRAINT_CHECK,
        );
    }

    assert_constraint(
        connection.execute(
            "INSERT INTO resource_claims VALUES ('story-a', 'operation-a', '{', 'hash')",
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    assert_constraint(
        connection.execute(
            "INSERT INTO policy_checks VALUES ('story-a', 'operation-a', 1, '{')",
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO approvals (
                approval_id, story_id, session_id, operation_id, binding_json,
                binding_hash, state, expires_at, created_at, updated_at
            ) VALUES ('bad-approval-json', 'story-a', 'session-a',
                'operation-a', '{', 'hash', 'pending', 't', 't', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO events (
                story_id, sequence, obs_id, event_id, session_id, operation_id,
                event_type, redacted_payload_json, event_hash, recorded_at
            ) VALUES ('story-a', 2, 'obs-bad-json', 'event-bad-json',
                'session-a', 'operation-a', 'observed', '{', 'hash', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO story_frames (
                story_id, sequence, story_version, event_hash, snapshot_hash,
                frame_hash, safe_story_json, recorded_at
            ) VALUES ('story-a', 1, 0, 'event-hash-a', 'snapshot',
                'frame-bad-json', '{', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    assert_constraint(
        connection.execute(
            "INSERT INTO report_claims VALUES ('story-a', 'bad-claim', '{')",
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );

    // Approval bindings are deliberately single-use, not merely valid JSON.
    assert_constraint(
        connection.execute(
            r#"INSERT INTO approvals (
                approval_id, story_id, session_id, operation_id, binding_json,
                binding_hash, state, expires_at, created_at, updated_at
            ) VALUES ('bad-consumptions', 'story-a', 'session-a',
                'operation-a', '{"maximum_consumptions":2}', 'hash',
                'pending', 't', 't', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
}

#[test]
fn integer_versions_counters_sequences_and_ordinals_are_bounded() {
    let (_temp, connection) = open_seeded();

    assert_constraint(
        connection.execute(
            r#"INSERT INTO stories (
                story_id, schema_version, title, scenario_id, run_mode,
                enforcement_mode, status, evidence_status, safe_story_json,
                version, created_at, updated_at
            ) VALUES ('negative-story-version', '1.0.0', 'bad', 'scenario', 'deterministic',
                'enforced', 'running', 'pending', '{}', -1, 't', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    for (session_id, active, version) in
        [("bad-active", 2_i64, 0_i64), ("bad-session-version", 1, -1)]
    {
        assert_constraint(
            connection.execute(
                r#"INSERT INTO sessions (
                    session_id, story_id, authority_json, policy_snapshot_hash,
                    expires_at, active, version
                ) VALUES (?1, 'story-a', '{}', 'policy', 't', ?2, ?3)"#,
                params![session_id, active, version],
            ),
            ffi::SQLITE_CONSTRAINT_CHECK,
        );
    }
    for (singleton, process_id) in [(0_i64, 1_i64), (1, 0)] {
        assert_constraint(
            connection.execute(
                "INSERT INTO active_instances VALUES (?1, 'bad-instance', 'story-a', 'session-a', ?2, 'host', 'token', 't')",
                params![singleton, process_id],
            ),
            ffi::SQLITE_CONSTRAINT_CHECK,
        );
    }

    for column in [
        "version",
        "calls_reserved",
        "calls_committed",
        "file_bytes_reserved",
        "file_bytes_committed",
        "network_bytes_reserved",
        "network_bytes_committed",
    ] {
        let sql = format!(
            "INSERT INTO budget_usage (story_id, session_id, {column}) VALUES ('story-a', 'session-a', -1)"
        );
        assert_constraint(connection.execute(&sql, []), ffi::SQLITE_CONSTRAINT_CHECK);
    }

    assert_constraint(
        connection.execute(
            r#"INSERT INTO operations (
                operation_id, story_id, session_id, invocation_key, provider,
                action, argument_hash, redacted_arguments_json,
                private_arguments_json, policy_snapshot_hash, state,
                side_effect_state, version, created_at, updated_at
            ) VALUES ('negative-operation-version', 'story-a', 'session-a',
                'negative-operation-version', 'provider', 'action', 'args',
                '{}', x'7b7d', 'policy', 'proposed', 'not_attempted', -1, 't', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    assert_constraint(
        connection.execute(
            "INSERT INTO policy_checks VALUES ('story-a', 'operation-a', 0, '{}')",
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO approvals (
                approval_id, story_id, session_id, operation_id, binding_json,
                binding_hash, state, expires_at, version, created_at, updated_at
            ) VALUES ('negative-approval-version', 'story-a', 'session-a',
                'operation-a', '{"maximum_consumptions":1}', 'hash',
                'pending', 't', -1, 't', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO events (
                story_id, sequence, obs_id, event_id, session_id, operation_id,
                event_type, redacted_payload_json, event_hash, recorded_at
            ) VALUES ('story-a', 0, 'obs-zero', 'event-zero', 'session-a',
                'operation-a', 'observed', '{}', 'hash-zero', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO story_frames (
                story_id, sequence, story_version, event_hash, snapshot_hash,
                frame_hash, safe_story_json, recorded_at
            ) VALUES ('story-a', 0, 0, 'hash-zero', 'snapshot',
                'frame-zero-sequence', '{}', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO story_frames (
                story_id, sequence, story_version, event_hash, snapshot_hash,
                frame_hash, safe_story_json, recorded_at
            ) VALUES ('story-a', 1, -1, 'event-hash-a', 'snapshot',
                'frame-negative-version', '{}', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
    assert_constraint(
        connection.execute(
            r#"INSERT INTO exports (
                export_id, story_id, story_version, relative_path,
                staging_name, state, created_at
            ) VALUES ('negative-export-version', 'story-a', -1,
                'export.json', 'staging', 'preparing', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
}

#[test]
fn frozen_enum_columns_accept_every_contract_value() {
    let (_temp, connection) = open_seeded();

    let mut story_values = Vec::new();
    story_values.extend(
        ["live", "deterministic", "recorded"]
            .into_iter()
            .map(|value| (value, "enforced", "running", "pending")),
    );
    story_values.extend(
        ["monitor_only", "enforced"]
            .into_iter()
            .map(|value| ("deterministic", value, "running", "pending")),
    );
    story_values.extend(
        [
            "running",
            "awaiting_approval",
            "blocked_before_side_effect",
            "completed_with_controlled_side_effect",
            "failed",
            "outcome_unknown",
            "evidence_invalid",
        ]
        .into_iter()
        .map(|value| ("deterministic", "enforced", value, "pending")),
    );
    story_values.extend(
        ["pending", "verified", "incomplete", "invalid"]
            .into_iter()
            .map(|value| ("deterministic", "enforced", "running", value)),
    );
    for (index, (run_mode, enforcement_mode, status, evidence_status)) in
        story_values.into_iter().enumerate()
    {
        connection
            .execute(
                r#"INSERT INTO stories (
                    story_id, schema_version, title, scenario_id, run_mode,
                    enforcement_mode, status, evidence_status,
                    safe_story_json, created_at, updated_at
                ) VALUES (?1, '1.0.0', 'enum test', 'scenario', ?2, ?3,
                    ?4, ?5, '{}', 't', 't')"#,
                params![
                    format!("enum-story-{index}"),
                    run_mode,
                    enforcement_mode,
                    status,
                    evidence_status
                ],
            )
            .unwrap();
    }

    for (index, state) in [
        "proposed",
        "policy_evaluated",
        "denied",
        "awaiting_approval",
        "denied_by_reviewer",
        "expired",
        "approved",
        "observed_only",
        "execution_leased",
        "executing",
        "completed",
        "failed",
        "outcome_unknown",
    ]
    .into_iter()
    .enumerate()
    {
        insert_operation(
            &connection,
            &format!("enum-operation-state-{index}"),
            None,
            state,
            "not_attempted",
        )
        .unwrap();
    }
    for (index, side_effect_state) in [
        "not_attempted",
        "blocked_before_execution",
        "simulated",
        "completed",
        "failed_before_side_effect",
        "executed_with_error",
        "outcome_unknown",
    ]
    .into_iter()
    .enumerate()
    {
        insert_operation(
            &connection,
            &format!("enum-side-effect-{index}"),
            None,
            "proposed",
            side_effect_state,
        )
        .unwrap();
    }
    for (index, decision) in ["allowed", "denied", "requires_review"]
        .into_iter()
        .enumerate()
    {
        insert_operation(
            &connection,
            &format!("enum-policy-{index}"),
            Some(decision),
            "proposed",
            "not_attempted",
        )
        .unwrap();
    }

    for (index, approval_state) in [
        "pending", "approved", "leased", "consumed", "denied", "expired", "revoked",
    ]
    .into_iter()
    .enumerate()
    {
        let operation_id = format!("enum-approval-operation-{index}");
        insert_operation(
            &connection,
            &operation_id,
            None,
            "proposed",
            "not_attempted",
        )
        .unwrap();
        connection
            .execute(
                r#"INSERT INTO approvals (
                    approval_id, story_id, session_id, operation_id,
                    binding_json, binding_hash, state, expires_at,
                    created_at, updated_at
                ) VALUES (?1, 'story-a', 'session-a', ?2,
                    '{"maximum_consumptions":1}', 'hash', ?3, 't', 't', 't')"#,
                params![
                    format!("enum-approval-{index}"),
                    operation_id,
                    approval_state
                ],
            )
            .unwrap();
    }
}

#[test]
fn frozen_enum_columns_reject_unknown_values() {
    let (_temp, connection) = open_seeded();

    for (index, run_mode, enforcement_mode, status, evidence_status) in [
        (0, "unknown", "enforced", "running", "pending"),
        (1, "deterministic", "unknown", "running", "pending"),
        (2, "deterministic", "enforced", "unknown", "pending"),
        (3, "deterministic", "enforced", "running", "unknown"),
    ] {
        assert_constraint(
            connection.execute(
                r#"INSERT INTO stories (
                    story_id, schema_version, title, scenario_id, run_mode,
                    enforcement_mode, status, evidence_status,
                    safe_story_json, created_at, updated_at
                ) VALUES (?1, '1.0.0', 'bad enum', 'scenario', ?2, ?3,
                    ?4, ?5, '{}', 't', 't')"#,
                params![
                    format!("bad-enum-story-{index}"),
                    run_mode,
                    enforcement_mode,
                    status,
                    evidence_status
                ],
            ),
            ffi::SQLITE_CONSTRAINT_CHECK,
        );
    }

    for (operation_id, decision, state, side_effect_state) in [
        (
            "bad-policy-decision",
            Some("unknown"),
            "proposed",
            "not_attempted",
        ),
        ("bad-operation-state", None, "unknown", "not_attempted"),
        ("bad-side-effect", None, "proposed", "unknown"),
    ] {
        assert_constraint(
            insert_operation(
                &connection,
                operation_id,
                decision,
                state,
                side_effect_state,
            ),
            ffi::SQLITE_CONSTRAINT_CHECK,
        );
    }

    assert_constraint(
        connection.execute(
            r#"INSERT INTO approvals (
                approval_id, story_id, session_id, operation_id, binding_json,
                binding_hash, state, expires_at, created_at, updated_at
            ) VALUES ('bad-approval-state', 'story-a', 'session-a',
                'operation-a', '{"maximum_consumptions":1}', 'hash',
                'unknown', 't', 't', 't')"#,
            [],
        ),
        ffi::SQLITE_CONSTRAINT_CHECK,
    );
}
