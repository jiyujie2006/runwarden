CREATE TABLE stories (
    story_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    title TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    run_mode TEXT NOT NULL,
    enforcement_mode TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_status TEXT NOT NULL,
    safe_story_json TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(run_mode IN ('live', 'deterministic', 'recorded')),
    CHECK(enforcement_mode IN ('monitor_only', 'enforced')),
    CHECK(status IN (
      'running', 'awaiting_approval', 'blocked_before_side_effect',
      'completed_with_controlled_side_effect', 'failed', 'outcome_unknown',
      'evidence_invalid'
    )),
    CHECK(evidence_status IN ('pending', 'verified', 'incomplete', 'invalid')),
    CHECK(json_valid(safe_story_json))
) STRICT;

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    authority_json TEXT NOT NULL,
    policy_snapshot_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
    UNIQUE(story_id, session_id),
    CHECK(json_valid(authority_json))
) STRICT;

CREATE TABLE active_instances (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    instance_id TEXT NOT NULL UNIQUE,
    story_id TEXT NOT NULL REFERENCES stories(story_id),
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    process_id INTEGER NOT NULL CHECK(process_id > 0),
    host_id TEXT NOT NULL,
    instance_token_hash TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id)
) STRICT;

CREATE TABLE budget_usage (
    story_id TEXT NOT NULL,
    session_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
    calls_reserved INTEGER NOT NULL DEFAULT 0 CHECK(calls_reserved >= 0),
    calls_committed INTEGER NOT NULL DEFAULT 0 CHECK(calls_committed >= 0),
    file_bytes_reserved INTEGER NOT NULL DEFAULT 0 CHECK(file_bytes_reserved >= 0),
    file_bytes_committed INTEGER NOT NULL DEFAULT 0 CHECK(file_bytes_committed >= 0),
    network_bytes_reserved INTEGER NOT NULL DEFAULT 0 CHECK(network_bytes_reserved >= 0),
    network_bytes_committed INTEGER NOT NULL DEFAULT 0 CHECK(network_bytes_committed >= 0),
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id)
) STRICT;

CREATE TABLE budget_reservations (
    lease_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    charge_json TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id),
    CHECK(json_valid(charge_json))
) STRICT;

CREATE TABLE operations (
    operation_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    invocation_key TEXT NOT NULL,
    parent_model_call_id TEXT,
    proposed_tool_call_id TEXT,
    provider TEXT NOT NULL,
    action TEXT NOT NULL,
    argument_hash TEXT NOT NULL,
    redacted_arguments_json TEXT NOT NULL,
    private_arguments_json BLOB NOT NULL,
    policy_snapshot_hash TEXT NOT NULL,
    policy_decision TEXT,
    policy_reason TEXT,
    state TEXT NOT NULL,
    side_effect_state TEXT NOT NULL,
    provider_result_json TEXT,
    version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
    lease_id TEXT,
    lease_owner TEXT,
    lease_expires_at TEXT,
    lease_pre_state TEXT,
    lease_instance_id TEXT,
    lease_instance_token_hash TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(story_id, operation_id),
    UNIQUE(story_id, session_id, operation_id),
    UNIQUE(story_id, session_id, invocation_key),
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id),
    CHECK(policy_decision IS NULL OR policy_decision IN (
      'allowed', 'denied', 'requires_review'
    )),
    CHECK(state IN (
      'proposed', 'policy_evaluated', 'denied', 'awaiting_approval',
      'denied_by_reviewer', 'expired', 'approved', 'observed_only',
      'execution_leased', 'executing', 'completed', 'failed',
      'outcome_unknown'
    )),
    CHECK(side_effect_state IN (
      'not_attempted', 'blocked_before_execution', 'simulated', 'completed',
      'failed_before_side_effect', 'executed_with_error', 'outcome_unknown'
    )),
    CHECK(json_valid(redacted_arguments_json)),
    CHECK(json_valid(CAST(private_arguments_json AS TEXT))),
    CHECK(provider_result_json IS NULL OR json_valid(provider_result_json))
) STRICT;

CREATE TABLE resource_claims (
    story_id TEXT NOT NULL,
    operation_id TEXT PRIMARY KEY,
    claim_json TEXT NOT NULL,
    claim_hash TEXT NOT NULL,
    FOREIGN KEY(story_id, operation_id)
      REFERENCES operations(story_id, operation_id) ON DELETE CASCADE,
    CHECK(json_valid(claim_json))
) STRICT;

CREATE TABLE policy_checks (
    story_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal > 0),
    check_json TEXT NOT NULL,
    PRIMARY KEY(operation_id, ordinal),
    FOREIGN KEY(story_id, operation_id)
      REFERENCES operations(story_id, operation_id) ON DELETE CASCADE,
    CHECK(json_valid(check_json))
) STRICT;

CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    binding_json TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    reviewer TEXT,
    reason TEXT,
    expires_at TEXT NOT NULL,
    lease_id TEXT,
    lease_owner TEXT,
    lease_expires_at TEXT,
    version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(story_id, session_id, operation_id)
      REFERENCES operations(story_id, session_id, operation_id) ON DELETE CASCADE,
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id),
    CHECK(state IN (
      'pending', 'approved', 'leased', 'consumed', 'denied', 'expired',
      'revoked'
    )),
    CHECK(json_valid(binding_json)),
    CHECK(
      json_type(binding_json, '$.maximum_consumptions') IS 'integer'
      AND json_extract(binding_json, '$.maximum_consumptions') IS 1
    )
) STRICT;

CREATE TABLE events (
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    obs_id TEXT NOT NULL UNIQUE,
    event_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    operation_id TEXT,
    event_type TEXT NOT NULL,
    provider TEXT,
    redacted_payload_json TEXT NOT NULL,
    previous_hash TEXT,
    event_hash TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY(story_id, sequence),
    UNIQUE(story_id, sequence, event_hash),
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id),
    FOREIGN KEY(story_id, session_id, operation_id)
      REFERENCES operations(story_id, session_id, operation_id),
    CHECK(json_valid(redacted_payload_json))
) STRICT;

CREATE TABLE story_frames (
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    story_version INTEGER NOT NULL CHECK(story_version >= 0),
    event_hash TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    previous_frame_hash TEXT,
    frame_hash TEXT NOT NULL UNIQUE,
    safe_story_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY(story_id, sequence),
    FOREIGN KEY(story_id, sequence, event_hash)
      REFERENCES events(story_id, sequence, event_hash),
    CHECK(json_valid(safe_story_json))
) STRICT;

CREATE TABLE report_claims (
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    claim_id TEXT NOT NULL,
    claim_json TEXT NOT NULL,
    PRIMARY KEY(story_id, claim_id),
    CHECK(json_valid(claim_json))
) STRICT;

CREATE TABLE exports (
    export_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL REFERENCES stories(story_id),
    story_version INTEGER NOT NULL CHECK(story_version >= 0),
    relative_path TEXT NOT NULL UNIQUE,
    staging_name TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    manifest_hash TEXT,
    chain_head TEXT,
    final_frame_hash TEXT,
    created_at TEXT NOT NULL,
    finalized_at TEXT,
    CHECK(state IN ('preparing', 'ready_to_publish', 'finalized', 'failed'))
) STRICT;

CREATE INDEX operations_story_state_idx ON operations(story_id, state);
CREATE INDEX events_story_event_idx ON events(story_id, event_type);
CREATE INDEX approvals_state_expiry_idx ON approvals(state, expires_at);

-- Rust journal versions/counters are u64. All future persistence code must
-- perform a checked u64-to-i64 conversion before binding these INTEGERs.
PRAGMA user_version = 1;
