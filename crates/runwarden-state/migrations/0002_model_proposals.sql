CREATE TABLE model_calls (
    model_call_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    endpoint_kind TEXT NOT NULL,
    model_id TEXT NOT NULL,
    prompt_hash TEXT NOT NULL,
    response_hash TEXT,
    input_filter_state TEXT NOT NULL,
    output_filter_state TEXT,
    output_risk_codes_json TEXT,
    response_forwarded INTEGER CHECK(response_forwarded IN (0, 1)),
    output_bytes INTEGER CHECK(output_bytes IS NULL OR output_bytes >= 0),
    proposal_count INTEGER CHECK(proposal_count IS NULL OR proposal_count >= 0),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(story_id, model_call_id),
    UNIQUE(story_id, session_id, model_call_id),
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id),
    CHECK(length(prompt_hash) = 71
      AND substr(prompt_hash, 1, 7) = 'sha256:'
      AND substr(prompt_hash, 8) NOT GLOB '*[^0-9a-f]*'),
    CHECK(response_hash IS NULL OR (
      length(response_hash) = 71
      AND substr(response_hash, 1, 7) = 'sha256:'
      AND substr(response_hash, 8) NOT GLOB '*[^0-9a-f]*'
    )),
    CHECK(input_filter_state IN ('pending', 'safe', 'flagged', 'blocked')),
    CHECK(output_filter_state IS NULL OR
      output_filter_state IN ('safe', 'flagged', 'blocked')),
    CHECK(CASE
      WHEN output_risk_codes_json IS NULL THEN 1
      WHEN json_valid(output_risk_codes_json)
        THEN json_type(output_risk_codes_json) IS 'array'
      ELSE 0
    END)
) STRICT;

CREATE TABLE model_usage (
    story_id TEXT NOT NULL,
    session_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
    calls_committed INTEGER NOT NULL DEFAULT 0 CHECK(calls_committed >= 0),
    input_bytes_committed INTEGER NOT NULL DEFAULT 0 CHECK(input_bytes_committed >= 0),
    output_bytes_committed INTEGER NOT NULL DEFAULT 0 CHECK(output_bytes_committed >= 0),
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id)
) STRICT;

CREATE TABLE tool_proposals (
    proposal_id TEXT PRIMARY KEY,
    story_id TEXT NOT NULL REFERENCES stories(story_id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    model_call_id TEXT NOT NULL,
    upstream_tool_call_id TEXT,
    provider TEXT NOT NULL,
    action TEXT NOT NULL,
    argument_hash TEXT NOT NULL,
    redacted_arguments_json TEXT NOT NULL,
    linked_operation_id TEXT UNIQUE,
    created_at TEXT NOT NULL,
    FOREIGN KEY(story_id, session_id) REFERENCES sessions(story_id, session_id),
    FOREIGN KEY(story_id, session_id, model_call_id)
      REFERENCES model_calls(story_id, session_id, model_call_id) ON DELETE CASCADE,
    FOREIGN KEY(story_id, session_id, linked_operation_id)
      REFERENCES operations(story_id, session_id, operation_id),
    CHECK(length(argument_hash) = 71
      AND substr(argument_hash, 1, 7) = 'sha256:'
      AND substr(argument_hash, 8) NOT GLOB '*[^0-9a-f]*'),
    CHECK(CASE WHEN json_valid(redacted_arguments_json)
      THEN json_type(redacted_arguments_json) IS 'object' ELSE 0 END)
) STRICT;

CREATE INDEX tool_proposals_commitment_idx
ON tool_proposals(story_id, session_id, provider, action, argument_hash);

CREATE UNIQUE INDEX tool_proposals_upstream_id_idx
ON tool_proposals(model_call_id, upstream_tool_call_id)
WHERE upstream_tool_call_id IS NOT NULL;

INSERT INTO model_usage (
    story_id, session_id, version, calls_committed,
    input_bytes_committed, output_bytes_committed
)
SELECT story_id, session_id, 0, 0, 0, 0 FROM sessions;

PRAGMA user_version = 2;
