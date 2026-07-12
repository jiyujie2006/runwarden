use runwarden_state::{JournalError, StateStore};

const MIGRATION_V1: &str = include_str!("../migrations/0001_story_journal.sql");

const TABLES: [&str; 16] = [
    "stories",
    "sessions",
    "active_instances",
    "operations",
    "budget_usage",
    "budget_reservations",
    "resource_claims",
    "policy_checks",
    "approvals",
    "events",
    "story_frames",
    "report_claims",
    "exports",
    "model_calls",
    "model_usage",
    "tool_proposals",
];

#[test]
fn opening_a_store_applies_schema_v2_and_required_pragmas() {
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let store = StateStore::open(&state_dir).unwrap();
    let diagnostics = store.diagnostics().unwrap();

    assert_eq!(diagnostics.schema_version, 2);
    assert_eq!(diagnostics.journal_mode, "wal");
    assert!(diagnostics.foreign_keys);
    assert_eq!(diagnostics.synchronous, 2);
    assert_eq!(diagnostics.busy_timeout_ms, 5_000);
    let mut expected_tables = TABLES.map(str::to_string);
    expected_tables.sort();
    assert_eq!(diagnostics.tables, expected_tables);

    let reopened = StateStore::open(&state_dir).unwrap();
    assert_eq!(reopened.diagnostics().unwrap().schema_version, 2);
}

#[test]
fn opening_a_v1_store_migrates_existing_sessions_and_preserves_rows() {
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("v1");
    std::fs::create_dir_all(&state_dir).unwrap();
    let database = state_dir.join("runwarden.db");
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection.execute_batch(MIGRATION_V1).unwrap();
    connection
        .execute_batch(
            r#"
            INSERT INTO stories (
                story_id, schema_version, title, scenario_id, run_mode,
                enforcement_mode, status, evidence_status, safe_story_json,
                created_at, updated_at
            ) VALUES (
                'story-v1', '1.0.0', 'v1 story', 'migration', 'deterministic',
                'enforced', 'running', 'pending', '{}',
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
            );
            INSERT INTO sessions (
                session_id, story_id, authority_json, policy_snapshot_hash,
                expires_at, active
            ) VALUES (
                'session-v1', 'story-v1', '{}',
                'sha256:0000000000000000000000000000000000000000000000000000000000000000',
                '2027-01-01T00:00:00Z', 1
            );
            "#,
        )
        .unwrap();
    drop(connection);

    let store = StateStore::open(&state_dir).unwrap();
    assert_eq!(store.diagnostics().unwrap().schema_version, 2);

    let connection = rusqlite::Connection::open(&database).unwrap();
    let sessions: i64 = connection
        .query_row("SELECT count(*) FROM sessions", [], |row| row.get(0))
        .unwrap();
    let usage: (String, i64, i64, i64, i64) = connection
        .query_row(
            r#"SELECT story_id, version, calls_committed,
                      input_bytes_committed, output_bytes_committed
               FROM model_usage WHERE session_id = 'session-v1'"#,
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(sessions, 1);
    assert_eq!(usage, ("story-v1".to_owned(), 0, 0, 0, 0));
}

#[test]
fn unsupported_and_partial_schema_versions_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let unsupported = temp.path().join("unsupported");
    let store = StateStore::open(&unsupported).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(unsupported.join("runwarden.db")).unwrap();
    connection
        .execute_batch(
            r#"
            INSERT INTO stories (
                story_id, schema_version, title, scenario_id, run_mode,
                enforcement_mode, status, evidence_status, safe_story_json,
                created_at, updated_at
            ) VALUES (
                'newer-sentinel', '1.0.0', 'newer sentinel', 'migration',
                'deterministic', 'enforced', 'running', 'pending', '{}',
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
            );
            "#,
        )
        .unwrap();
    connection.pragma_update(None, "user_version", 3).unwrap();
    drop(connection);
    assert!(matches!(
        StateStore::open(&unsupported),
        Err(JournalError::Integrity(_))
    ));
    let connection = rusqlite::Connection::open(unsupported.join("runwarden.db")).unwrap();
    let sentinel: i64 = connection
        .query_row(
            "SELECT count(*) FROM stories WHERE story_id = 'newer-sentinel'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(sentinel, 1);

    let partial_v0 = temp.path().join("partial-v0");
    std::fs::create_dir_all(&partial_v0).unwrap();
    let connection = rusqlite::Connection::open(partial_v0.join("runwarden.db")).unwrap();
    connection
        .execute_batch("CREATE TABLE unexpected(value TEXT) STRICT;")
        .unwrap();
    drop(connection);
    assert!(matches!(
        StateStore::open(&partial_v0),
        Err(JournalError::Integrity(_))
    ));

    let partial_v1 = temp.path().join("partial-v1");
    std::fs::create_dir_all(&partial_v1).unwrap();
    let connection = rusqlite::Connection::open(partial_v1.join("runwarden.db")).unwrap();
    connection.execute_batch(MIGRATION_V1).unwrap();
    connection.execute_batch("DROP TABLE exports;").unwrap();
    drop(connection);
    assert!(matches!(
        StateStore::open(&partial_v1),
        Err(JournalError::Integrity(_))
    ));
    let connection = rusqlite::Connection::open(partial_v1.join("runwarden.db")).unwrap();
    let v2_tables: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'model_calls'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(v2_tables, 0);

    let partial_v2 = temp.path().join("partial-v2");
    let store = StateStore::open(&partial_v2).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(partial_v2.join("runwarden.db")).unwrap();
    connection.execute_batch("DROP TABLE model_usage;").unwrap();
    drop(connection);
    assert!(matches!(
        StateStore::open(&partial_v2),
        Err(JournalError::Integrity(_))
    ));

    let missing_index = temp.path().join("missing-causal-index");
    let store = StateStore::open(&missing_index).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(missing_index.join("runwarden.db")).unwrap();
    connection
        .execute_batch("DROP INDEX tool_proposals_upstream_id_idx;")
        .unwrap();
    drop(connection);
    assert!(matches!(
        StateStore::open(&missing_index),
        Err(JournalError::Integrity(_))
    ));
}

#[test]
fn concurrent_v1_openers_share_one_atomic_v2_upgrade() {
    use std::sync::{Arc, Barrier};

    let temp = tempfile::tempdir().unwrap();
    let state_dir = Arc::new(temp.path().join("v1-concurrent"));
    std::fs::create_dir_all(state_dir.as_path()).unwrap();
    rusqlite::Connection::open(state_dir.join("runwarden.db"))
        .unwrap()
        .execute_batch(MIGRATION_V1)
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let state_dir = Arc::clone(&state_dir);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                StateStore::open(state_dir.as_path())
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        let store = handle.join().unwrap().unwrap();
        assert_eq!(store.diagnostics().unwrap().schema_version, 2);
    }
}

#[test]
fn concurrent_first_openers_share_one_atomic_migration() {
    use std::sync::{Arc, Barrier};

    // Repetition makes the pre-lock version-read race deterministic enough to
    // catch without a production test hook. Each individual attempt still has
    // exactly two first openers released by one barrier onto one path.
    for attempt in 0..64 {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = Arc::new(temp.path().join(format!("state-{attempt}")));
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let state_dir = Arc::clone(&state_dir);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    StateStore::open(state_dir.as_path())
                })
            })
            .collect();

        let mut stores = Vec::new();
        for handle in handles {
            stores.push(handle.join().unwrap().unwrap_or_else(|error| {
                panic!("concurrent first opener failed on attempt {attempt}: {error}")
            }));
        }
        for store in stores {
            let diagnostics = store.diagnostics().unwrap();
            assert_eq!(diagnostics.schema_version, 2);
            let mut expected_tables = TABLES.map(str::to_string);
            expected_tables.sort();
            assert_eq!(diagnostics.tables, expected_tables);
        }
    }
}
