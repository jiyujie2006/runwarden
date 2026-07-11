use runwarden_state::{JournalError, StateStore};

const TABLES: [&str; 13] = [
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
];

#[test]
fn opening_a_store_applies_schema_v1_and_required_pragmas() {
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let store = StateStore::open(&state_dir).unwrap();
    let diagnostics = store.diagnostics().unwrap();

    assert_eq!(diagnostics.schema_version, 1);
    assert_eq!(diagnostics.journal_mode, "wal");
    assert!(diagnostics.foreign_keys);
    assert_eq!(diagnostics.synchronous, 2);
    assert_eq!(diagnostics.busy_timeout_ms, 5_000);
    let mut expected_tables = TABLES.map(str::to_string);
    expected_tables.sort();
    assert_eq!(diagnostics.tables, expected_tables);

    let reopened = StateStore::open(&state_dir).unwrap();
    assert_eq!(reopened.diagnostics().unwrap().schema_version, 1);
}

#[test]
fn unsupported_and_partial_schema_versions_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let unsupported = temp.path().join("unsupported");
    std::fs::create_dir_all(&unsupported).unwrap();
    let connection = rusqlite::Connection::open(unsupported.join("runwarden.db")).unwrap();
    connection.pragma_update(None, "user_version", 2).unwrap();
    drop(connection);
    assert!(matches!(
        StateStore::open(&unsupported),
        Err(JournalError::Integrity(_))
    ));

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
    let store = StateStore::open(&partial_v1).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(partial_v1.join("runwarden.db")).unwrap();
    connection.execute_batch("DROP TABLE exports;").unwrap();
    drop(connection);
    assert!(matches!(
        StateStore::open(&partial_v1),
        Err(JournalError::Integrity(_))
    ));
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
            assert_eq!(diagnostics.schema_version, 1);
            let mut expected_tables = TABLES.map(str::to_string);
            expected_tables.sort();
            assert_eq!(diagnostics.tables, expected_tables);
        }
    }
}
