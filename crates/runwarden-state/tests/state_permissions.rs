#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn assert_owner_only(state_dir: &std::path::Path) {
    assert_eq!(
        std::fs::metadata(state_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for name in ["runwarden.db", "runwarden.db-wal", "runwarden.db-shm"] {
        let path = state_dir.join(name);
        if path.exists() {
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600,
                "{}",
                path.display()
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn new_state_directory_and_database_files_are_owner_only() {
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    let store = runwarden_state::StateStore::open(&state_dir).unwrap();
    store.force_wal_write_for_test().unwrap();
    assert_owner_only(&state_dir);

    let connection = rusqlite::Connection::open(state_dir.join("runwarden.db")).unwrap();
    let story_count: i64 = connection
        .query_row("SELECT count(*) FROM stories", [], |row| row.get(0))
        .unwrap();
    assert_eq!(story_count, 0, "the WAL permission probe must not persist");
}

#[cfg(unix)]
#[test]
fn existing_state_directory_and_database_are_hardened() {
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    std::fs::create_dir(&state_dir).unwrap();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let database = state_dir.join("runwarden.db");
    std::fs::write(&database, []).unwrap();
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o666)).unwrap();

    let store = runwarden_state::StateStore::open(&state_dir).unwrap();
    store.force_wal_write_for_test().unwrap();
    assert_owner_only(&state_dir);
}

#[cfg(unix)]
#[test]
fn symlink_state_paths_are_rejected_without_following_them() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let state_link = temp.path().join("state-link");
    symlink(outside.path(), &state_link).unwrap();
    assert!(matches!(
        runwarden_state::StateStore::open(&state_link),
        Err(runwarden_state::JournalError::Permission(_))
    ));

    let state_dir = temp.path().join("state");
    std::fs::create_dir(&state_dir).unwrap();
    let outside_database = outside.path().join("outside.db");
    std::fs::write(&outside_database, b"unchanged").unwrap();
    symlink(&outside_database, state_dir.join("runwarden.db")).unwrap();
    assert!(matches!(
        runwarden_state::StateStore::open(&state_dir),
        Err(runwarden_state::JournalError::Permission(_))
    ));
    assert_eq!(std::fs::read(outside_database).unwrap(), b"unchanged");
}

#[cfg(unix)]
#[test]
fn relative_state_path_rejects_a_symlinked_ancestor_without_touching_outside() {
    use std::os::unix::fs::symlink;

    let current_dir = std::env::current_dir().unwrap();
    let temp = tempfile::Builder::new()
        .prefix("runwarden-state-ancestor-")
        .tempdir_in(&current_dir)
        .unwrap();
    let relative_root = temp.path().strip_prefix(&current_dir).unwrap();
    let trusted = temp.path().join("trusted");
    let outside = temp.path().join("outside");
    std::fs::create_dir(&trusted).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let marker = outside.join("marker");
    std::fs::write(&marker, b"unchanged").unwrap();
    symlink(&outside, trusted.join("link")).unwrap();

    let result =
        runwarden_state::StateStore::open(relative_root.join("trusted").join("link").join("state"));

    assert_eq!(std::fs::read(&marker).unwrap(), b"unchanged");
    assert!(!outside.join("state").exists());
    assert!(matches!(
        result,
        Err(runwarden_state::JournalError::Permission(_))
    ));
}

#[cfg(unix)]
#[test]
fn parent_components_in_state_paths_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let child = temp.path().join("child");
    std::fs::create_dir(&child).unwrap();
    let state_dir = child.join("..").join("state");

    assert!(matches!(
        runwarden_state::StateStore::open(&state_dir),
        Err(runwarden_state::JournalError::Permission(_))
    ));
    assert!(!temp.path().join("state").exists());
}

#[cfg(unix)]
#[test]
fn symlink_wal_and_shm_paths_are_rejected_without_following_them() {
    use std::os::unix::fs::symlink;

    for suffix in ["-wal", "-shm"] {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        std::fs::create_dir(&state_dir).unwrap();
        let outside_file = outside.path().join("outside");
        std::fs::write(&outside_file, b"unchanged").unwrap();
        symlink(
            &outside_file,
            state_dir.join(format!("runwarden.db{suffix}")),
        )
        .unwrap();

        assert!(matches!(
            runwarden_state::StateStore::open(&state_dir),
            Err(runwarden_state::JournalError::Permission(_))
        ));
        assert_eq!(std::fs::read(outside_file).unwrap(), b"unchanged");
    }
}

#[cfg(unix)]
#[test]
fn non_directory_state_and_non_regular_database_paths_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let state_file = temp.path().join("state-file");
    std::fs::write(&state_file, []).unwrap();
    assert!(matches!(
        runwarden_state::StateStore::open(&state_file),
        Err(runwarden_state::JournalError::Permission(_))
    ));

    for name in ["runwarden.db", "runwarden.db-wal", "runwarden.db-shm"] {
        let state_dir = temp.path().join(name.replace('.', "-"));
        std::fs::create_dir(&state_dir).unwrap();
        std::fs::create_dir(state_dir.join(name)).unwrap();
        assert!(matches!(
            runwarden_state::StateStore::open(&state_dir),
            Err(runwarden_state::JournalError::Permission(_))
        ));
    }
}

#[cfg(unix)]
#[test]
fn existing_wal_and_shm_files_are_hardened() {
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    drop(runwarden_state::StateStore::open(&state_dir).unwrap());

    let connection = rusqlite::Connection::open(state_dir.join("runwarden.db")).unwrap();
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .unwrap();
    connection
        .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
        .unwrap();

    for name in ["runwarden.db-wal", "runwarden.db-shm"] {
        let path = state_dir.join(name);
        assert!(path.is_file(), "SQLite did not create {}", path.display());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    }

    drop(runwarden_state::StateStore::open(&state_dir).unwrap());
    assert_owner_only(&state_dir);
    drop(connection);
}

#[cfg(not(unix))]
#[test]
fn non_unix_state_store_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    assert!(matches!(
        runwarden_state::StateStore::open(temp.path().join("state")),
        Err(runwarden_state::JournalError::Permission(_))
    ));
}
