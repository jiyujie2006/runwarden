use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::{Connection, ErrorCode, OpenFlags, TransactionBehavior, params};

use crate::JournalError;

const DATABASE_NAME: &str = "runwarden.db";
const MIGRATION_V1: &str = include_str!("../migrations/0001_story_journal.sql");
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreDiagnostics {
    pub schema_version: i64,
    pub journal_mode: String,
    pub foreign_keys: bool,
    pub synchronous: i64,
    pub busy_timeout_ms: i64,
    pub tables: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct StateStore {
    state_dir: PathBuf,
}

impl StateStore {
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self, JournalError> {
        let state_dir = state_dir.as_ref().to_path_buf();
        let mut connection = open_configured_connection(&state_dir)?;
        migrate(&mut connection)?;
        validate_v1_schema(&connection)?;
        harden_database_files(&state_dir)?;
        drop(connection);

        Ok(Self { state_dir })
    }

    pub fn diagnostics(&self) -> Result<StoreDiagnostics, JournalError> {
        let connection = open_configured_connection(&self.state_dir)?;
        validate_v1_schema(&connection)?;
        let diagnostics = read_diagnostics(&connection)?;
        harden_database_files(&self.state_dir)?;
        Ok(diagnostics)
    }

    /// Force SQLite to materialize its WAL sidecars for permission tests.
    ///
    /// This deliberately exposes no general-purpose raw SQL API.
    #[doc(hidden)]
    pub fn force_wal_write_for_test(&self) -> Result<(), JournalError> {
        let mut connection = open_configured_connection(&self.state_dir)?;
        validate_v1_schema(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let probe_id = uuid::Uuid::now_v7().to_string();
        transaction.execute(
            r#"INSERT INTO stories (
                story_id, schema_version, title, scenario_id, run_mode,
                enforcement_mode, status, evidence_status, safe_story_json,
                created_at, updated_at
            ) VALUES (
                ?1, '1.0.0', 'permission probe', 'internal', 'deterministic',
                'enforced', 'running', 'pending', '{}',
                '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'
            )"#,
            params![probe_id],
        )?;
        transaction.execute("DELETE FROM stories WHERE story_id = ?1", params![probe_id])?;
        transaction.commit()?;
        harden_database_files(&self.state_dir)
    }
}

fn open_configured_connection(state_dir: &Path) -> Result<Connection, JournalError> {
    prepare_state_directory(state_dir)?;
    prepare_database_files(state_dir)?;

    let database_path = state_dir.join(DATABASE_NAME);
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    // SQLITE_OPEN_URI is intentionally absent: paths are literal filesystem
    // paths and SQLite must not interpret query parameters or URI authorities.
    let connection = Connection::open_with_flags(database_path, flags)?;
    configure_connection(&connection)?;
    harden_database_files(state_dir)?;
    Ok(connection)
}

fn configure_connection(connection: &Connection) -> Result<(), JournalError> {
    // Install the timeout before journal_mode: switching or confirming WAL can
    // itself acquire a database lock during concurrent first opens.
    connection.busy_timeout(BUSY_TIMEOUT)?;
    set_wal_with_retry(connection)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "synchronous", "FULL")?;

    let diagnostics = read_diagnostics(connection)?;
    if diagnostics.journal_mode != "wal" {
        return Err(JournalError::Integrity(format!(
            "journal_mode is {}, expected wal",
            diagnostics.journal_mode
        )));
    }
    if !diagnostics.foreign_keys {
        return Err(JournalError::Integrity(
            "foreign_keys is disabled".to_owned(),
        ));
    }
    if diagnostics.synchronous != 2 {
        return Err(JournalError::Integrity(format!(
            "synchronous is {}, expected FULL (2)",
            diagnostics.synchronous
        )));
    }
    if diagnostics.busy_timeout_ms != 5_000 {
        return Err(JournalError::Integrity(format!(
            "busy_timeout is {}ms, expected 5000ms",
            diagnostics.busy_timeout_ms
        )));
    }
    Ok(())
}

fn set_wal_with_retry(connection: &Connection) -> Result<(), JournalError> {
    let deadline = Instant::now() + BUSY_TIMEOUT;
    loop {
        match connection.pragma_update(None, "journal_mode", "WAL") {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(
                    error.sqlite_error_code(),
                    Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
                ) && Instant::now() < deadline =>
            {
                // SQLite does not consistently invoke the busy handler while
                // changing journal mode, so retain the same bounded 5s policy
                // with a short retry interval.
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn read_diagnostics(connection: &Connection) -> Result<StoreDiagnostics, JournalError> {
    let schema_version = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let synchronous = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let busy_timeout_ms = connection.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
    let mut statement = connection.prepare(
        r#"SELECT name
           FROM sqlite_schema
           WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
           ORDER BY name"#,
    )?;
    let tables = statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;

    Ok(StoreDiagnostics {
        schema_version,
        journal_mode: journal_mode.to_ascii_lowercase(),
        foreign_keys: foreign_keys == 1,
        synchronous,
        busy_timeout_ms,
        tables,
    })
}

fn migrate(connection: &mut Connection) -> Result<(), JournalError> {
    // The version and emptiness checks must happen only after the write lock is
    // acquired. A second first opener then waits, rereads v1, and validates
    // instead of attempting the v1 DDL a second time.
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    match version {
        0 => {
            if !schema_objects(&transaction)?.is_empty() {
                return Err(JournalError::Integrity(
                    "schema version 0 contains application schema objects".to_owned(),
                ));
            }

            transaction.execute_batch(MIGRATION_V1)?;
            validate_v1_schema(&transaction)?;
            transaction.commit()?;
            Ok(())
        }
        1 => {
            validate_v1_schema(&transaction)?;
            transaction.commit()?;
            Ok(())
        }
        unsupported => Err(JournalError::Integrity(format!(
            "unsupported schema version {unsupported}"
        ))),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: String,
}

fn schema_objects(connection: &Connection) -> Result<Vec<SchemaObject>, JournalError> {
    let mut statement = connection.prepare(
        r#"SELECT type, name, tbl_name, coalesce(sql, '')
           FROM sqlite_schema
           WHERE name NOT LIKE 'sqlite_%'
           ORDER BY type, name"#,
    )?;
    let rows = statement.query_map([], |row| {
        Ok(SchemaObject {
            object_type: row.get(0)?,
            name: row.get(1)?,
            table_name: row.get(2)?,
            sql: row.get(3)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn expected_schema_objects() -> Result<Vec<SchemaObject>, JournalError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(MIGRATION_V1)?;
    schema_objects(&expected)
}

fn validate_v1_schema(connection: &Connection) -> Result<(), JournalError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != 1 {
        return Err(JournalError::Integrity(format!(
            "schema version is {version}, expected 1"
        )));
    }

    let actual = schema_objects(connection)?;
    let expected = expected_schema_objects()?;
    if actual != expected {
        return Err(JournalError::Integrity(
            "schema objects do not match migration version 1".to_owned(),
        ));
    }

    let violations: i64 =
        connection.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if violations != 0 {
        return Err(JournalError::Integrity(format!(
            "foreign_key_check reported {violations} violation(s)"
        )));
    }
    Ok(())
}

fn prepare_state_directory(state_dir: &Path) -> Result<(), JournalError> {
    match fs::symlink_metadata(state_dir) {
        Ok(metadata) => validate_directory_metadata(state_dir, &metadata)?,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            fs::create_dir_all(state_dir).map_err(|error| permission_error(state_dir, error))?;
            let metadata = fs::symlink_metadata(state_dir)
                .map_err(|error| permission_error(state_dir, error))?;
            validate_directory_metadata(state_dir, &metadata)?;
        }
        Err(error) => return Err(permission_error(state_dir, error)),
    }
    set_owner_only_directory(state_dir)
}

fn validate_directory_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), JournalError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(JournalError::Permission(format!(
            "state directory {} is a symlink or is not a directory",
            path.display()
        )));
    }
    Ok(())
}

fn prepare_database_files(state_dir: &Path) -> Result<(), JournalError> {
    for path in database_paths(state_dir) {
        validate_and_harden_existing_file(&path)?;
    }

    let database_path = state_dir.join(DATABASE_NAME);
    if !database_path.exists() {
        create_database_file(&database_path)?;
    }
    validate_and_harden_existing_file(&database_path)
}

fn harden_database_files(state_dir: &Path) -> Result<(), JournalError> {
    for path in database_paths(state_dir) {
        validate_and_harden_existing_file(&path)?;
    }
    Ok(())
}

fn database_paths(state_dir: &Path) -> [PathBuf; 3] {
    [
        state_dir.join(DATABASE_NAME),
        state_dir.join(format!("{DATABASE_NAME}-wal")),
        state_dir.join(format!("{DATABASE_NAME}-shm")),
    ]
}

fn validate_and_harden_existing_file(path: &Path) -> Result<(), JournalError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(JournalError::Permission(format!(
                    "database path {} is a symlink or is not a regular file",
                    path.display()
                )));
            }
            set_owner_only_file(path)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(permission_error(path, error)),
    }
}

fn create_database_file(path: &Path) -> Result<(), JournalError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            validate_and_harden_existing_file(path)
        }
        Err(error) => Err(permission_error(path, error)),
    }
}

#[cfg(unix)]
fn set_owner_only_directory(path: &Path) -> Result<(), JournalError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| permission_error(path, error))
}

#[cfg(not(unix))]
fn set_owner_only_directory(_path: &Path) -> Result<(), JournalError> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_file(path: &Path) -> Result<(), JournalError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| permission_error(path, error))
}

#[cfg(not(unix))]
fn set_owner_only_file(_path: &Path) -> Result<(), JournalError> {
    Ok(())
}

fn permission_error(path: &Path, error: std::io::Error) -> JournalError {
    JournalError::Permission(format!("{}: {error}", path.display()))
}
