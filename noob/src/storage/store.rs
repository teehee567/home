//! one sqlite db per node

use std::path::Path;
use std::time::Duration;

use sea_orm::sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
use sea_orm::{DatabaseConnection, DbErr, RuntimeErr, SqlxSqliteConnector};

/// open db apply wal pragmas
pub async fn open_db(path: impl AsRef<Path>) -> Result<DatabaseConnection, DbErr> {
    let options = SqliteConnectOptions::new()
        .filename(path.as_ref())
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .map_err(|e| DbErr::Conn(RuntimeErr::SqlxError(e)))?;
    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}

/// in memory db for tests
pub async fn memory_db() -> Result<DatabaseConnection, DbErr> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(SqliteConnectOptions::new().in_memory(true))
        .await
        .map_err(|e| DbErr::Conn(RuntimeErr::SqlxError(e)))?;
    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}
