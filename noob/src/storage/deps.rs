use std::path::PathBuf;

use sea_orm::{DatabaseConnection, DbErr};

use super::store;

/// deps passed to each module
pub struct NodeDeps {
    db: DatabaseConnection,
    pub data_dir: PathBuf,
}

impl NodeDeps {
    /// open db in data dir
    pub async fn open(data_dir: PathBuf) -> Result<Self, DbErr> {
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| DbErr::Custom(format!("create data dir {}: {e}", data_dir.display())))?;
        let db = store::open_db(data_dir.join("noob.db")).await?;
        super::schema::ensure_node_tables(&db).await?;
        Ok(Self { db, data_dir })
    }

    /// in memory db for tests
    pub async fn memory() -> Result<Self, DbErr> {
        let db = store::memory_db().await?;
        super::schema::ensure_node_tables(&db).await?;
        Ok(Self { db, data_dir: std::env::temp_dir() })
    }

    /// clone pooled db handle
    pub fn db(&self) -> DatabaseConnection {
        self.db.clone()
    }
}

/// per role data directory
pub fn node_data_dir(role: &str) -> PathBuf {
    dirs_next::data_dir().expect("no platform data directory").join("noob").join(role)
}
