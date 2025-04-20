use std::path::{Path, PathBuf};
use rusqlite::Connection;
use super::DataResult;

#[derive(Clone)]
pub struct Database {
    path: PathBuf,
}

fn connect(path: impl AsRef<Path>) -> DataResult<Connection> {
    let db = Connection::open(&path)?;
    db.pragma_update(None, "foreign_keys", "ON")?;
    Ok(db)
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> DataResult<Database> {
        let db = connect(&path)?;
        
        // 初始化数据库表结构
        db.execute(
            "CREATE TABLE IF NOT EXISTS `yt_plugin_cache` (
                `plugin_id` INTEGER NOT NULL,
                `key` TEXT NOT NULL,
                `value` BLOB NOT NULL,
                PRIMARY KEY (`plugin_id`, `key`)
            )",
            [],
        )?;
        
        Ok(Database {
            path: path.as_ref().to_path_buf(),
        })
    }

    pub fn connect(&self) -> DataResult<Connection> {
        connect(self.path.as_path())
    }

    pub fn connect_temp() -> DataResult<Connection> {
        let db = Connection::open_in_memory()?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        
        // 内存数据库也需要初始化表结构
        db.execute(
            "CREATE TABLE IF NOT EXISTS `yt_plugin_cache` (
                `plugin_id` INTEGER NOT NULL,
                `key` TEXT NOT NULL,
                `value` BLOB NOT NULL,
                PRIMARY KEY (`plugin_id`, `key`)
            )",
            [],
        )?;
        
        Ok(db)
    }
}