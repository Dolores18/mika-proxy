use serde::{de::DeserializeOwned, Serialize};
use rusqlite::{params, OptionalExtension};
use serde_json;

use super::{DataResult, Database, PluginId};

#[derive(Clone)]
pub struct PluginCache {
    plugin_id: PluginId,
    db: Option<Database>,
}

impl PluginCache {
    pub fn new(plugin_id: PluginId, db: Option<Database>) -> Self {
        Self { plugin_id, db }
    }

    pub fn set<T: Serialize>(&self, key: &str, value: &T) -> DataResult<()> {
        let Some(db) = &self.db else { return Ok(()) };
        let conn = db.connect()?;
        conn.execute(
            "INSERT OR REPLACE INTO `yt_plugin_cache` (`plugin_id`, `key`, `value`) VALUES (?1, ?2, ?3)",
            params![self.plugin_id.0, key, serde_json::to_string(value).unwrap().as_bytes()],
        )?;
        Ok(())
    }
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> DataResult<Option<T>> {
        let Some(db) = &self.db else { return Ok(None) };
        let conn = db.connect()?;
        let ret = conn
            .query_row(
                "SELECT `value` FROM `yt_plugin_cache` WHERE `plugin_id` = ?1 AND `key` = ?2",
                params![self.plugin_id.0, key],
                |row| {
                    let value: Vec<u8> = row.get(0)?;
                    let json_str = String::from_utf8(value)
                        .map_err(|_| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, "无效的UTF-8数据".into()))?;
                    Ok(serde_json::from_str::<T>(&json_str).ok())
                },
            )
            .optional()?
            .flatten();
        Ok(ret)
    }
}