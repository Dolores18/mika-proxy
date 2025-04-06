/// 数据操作结果类型
pub type DataResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// 插件ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PluginId(pub u32);

// 导入子模块
mod db;
pub use db::Database;

mod plugin_cache;
pub use plugin_cache::PluginCache;

mod error;
pub use error::DataError;
