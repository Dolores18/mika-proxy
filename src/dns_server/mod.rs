mod datagram;
mod map_back;

use std::sync::Arc;

pub use datagram::DnsServer;
pub use map_back::{MapBackDatagramSessionHandler, MapBackStreamHandler};

pub async fn cache_writer(plugin: Arc<DnsServer>) {
    println!("启动DNS缓存写入任务");
    
    let (plugin, notify) = {
        let notify = plugin.new_notify.clone();
        let weak = Arc::downgrade(&plugin);
        drop(plugin);
        (weak, notify)
    };
    if plugin.strong_count() == 0 {
        panic!("dns-server has no strong reference left for cache_writer");
    }

    use tokio::select;
    use tokio::time::{sleep, Duration};
    
    println!("DNS缓存写入任务已启动，等待通知或定时保存");
    
    loop {
        let mut notified_fut = notify.notified();
        let mut sleep_fut = sleep(Duration::from_secs(3600)); // 默认1小时保存一次
        
        'debounce: loop {
            select! {
                _ = notified_fut => {
                    println!("收到DNS缓存更新通知，准备3秒后保存");
                    notified_fut = notify.notified();
                    sleep_fut = sleep(Duration::from_secs(3));
                }
                _ = sleep_fut => {
                    println!("DNS缓存定时保存触发");
                    break 'debounce;
                }
            }
        }
        
        match plugin.upgrade() {
            Some(plugin) => {
                println!("开始执行DNS缓存保存...");
                plugin.save_cache();
            }
            None => {
                println!("DNS服务器实例已被释放，停止缓存写入任务");
                break;
            }
        }
    }
}
