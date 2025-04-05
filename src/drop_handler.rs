use crate::fallback::FallbackStream;
use crate::flow::*;
use log::info;
use std::mem::ManuallyDrop;
use std::sync::Weak;

pub struct DropHandler {
    next: Weak<dyn StreamHandler>,
}

impl DropHandler {
    pub fn new(next: Weak<dyn StreamHandler>) -> Self {
        Self { next }
    }
}

impl StreamHandler for DropHandler {
    fn on_stream(&self, lower: Box<dyn Stream>, initial_data: Buffer, context: Box<FlowContext>) {
        let next = match self.next.upgrade() {
            Some(next) => next,
            None => return,
        };

        // 使用 FallbackStream 包装原始流
        let drop_stream = FallbackStream {
            tx_closed: false,
            lower: ManuallyDrop::new(lower),
            on_fallback: ManuallyDrop::new(Box::new(move |_: Box<dyn Stream>| {
                info!("Fallback triggered: handling abnormal stream termination");
            })
                as Box<dyn FnOnce(Box<dyn Stream>) + Send + Sync + Unpin>),
        };

        next.on_stream(Box::new(drop_stream), initial_data, context)
    }
}
