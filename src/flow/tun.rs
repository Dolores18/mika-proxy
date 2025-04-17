use super::*;
use std::io;
pub type TunBufferSignature = [*mut usize; 2];

#[derive(Debug)]
pub struct TunBufferToken {
    /// Opaque data
    signature: TunBufferSignature,
    pub data: &'static mut [u8],
}

unsafe impl Send for TunBufferToken {}
unsafe impl Sync for TunBufferToken {}

// 实现Clone trait
impl Clone for TunBufferToken {
    fn clone(&self) -> Self {
        // 这里需要使用unsafe代码，因为我们要复制可变静态引用
        // 注意：这是不安全的，因为会产生多个&mut引用指向同一内存
        // 调用者必须确保正确使用，不会同时使用原始值和克隆值
        unsafe {
            Self {
                signature: self.signature,
                data: std::slice::from_raw_parts_mut(
                    self.data.as_ptr() as *mut u8,
                    self.data.len()
                ),
            }
        }
    }
}

impl TunBufferToken {
    /// # Safety
    ///
    /// User must ensure `signature` can be sent to other threads safely.
    pub unsafe fn new(signature: TunBufferSignature, data: &'static mut [u8]) -> Self {
        Self { signature, data }
    }
    pub fn into_parts(self) -> (TunBufferSignature, &'static mut [u8]) {
        (self.signature, self.data)
    }
}

pub trait Tun: Send + Sync {
    // Read
    fn blocking_recv(&self) -> Option<Buffer>;
    fn return_recv_buffer(&self, buf: Buffer);

    // Write
    fn get_tx_buffer(&self) -> Option<TunBufferToken>;
    fn send(&self, buf: TunBufferToken, len: usize);
    fn return_tx_buffer(&self, buf: TunBufferToken);
}
