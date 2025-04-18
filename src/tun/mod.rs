use crate::flow::*;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

//pub mod mactun;

//pub use self::mactun::MacTun;

//pub mod tun_device;
//pub use self::tun_device::MacTun;

pub mod exchange_with_resolver;
pub use self::exchange_with_resolver::exchange_with_resolver;

pub mod mactun;
pub use self::mactun::MacTun;

