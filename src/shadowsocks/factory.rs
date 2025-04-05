use std::marker::PhantomData;
use std::sync::{Arc, Weak};

pub mod datagram;

pub mod stream;
use super::crypto::*;
use super::SupportedCipher;
use crate::flow::*;
//use stream::ShadowsocksStreamServerFactory;

use stream::ShadowsocksStreamOutboundFactory;
