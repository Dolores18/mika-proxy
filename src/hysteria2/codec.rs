use crate::flow::DestinationAddr;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn::VarInt;
use std::io::ErrorKind;
use tokio_util::codec::{Decoder, Encoder};

pub struct Hy2TcpCodec;

/// Hysteria2 TCP 响应格式
/// ```text
/// [uint8] Status (0x00 = OK, 0x01 = Error)
/// [varint] Message length
/// [bytes] Message string
/// [varint] Padding length
/// [bytes] Random padding
/// ```
#[derive(Debug)]
pub struct Hy2TcpResp {
    pub status: u8,
    pub msg: String,
}

impl Decoder for Hy2TcpCodec {
    type Error = std::io::Error;
    type Item = Hy2TcpResp;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        if !src.has_remaining() {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        
        let status = src.get_u8();
        
        // 手动解析 VarInt
        let msg_len = decode_varint(src)
            .ok_or(ErrorKind::InvalidData)? as usize;

        if src.remaining() < msg_len {
            return Err(ErrorKind::UnexpectedEof.into());
        }

        let msg: Vec<u8> = src.split_to(msg_len).into();
        let msg: String = String::from_utf8(msg)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;

        let padding_len = decode_varint(src)
            .ok_or(ErrorKind::UnexpectedEof)? as usize;

        if src.remaining() < padding_len {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        src.advance(padding_len);

        Ok(Some(Hy2TcpResp { status, msg }))
    }
}

#[inline]
pub fn padding(range: std::ops::RangeInclusive<u32>) -> Vec<u8> {
    use getrandom::getrandom;
    let start = *range.start();
    let end = *range.end();
    let mut buf = [0u8; 4];
    getrandom(&mut buf).unwrap();
    let random_val = u32::from_le_bytes(buf);
    let len = (start + (random_val % (end - start + 1))) as usize;
    vec![b'A'; len] // 简单填充
}

impl Encoder<&'_ DestinationAddr> for Hy2TcpCodec {
    type Error = std::io::Error;

    fn encode(
        &mut self,
        item: &'_ DestinationAddr,
        buf: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let req_id = VarInt::from_u32(0x401);

        let padding = padding(64..=512);
        let padding_len = padding.len() as u64;

        // 将目标地址转换为字符串格式
        let addr_str = format!("{}:{}", item.host.to_string(), item.port);
        let addr = addr_str.into_bytes();
        let addr_len = addr.len() as u64;

        buf.reserve(
            varint_size(req_id.into_inner())
                + varint_size(addr_len)
                + addr.len()
                + varint_size(padding_len)
                + padding.len(),
        );

        encode_varint(req_id.into_inner(), buf);
        encode_varint(addr_len, buf);
        buf.put_slice(&addr);
        encode_varint(padding_len, buf);
        buf.put_slice(&padding);

        Ok(())
    }
}

/// 计算 VarInt 编码所需的字节数
pub fn varint_size(x: u64) -> usize {
    if x < 2u64.pow(6) {
        1
    } else if x < 2u64.pow(14) {
        2
    } else if x < 2u64.pow(30) {
        4
    } else if x < 2u64.pow(62) {
        8
    } else {
        unreachable!("malformed VarInt");
    }
}

/// 编码 VarInt 到缓冲区
pub fn encode_varint(value: u64, buf: &mut BytesMut) {
    if value < 2u64.pow(6) {
        buf.put_u8(value as u8);
    } else if value < 2u64.pow(14) {
        buf.put_u16((value as u16) | 0x4000);
    } else if value < 2u64.pow(30) {
        buf.put_u32((value as u32) | 0x80000000);
    } else if value < 2u64.pow(62) {
        buf.put_u64(value | 0xC000000000000000);
    } else {
        unreachable!("VarInt too large");
    }
}

/// 从缓冲区解码 VarInt
pub fn decode_varint(buf: &mut BytesMut) -> Option<u64> {
    if buf.is_empty() {
        return None;
    }
    
    let first = buf[0];
    let tag = first >> 6;
    
    match tag {
        0 => {
            let val = buf.get_u8() as u64;
            Some(val)
        }
        1 => {
            if buf.len() < 2 {
                return None;
            }
            let val = buf.get_u16() as u64;
            Some(val & 0x3FFF)
        }
        2 => {
            if buf.len() < 4 {
                return None;
            }
            let val = buf.get_u32() as u64;
            Some(val & 0x3FFFFFFF)
        }
        3 => {
            if buf.len() < 8 {
                return None;
            }
            let val = buf.get_u64();
            Some(val & 0x3FFFFFFFFFFFFFFF)
        }
        _ => unreachable!(),
    }
}
