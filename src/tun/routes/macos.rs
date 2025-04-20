use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Weak};
use std::io::Error;
use log::{warn};
use crate::flow::StreamHandler;
use crate::flow::DatagramSessionHandler;
use crate::fakeip::FakeIp;

#[derive(Debug)]
pub struct Tunconfig {
    pub enabled: bool,
    pub tun_name: String,
    pub routes: Option<Vec<String>>,
    pub mtu: Option<u16>,
    pub netmask: Option<String>,
    pub gateway: String,
    pub stream_handler: Option<Weak<dyn StreamHandler>>,
    pub datagram_handler: Option<Weak<dyn DatagramSessionHandler>>,
    pub dns_hijack: bool,
    pub fakeip: Option<Arc<FakeIp>>,
}

impl Tunconfig {
    pub fn new(tun_name: String, routes: Option<Vec<String>>, mtu: Option<u16>, netmask: Option<String>, gateway: String) -> Self {
        Self { 
            enabled: true,
            tun_name, 
            routes, 
            mtu, 
            netmask, 
            gateway,
            stream_handler: None,
            datagram_handler: None,
            dns_hijack: true,
            fakeip: None,
        }
    }
    
    pub fn with_stream_handler(mut self, handler: Weak<dyn StreamHandler>) -> Self {
        self.stream_handler = Some(handler);
        self
    }
    
    pub fn with_datagram_handler(mut self, handler: Weak<dyn DatagramSessionHandler>) -> Self {
        self.datagram_handler = Some(handler);
        self
    }

    pub fn with_dns_hijack(mut self, hijack: bool) -> Self {
        self.dns_hijack = hijack;
        self
    }
    
    pub fn with_fakeip(mut self, fakeip: Arc<FakeIp>) -> Self {
        self.fakeip = Some(fakeip);
        self
    }
}

fn new_io_error(msg: &str) -> Error {
    Error::new(std::io::ErrorKind::Other, msg)
}

struct NetworkInterface {
    name: String,
}

fn get_outbound_interface() -> Option<NetworkInterface> {
    // 这里简化实现，实际应该获取默认网络接口
    Some(NetworkInterface { name: "en0".to_string() })
}

/// let's assume that the `route` command is available on macOS
pub fn add_route(via: &str, dest: &str) -> std::io::Result<()> {
    // 判断是否是IPv6地址
    if dest.contains(':') {
        // IPv6路由
        // 使用ifconfig添加IPv6地址，如果dest格式为IPv6地址/前缀
        if dest.contains('/') {
            let parts: Vec<&str> = dest.split('/').collect();
            if parts.len() == 2 {
                let cmd = std::process::Command::new("ifconfig")
                    .arg(via)
                    .arg("inet6")
                    .arg(parts[0])
                    .arg("prefixlen")
                    .arg(parts[1])
                    .arg("alias")
                    .output()?;
                
                warn!("executing: ifconfig {} inet6 {} prefixlen {} alias", via, parts[0], parts[1]);
                if !cmd.status.success() {
                    return Err(new_io_error("add ipv6 address failed"));
                }
                return Ok(());
            }
        }
        
        // 添加IPv6路由
        let cmd = std::process::Command::new("route")
            .arg("add")
            .arg("-inet6")
            .arg(dest)
            .arg("-interface")
            .arg(via)
            .output()?;
            
        warn!("executing: route add -inet6 {} -interface {}", dest, via);
        if !cmd.status.success() {
            return Err(new_io_error("add ipv6 route failed"));
        }
    } else {
        // IPv4路由
        let cmd = std::process::Command::new("route")
            .arg("add")
            .arg("-net")
            .arg(dest)
            .arg("-interface")
            .arg(via)
            .output()?;

        warn!("executing: route add -net {} -interface {}", dest, via);
        if !cmd.status.success() {
            return Err(new_io_error("add route failed"));
        }
    }
    
    Ok(())
}

/// 专门用于配置IPv6地址
pub fn configure_ipv6(interface: &str, ipv6_addr: &str, prefix_len: u8) -> std::io::Result<()> {
    let cmd = std::process::Command::new("ifconfig")
        .arg(interface)
        .arg("inet6")
        .arg(ipv6_addr)
        .arg("prefixlen")
        .arg(prefix_len.to_string())
        .arg("alias")
        .output()?;
        
    warn!("executing: ifconfig {} inet6 {} prefixlen {} alias", interface, ipv6_addr, prefix_len);
    if !cmd.status.success() {
        Err(new_io_error("configure ipv6 address failed"))
    } else {
        Ok(())
    }
}

fn get_default_gateway() -> std::io::Result<Option<Ipv4Addr>> {
    let cmd = std::process::Command::new("route")
        .arg("-n")
        .arg("get")
        .arg("default")
        .output()?;

    if !cmd.status.success() {
        return Ok(None);
    }

    let output = String::from_utf8_lossy(&cmd.stdout);

    let mut gateway = None;
    for line in output.lines() {
        if line.trim().contains("gateway:") {
            gateway = line
                .split_whitespace()
                .last()
                .and_then(|x| x.parse::<Ipv4Addr>().ok());
            break;
        }
    }

    Ok(gateway)
}

/// it seems to be fine to add the default route multiple times
pub fn maybe_add_default_route() -> std::io::Result<()> {
    let gateway = get_default_gateway()?;
    if let Some(gateway) = gateway {
        let default_interface =
            get_outbound_interface().ok_or(new_io_error("get default interface"))?;

        let cmd = std::process::Command::new("route")
            .arg("add")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("0/0")
            .arg(gateway.to_string())
            .output()?;

        warn!(
            "executing: route add -ifscope {} 0/0 {}",
            default_interface.name, gateway
        );

        if !cmd.status.success() {
            Err(new_io_error("add default route failed"))
        } else {
            Ok(())
        }
    } else {
        Err(new_io_error(
            "cant set default route, default gateway not found",
        ))
    }
}

/// failing to delete the default route won't cause route failure
pub fn maybe_routes_clean_up(_: &Tunconfig) -> std::io::Result<()> {
    let gateway = get_default_gateway()?;
    if let Some(gateway) = gateway {
        let default_interface =
            get_outbound_interface().ok_or(new_io_error("get default interface"))?;
        let cmd = std::process::Command::new("route")
            .arg("delete")
            .arg("-ifscope")
            .arg(&default_interface.name)
            .arg("0/0")
            .arg(gateway.to_string())
            .output()?;

        warn!(
            "executing: route delete -ifscope {} 0/0 {}",
            default_interface.name, gateway
        );

        if !cmd.status.success() {
            Err(new_io_error("delete default route failed"))
        } else {
            Ok(())
        }
    } else {
        Err(new_io_error(
            "cant delete default route, default gateway not found",
        ))
    }
}
